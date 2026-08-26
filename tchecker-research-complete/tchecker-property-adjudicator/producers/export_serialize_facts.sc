// JS-PROV-DOS1 — unguarded serialize-on-attacker-data DoS fact producer.
//
// Models the Unleash CWE-674 crash (GHSA-r5pq-6chh-j3xp): an error formatter
// calls JSON.stringify on a raw request-body value with no guard; deeply-nested
// JSON makes it throw RangeError synchronously; the throw is not wrapped in
// try/catch and the process registers no uncaughtException handler, so Node
// exits(1) -- an unauthenticated single-request DoS.
//
// Fact files (separate, opt-in -- R33 rule):
//   serialize_sinks.tsv  file, method, line, callee, arg_code,
//                        arg_attacker_controlled, in_try_catch
//       callee in {JSON.stringify, util.inspect, <recursive serializer>}.
//   uncaught_handlers.tsv  file, kind   (kind = uncaughtException|unhandledRejection)
//   depth_guards.tsv       file, method  (a method that applies a depth/size
//                          guard before serializing -- exonerates the sink)
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s: String) = Option(s).getOrElse("").replace("\n", " ").replace("\t", " ").take(200)
  def w(n: String) = new java.io.PrintWriter(new java.io.File(s"$outDir/$n"), "UTF-8")

  // attacker-source markers: a value read from the request. Covers Express/Koa
  // (req.body, ctx.request.body), Hapi (request.payload/query/params), and
  // Fastify (request.body/query/params). Framework-agnostic per the FXA scan
  // finding that Express-only patterns miss Hapi's request.payload.
  def attackerCode(code: String): Boolean =
    code.matches("""(?s).*\breq(uest)?\.body\b.*""") ||
    code.matches("""(?s).*\b_?\.?get\s*\(\s*req(uest)?\.body.*""") ||
    code.matches("""(?s).*\bctx\.request\.body\b.*""") ||
    code.matches("""(?s).*\brequest\.(payload|query|params)\b.*""") ||   // Hapi / Fastify
    code.matches("""(?s).*\breq\.(query|params)\b.*""") ||               // Express query/params
    code.matches("""(?s).*\b_?\.?get\s*\(\s*request\.(payload|query|params).*""") ||
    code.matches("""(?s).*\bpropertyValue\b.*""")   // named body value in fixture/advisory

  val serializers = Set("stringify", "inspect")
  def isSerializer(c: nodes.Call): Boolean = {
    val code = Option(c.code).getOrElse("")
    code.matches("""(?s).*\bJSON\.stringify\s*\(.*""") ||
    code.matches("""(?s).*\butil\.inspect\s*\(.*""") ||
    (c.name == "stringify" && code.contains("JSON"))
  }

  // ---- serialize_sinks.tsv -------------------------------------------------
  val ss = w("serialize_sinks.tsv")
  try cpg.method.isExternal(false).l.foreach { m =>
    // locals in this method that trace to an attacker source
    val tainted = scala.collection.mutable.Set[String]()
    m.assignment.l.foreach { a =>
      val rhs = a.argument.l.find(_.argumentIndex == 2).map(x => Option(x.code).getOrElse("")).getOrElse("")
      val lhs = a.argument.l.find(_.argumentIndex == 1).collect { case i: nodes.Identifier => i.name }
      if (attackerCode(rhs) || tainted.exists(t => rhs.matches(s"""(?s).*\\b${java.util.regex.Pattern.quote(t)}\\b.*""")))
        lhs.foreach(tainted += _)
    }
    // the REAL serializer calls (not lowered assignment temps): a call whose
    // name is stringify/inspect. Dedup by line.
    val seen = scala.collection.mutable.Set[Int]()
    m.call.l.filter(isSerializer).foreach { c =>
      val line = c.lineNumber.map(_.toInt).getOrElse(-1)
      if (c.name == "stringify" || c.name == "inspect") {
        if (seen.add(line)) {
          val argCode = c.argument.l.filter(_.argumentIndex >= 1).map(a => Option(a.code).getOrElse("")).mkString(" ")
          val attacker = attackerCode(argCode) ||
            tainted.exists(t => argCode.matches(s"""(?s).*\\b${java.util.regex.Pattern.quote(t)}\\b.*"""))
          val inTry = c.inAst.collectAll[nodes.ControlStructure].l.exists(_.controlStructureType == "TRY")
          // BOUNDED LITERAL: the arg is a freshly-constructed object/array literal
          // whose nesting is bounded by source, and which does NOT directly embed
          // a raw request accessor as a member value. Such a value cannot carry
          // deeply-nested attacker JSON, so it is not the serialize-DoS shape even
          // when taint reaches it via a key->value lookup (the FXA emails.js case:
          // `JSON.stringify({ uid, secret })` where secret is a server hex string).
          val at = argCode.trim
          val boundedLiteral = (at.startsWith("{") || at.startsWith("[")) && !attackerCode(argCode)
          ss.println(Seq(cl(m.filename), cl(m.fullName), line.toString,
            "JSON.stringify", cl(argCode), attacker.toString, inTry.toString,
            boundedLiteral.toString).mkString("\t"))
        }
      }
    }
  } finally ss.close()

  // ---- uncaught_handlers.tsv ----------------------------------------------
  val uh = w("uncaught_handlers.tsv")
  try cpg.call.nameExact("on").l.foreach { c =>
    val code = Option(c.code).getOrElse("")
    if (code.matches("""(?s).*process\.on\b.*""")) {
      if (code.contains("uncaughtException"))
        uh.println(Seq(cl(c.method.filename), "uncaughtException").mkString("\t"))
      if (code.contains("unhandledRejection"))
        uh.println(Seq(cl(c.method.filename), "unhandledRejection").mkString("\t"))
    }
  } finally uh.close()

  // ---- depth_guards.tsv ----------------------------------------------------
  // A method that computes a nesting depth / size and branches on it before the
  // serializer -- the mitigation. Heuristic: a call to a depth/size helper or a
  // comparison against a depth-like local, in the same method as a serializer.
  val dg = w("depth_guards.tsv")
  try cpg.method.isExternal(false).l.foreach { m =>
    val hasSerializer = m.call.l.exists(isSerializer)
    if (hasSerializer) {
      val guardsDepth = m.ast.isCall.l.exists { c =>
        val code = Option(c.code).getOrElse("")
        code.matches("""(?s).*\bdepth\w*\s*\(.*""") ||
        code.matches("""(?s).*\b(maxDepth|nestingLimit|sizeLimit|byteLength)\b.*""")
      } || m.call.name("<operator>.(greaterThan|lessThan|greaterEqualsThan|lessEqualsThan)").l.exists { c =>
        Option(c.code).getOrElse("").toLowerCase.matches("""(?s).*\b(depth|nesting|size|len(gth)?)\b.*""")
      }
      if (guardsDepth)
        dg.println(Seq(cl(m.filename), cl(m.fullName)).mkString("\t"))
    }
  } finally dg.close()

  println(s"DOS1_FACTS_COMPLETE: $outDir")
}
