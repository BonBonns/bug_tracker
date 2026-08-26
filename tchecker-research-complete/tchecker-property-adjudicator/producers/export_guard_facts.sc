// JS-PROV-GF1 — guard-fallthrough fact producer.
//
// Models the class behind the Pods pods_error() bypass, in JS/TS:
//   a GUARD calls a helper it BELIEVES halts the request, the helper has a
//   path that RETURNS instead of terminating, the caller DISCARDS the return
//   value (bare statement, no `return`/`throw`), and a SENSITIVE SINK is
//   reachable afterwards in the same function.
//
// Three fact files (each a separate opt-in file, per the R33 lesson):
//   terminator_profile.tsv  file, method_fullname, verdict, evidence
//       verdict in {ALWAYS, CONDITIONAL, NEVER}. A function is ALWAYS iff every
//       control path reaches a terminating call (throw/ctx.throw/process.exit/
//       a known ALWAYS terminator) with NO `return <value>` escaping. If some
//       path returns a value, it is CONDITIONAL -- the dangerous shape.
//   guard_calls.tsv  file, enclosing_method, callee_name, callee_fullname,
//                    line, in_conditional, is_bare_statement, is_returned
//   sink_sites.tsv   file, enclosing_method, sink_kind, code, line
//
// The engine's VERDICT tool (guard_fallthrough_verdict.py) joins these; this
// script only measures. Nothing here decides a vulnerability.
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s: String) = Option(s).getOrElse("").replace("\n", " ").replace("\t", " ").take(140)
  def w(n: String) = new java.io.PrintWriter(new java.io.File(s"$outDir/$n"), "UTF-8")

  // Names that terminate a request/handler by throwing or exiting.
  val terminatorNames = Set("throw", "assert", "exit", "abort")
  def isTerminatingCall(c: nodes.Call): Boolean = {
    val n = c.name
    val code = Option(c.code).getOrElse("")
    // ctx.throw(...), ctx.assert(...), process.exit(...), koa ctx.throw, etc.,
    // plus Hapi: throwing a Boom error (Boom.badRequest/unauthorized/...) or
    // h.response(...).takeover() both terminate the request lifecycle.
    n == "throw" || n == "assert" || n == "exit" ||
      code.matches("""(?s).*\b(ctx|context|c)\.(throw|assert)\b.*""") ||
      code.matches("""(?s).*\bprocess\.exit\b.*""") ||
      code.matches("""(?s).*\bBoom\.\w+\s*\(.*""") ||
      code.matches("""(?s).*\.takeover\s*\(\s*\).*""")
  }

  // ---- terminator_profile.tsv ---------------------------------------------
  // A method's own body: does every path terminate, or can a value return?
  val tp = w("terminator_profile.tsv")
  try cpg.method.isExternal(false).l.foreach { m =>
    val throwsCTS = m.ast.isControlStructure.l.exists(cs => cs.controlStructureType == "THROW")
    val throwCalls = m.call.l.filter(isTerminatingCall)
    // returns that carry a value (i.e. `return X`, not bare `return;`)
    val valueReturns = m.ast.isReturn.l.filter { r =>
      r.astChildren.l.nonEmpty && Option(r.code).getOrElse("").trim != "return"
    }
    val hasTerminator = throwsCTS || throwCalls.nonEmpty
    // CONDITIONAL iff it can both terminate AND return a value on some path;
    // ALWAYS iff it terminates and never returns a value; NEVER otherwise.
    val verdict =
      if (hasTerminator && valueReturns.nonEmpty) "CONDITIONAL"
      else if (hasTerminator && valueReturns.isEmpty) "ALWAYS"
      else "NEVER"
    val evid = s"throwCS=${throwsCTS} throwCalls=${throwCalls.size} valueReturns=${valueReturns.size}"
    tp.println(Seq(cl(m.filename), cl(m.fullName), verdict, cl(evid)).mkString("\t"))
  } finally tp.close()

  // ---- guard_calls.tsv -----------------------------------------------------
  // Every call whose callee name suggests a guard/deny/terminator helper, with
  // the structural facts the verdict needs. We do NOT hard-code the helper set;
  // the verdict cross-references terminator_profile. Here we emit ALL calls
  // that are (a) bare statements or (b) returned, inside a conditional, so the
  // verdict can decide which matter.
  val gc = w("guard_calls.tsv")
  try cpg.method.isExternal(false).l.foreach { m =>
    m.call.l.foreach { c =>
      // enclosing conditional?
      val inIf = c.inAst.collectAll[nodes.ControlStructure].exists(cs =>
        cs.controlStructureType == "IF" || cs.controlStructureType == "ELSE")
      // is this call the RHS of a return? climb parents for a Return node.
      val underReturn = c.inAst.collectAll[nodes.Return].nonEmpty
      // bare statement: the call's parent is a Block (expression statement),
      // not an assignment / return / argument to another call.
      val parentLabel = c.astParent.label
      val isBare = parentLabel == "BLOCK"
      val calleeFull = c.callee.fullName.headOption.getOrElse(c.methodFullName)
      // only emit calls that are user-defined function invocations or ctx.* —
      // skip operator/builtin noise to keep the file small.
      val nm = c.name
      val interesting = !nm.startsWith("<operator>") && nm != "require" &&
        (isBare || underReturn)
      if (interesting && inIf) {
        gc.println(Seq(cl(m.filename), cl(m.fullName), cl(nm), cl(calleeFull),
          c.lineNumber.map(_.toString).getOrElse(""),
          inIf.toString, isBare.toString, underReturn.toString).mkString("\t"))
      }
    }
  } finally gc.close()

  // ---- sink_sites.tsv ------------------------------------------------------
  // Sensitive operations that must not be reached past a failed guard. Curated
  // kinds, same spirit as security_sink_profile: DB writes, fs writes, code
  // exec, response-body assignment of privileged data.
  val sk = w("sink_sites.tsv")
  def sinkKind(c: nodes.Call): Option[String] = {
    val code = Option(c.code).getOrElse("")
    if (c.name == "update" || c.name == "insert" || c.name == "del" || c.name == "delete") Some("DB_WRITE")
    else if (code.matches("""(?s).*\bwriteFile(Sync)?\b.*""")) Some("FS_WRITE")
    else if (code.matches("""(?s).*\b(exec|execSync|spawn|eval)\b.*""")) Some("CODE_EXEC")
    else None
  }
  try cpg.method.isExternal(false).l.foreach { m =>
    m.call.l.foreach { c =>
      sinkKind(c).foreach { k =>
        sk.println(Seq(cl(m.filename), cl(m.fullName), k, cl(c.code),
          c.lineNumber.map(_.toString).getOrElse("")).mkString("\t"))
      }
    }
  } finally sk.close()

  // ---- guard_then_sink_order.tsv ------------------------------------------
  // For each (method), the min line of a guard-call and whether a sink exists
  // at a GREATER line (i.e. reachable after the guard in source order). This is
  // a conservative proxy for "sink reachable past the guard" -- a real CFG
  // reachability pass is the sound version (named as a ceiling in the verdict).
  val go = w("method_guard_sink_lines.tsv")
  try cpg.method.isExternal(false).l.foreach { m =>
    val guardLines = m.call.l.filter { c =>
      val inIf = c.inAst.collectAll[nodes.ControlStructure].exists(cs =>
        cs.controlStructureType == "IF")
      val isBare = c.astParent.label == "BLOCK"
      !c.name.startsWith("<operator>") && c.name != "require" && inIf && isBare
    }.flatMap(_.lineNumber.map(_.toInt))
    val sinkLines = m.call.l.filter(c => sinkKind(c).isDefined).flatMap(_.lineNumber.map(_.toInt))
    if (guardLines.nonEmpty && sinkLines.nonEmpty) {
      go.println(Seq(cl(m.filename), cl(m.fullName),
        guardLines.min.toString, sinkLines.max.toString).mkString("\t"))
    }
  } finally go.close()

  println(s"GF1_FACTS_COMPLETE: $outDir")
}
