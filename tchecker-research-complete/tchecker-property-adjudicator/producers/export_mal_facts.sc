// MAL-NPM-1 — install-time exfiltration behavior fact producer.
//
// Detects the dependency-confusion / install-hook data-exfil shape (e.g.
// lumen-pages-community MAL-2026-14356): a script harvests host/installer
// identifiers and sends them to a hardcoded external collector. Joern supplies
// the call graph so the harvested identifiers can be LINKED to the outbound
// request, which is what separates real exfil from incidental os/network use.
//
// Fact files (separate, opt-in -- R33 rule):
//   identifier_reads.tsv  file, method, line, kind, code
//       kind in {HOSTNAME, USERNAME, CWD, PLATFORM, NODE_VERSION, ENV, NETIF}.
//   outbound_requests.tsv file, method, line, api, url_code, has_literal_host
//       api in {HTTPS_GET, HTTP_GET, FETCH, AXIOS, REQUEST, CHILD_EXEC}.
//   exfil_links.tsv       file, method, request_line, identifier_kinds
//       an outbound request whose argument/URL expression transitively includes
//       an identifier read (same enclosing method).
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s: String) = Option(s).getOrElse("").replace("\n", " ").replace("\t", " ").take(200)
  def w(n: String) = new java.io.PrintWriter(new java.io.File(s"$outDir/$n"), "UTF-8")

  // classify an identifier-harvesting expression by its code
  def identifierKind(code: String): Option[String] = {
    val c = code
    if (c.matches("""(?s).*\bos\.hostname\s*\(.*""") || c.matches("""(?s).*\.hostname\b.*""")) Some("HOSTNAME")
    else if (c.matches("""(?s).*\bos\.userInfo\b.*""") || c.matches("""(?s).*\.username\b.*""")) Some("USERNAME")
    else if (c.matches("""(?s).*\bprocess\.cwd\s*\(.*""")) Some("CWD")
    else if (c.matches("""(?s).*\bprocess\.platform\b.*""") || c.matches("""(?s).*\bos\.platform\b.*""")) Some("PLATFORM")
    else if (c.matches("""(?s).*\bprocess\.version\b.*""")) Some("NODE_VERSION")
    else if (c.matches("""(?s).*\bprocess\.env\b.*""")) Some("ENV")
    else if (c.matches("""(?s).*\bos\.networkInterfaces\b.*""")) Some("NETIF")
    else None
  }

  // ---- identifier_reads.tsv ------------------------------------------------
  val ir = w("identifier_reads.tsv")
  try cpg.method.isExternal(false).l.foreach { m =>
    // fieldAccess + call nodes both carry the identifying code
    val nodes0 = m.ast.isCall.l.map(c => (c: nodes.AstNode, Option(c.code).getOrElse(""))) ++
      m.ast.isCall.name("<operator>.fieldAccess").l.map(c => (c: nodes.AstNode, Option(c.code).getOrElse("")))
    val seen = scala.collection.mutable.Set[(Int, String)]()
    nodes0.foreach { case (n, code) =>
      identifierKind(code).foreach { k =>
        val line = n.lineNumber.map(_.toInt).getOrElse(-1)
        if (seen.add((line, k)))
          ir.println(Seq(cl(m.filename), cl(m.fullName), line.toString, k, cl(code)).mkString("\t"))
      }
    }
  } finally ir.close()

  // ---- outbound_requests.tsv ----------------------------------------------
  val or = w("outbound_requests.tsv")
  def requestApi(c: nodes.Call): Option[String] = {
    val code = Option(c.code).getOrElse("")
    if (code.matches("""(?s).*\bhttps\.(get|request)\b.*""")) Some("HTTPS_GET")
    else if (code.matches("""(?s).*\bhttp\.(get|request)\b.*""")) Some("HTTP_GET")
    else if (c.name == "fetch" || code.matches("""(?s).*\bfetch\s*\(.*""")) Some("FETCH")
    else if (code.matches("""(?s).*\baxios\b.*""")) Some("AXIOS")
    else None
  }
  try cpg.method.isExternal(false).l.foreach { m =>
    m.call.l.foreach { c =>
      requestApi(c).foreach { api =>
        val urlArg = c.argument.l.find(_.argumentIndex == 1).map(a => Option(a.code).getOrElse("")).getOrElse("")
        val hasLiteralHost = urlArg.matches("""(?s).*https?://[^"'\s)]+.*""")
        or.println(Seq(cl(m.filename), cl(m.fullName),
          c.lineNumber.map(_.toString).getOrElse(""), api, cl(urlArg),
          hasLiteralHost.toString).mkString("\t"))
      }
    }
  } finally or.close()

  // ---- exfil_links.tsv -----------------------------------------------------
  // A request in a method where identifier reads also occur, AND the identifier
  // values reach the request: either directly in the URL arg, or via a local
  // (info/qs/url) that the request arg references. Conservative: same-method
  // reachability by local-name mention, not full dataflow (ceiling stated).
  val el = w("exfil_links.tsv")
  try cpg.method.isExternal(false).l.foreach { m =>
    val idReads = m.ast.isCall.l.flatMap(c => identifierKind(Option(c.code).getOrElse("")).map(k => (k, c))) 
    if (idReads.nonEmpty) {
      // locals assigned from an expression containing an identifier read
      val taintedLocals = scala.collection.mutable.Set[String]()
      m.assignment.l.foreach { a =>
        val rhs = a.argument.l.find(_.argumentIndex == 2).map(x => Option(x.code).getOrElse("")).getOrElse("")
        val lhs = a.argument.l.find(_.argumentIndex == 1).collect { case i: nodes.Identifier => i.name }
        if (identifierKind(rhs).isDefined || taintedLocals.exists(t => rhs.matches(s"""(?s).*\\b${java.util.regex.Pattern.quote(t)}\\b.*""")))
          lhs.foreach(taintedLocals += _)
      }
      m.call.l.foreach { c =>
        requestApi(c).foreach { _ =>
          val argCode = c.argument.l.filter(_.argumentIndex >= 1).map(a => Option(a.code).getOrElse("")).mkString(" ")
          val directId = identifierKind(argCode).isDefined
          val viaLocal = taintedLocals.exists(t => argCode.matches(s"""(?s).*\\b${java.util.regex.Pattern.quote(t)}\\b.*"""))
          if (directId || viaLocal) {
            val kinds = idReads.map(_._1).distinct.sorted.mkString(",")
            el.println(Seq(cl(m.filename), cl(m.fullName),
              c.lineNumber.map(_.toString).getOrElse(""), kinds).mkString("\t"))
          }
        }
      }
    }
  } finally el.close()

  // ---- decode_eval_sinks.tsv ----------------------------------------------
  // A dynamic-code sink (eval / new Function / vm.run*) whose argument is (or
  // derives from) a base64/hex decode -- the obfuscated-payload shape. `decoded`
  // is true iff a decode call feeds the sink (directly or via a local).
  val ev = w("decode_eval_sinks.tsv")
  val evalNames = Set("eval", "Function", "runInThisContext", "runInContext", "runInNewContext")
  def isDecode(code: String): Boolean =
    code.matches("""(?s).*\bBuffer\.from\s*\([^)]*base64.*""") ||
    code.matches("""(?s).*\bBuffer\.from\s*\([^)]*hex.*""") ||
    code.matches("""(?s).*\batob\s*\(.*""")
  try cpg.method.isExternal(false).l.foreach { m =>
    // locals whose initializer is a decode
    val decodedLocals = scala.collection.mutable.Set[String]()
    m.assignment.l.foreach { a =>
      val rhs = a.argument.l.find(_.argumentIndex == 2).map(x => Option(x.code).getOrElse("")).getOrElse("")
      val lhs = a.argument.l.find(_.argumentIndex == 1).collect { case i: nodes.Identifier => i.name }
      if (isDecode(rhs) || decodedLocals.exists(t => rhs.matches(s"""(?s).*\\b${java.util.regex.Pattern.quote(t)}\\b.*""")))
        lhs.foreach(decodedLocals += _)
    }
    m.call.l.foreach { c =>
      val code = Option(c.code).getOrElse("")
      val isEvalSink = evalNames.contains(c.name) || code.matches("""(?s).*\bnew Function\b.*""")
      if (isEvalSink) {
        val argCode = c.argument.l.filter(_.argumentIndex >= 1).map(a => Option(a.code).getOrElse("")).mkString(" ")
        val fedByDecode = isDecode(argCode) ||
          decodedLocals.exists(t => argCode.matches(s"""(?s).*\\b${java.util.regex.Pattern.quote(t)}\\b.*"""))
        ev.println(Seq(cl(m.filename), cl(m.fullName),
          c.lineNumber.map(_.toString).getOrElse(""), cl(c.name), fedByDecode.toString,
          cl(code)).mkString("\t"))
      }
    }
  } finally ev.close()

  // ---- exec_sites.tsv ------------------------------------------------------
  // child_process spawns. The verdict pairs these with the manifest install
  // hook (install-time exec is the dangerous case). `pipes_shell` flags a
  // command that pipes to sh / curls a payload.
  val ex = w("exec_sites.tsv")
  val execNames = Set("exec", "execSync", "spawn", "spawnSync", "execFile", "fork")
  // 2026-08-24: `exec` is overloaded. child_process.exec(cmd) is a command-execution
  // sink; RegExp.prototype.exec(str) (e.g. `RE.exec(path)`) is completely benign but
  // shares the call name. Matching on name alone produced a FALSE POSITIVE on Mozilla
  // Send (`DOWNLOAD_URL.exec(url.pathname)`), which — in a package carrying an install
  // hook — could inflate a malicious verdict. Only `exec`/`execSync` are RegExp methods;
  // spawn/execFile/fork are process-only and never filtered. For those two, drop the
  // call when its receiver is a regex: a regex literal receiver, or an identifier whose
  // name looks like a compiled-regex constant (matches /RE|REGEX|PATTERN|_RE$/i), or a
  // receiver the arg count disqualifies (RegExp.exec takes exactly one string arg and is
  // a member call `x.exec(...)`; child_process.exec is typically a bare/imported call).
  val regexNameRe = """(?i).*(regex|regexp|pattern|_re|url|matcher).*""".r
  def looksRegexReceiver(c: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
    val recvOpt = c.argument.headOption
    recvOpt.exists { r =>
      val rc = Option(r.code).getOrElse("")
      // literal regex receiver, or identifier that reads as a regex/pattern/url constant
      rc.startsWith("/") || regexNameRe.pattern.matcher(rc).matches()
    }
  }
  // a member-style `recv.exec(...)` (receiver present and code contains ".exec")
  def isMemberExec(c: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
    val code = Option(c.code).getOrElse("")
    code.matches("""(?s).*\.\s*exec(Sync)?\s*\(.*""")
  }
  try cpg.method.isExternal(false).l.foreach { m =>
    m.call.l.foreach { c =>
      if (execNames.contains(c.name)) {
        val code = Option(c.code).getOrElse("")
        // suppress RegExp.prototype.exec/execSync member calls with a regex-like receiver
        val regexExec = (c.name == "exec" || c.name == "execSync") &&
                        isMemberExec(c) && looksRegexReceiver(c)
        if (!regexExec) {
          val pipesShell = code.matches("""(?s).*(\|\s*(ba)?sh|curl|wget|iwr|Invoke-).*""")
          ex.println(Seq(cl(m.filename), cl(m.fullName),
            c.lineNumber.map(_.toString).getOrElse(""), cl(c.name), pipesShell.toString,
            cl(code)).mkString("\t"))
        }
      }
    }
  } finally ex.close()

  // ---- helper_launder.tsv --------------------------------------------------
  // Interprocedural exfil: a HELPER that reads identifiers and RETURNS them,
  // whose result flows (via a call) into an outbound request -- possibly in a
  // different function. Emit (harvest_helper, identifier_kinds) and
  // (send_helper) so the verdict can link them by intra-file call edges.
  val hl = w("helper_launder.tsv")
  try cpg.method.isExternal(false).l.foreach { m =>
    // does this method read identifiers AND return a value containing them?
    val idKinds = m.ast.isCall.l.flatMap(c => identifierKind(Option(c.code).getOrElse("")).map(k => k)).distinct.sorted
    val returnsIds = m.ast.isReturn.l.exists { r =>
      val rc = Option(r.code).getOrElse("")
      idKinds.nonEmpty || identifierKind(rc).isDefined
    }
    if (idKinds.nonEmpty && returnsIds) {
      hl.println(Seq(cl(m.filename), "HARVEST_HELPER", cl(m.fullName),
        idKinds.mkString(",")).mkString("\t"))
    }
    // does this method issue an outbound request whose URL ARGUMENT carries a
    // parameter (the laundered identifiers)? We trace params through locals
    // assigned from them, and require the taint to reach the request's own
    // argument -- not merely appear somewhere in the method body.
    val params = m.parameter.name.l.filter(_.nonEmpty).toSet
    val taintedLocals = scala.collection.mutable.Set[String]()
    taintedLocals ++= params
    m.assignment.l.foreach { a =>
      val rhs = a.argument.l.find(_.argumentIndex == 2).map(x => Option(x.code).getOrElse("")).getOrElse("")
      val lhs = a.argument.l.find(_.argumentIndex == 1).collect { case i: nodes.Identifier => i.name }
      if (taintedLocals.exists(t => rhs.matches(s"""(?s).*\\b${java.util.regex.Pattern.quote(t)}\\b.*""")))
        lhs.foreach(taintedLocals += _)
    }
    m.call.l.foreach { c =>
      requestApi(c).foreach { _ =>
        val argCode = c.argument.l.filter(_.argumentIndex >= 1).map(a => Option(a.code).getOrElse("")).mkString(" ")
        val reaches = taintedLocals.exists(t =>
          argCode.matches(s"""(?s).*\\b${java.util.regex.Pattern.quote(t)}\\b.*"""))
        if (reaches)
          hl.println(Seq(cl(m.filename), "SEND_HELPER", cl(m.fullName),
            c.lineNumber.map(_.toString).getOrElse("")).mkString("\t"))
      }
    }
  } finally hl.close()

  println(s"MALNPM1_FACTS_COMPLETE: $outDir")
}
