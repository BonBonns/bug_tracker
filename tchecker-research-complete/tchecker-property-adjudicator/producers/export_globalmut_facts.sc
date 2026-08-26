// JS-PROV-GS1 — global shared-singleton security-control mutation producer.
//
// Models the Unleash CWE-116 bug (GHSA-w4mq-xh27-6xpx): assigning to a
// security-sensitive member of an IMPORTED shared module singleton
// (`Mustache.escape = (t) => t`) disables that control for every consumer in
// the process, via Node's module cache. The safe alternative passes the
// override PER CALL (`render(a, c, undefined, { escape })`) and never mutates
// the shared object.
//
// Fact files (separate, opt-in -- R33 rule):
//   singleton_writes.tsv  file, method, line, base, member, base_is_import,
//                         rhs_is_identity, rhs_code
//       an assignment `base.member = rhs` where member is security-sensitive.
//       base_is_import: base is a require()/import binding (shared singleton).
//       rhs_is_identity: rhs is an identity function (weakens control to no-op).
//   percall_overrides.tsv  file, method, line, callee, opt_member
//       a render/template call passing a security-member override inside an
//       options-object argument (the safe pattern), so the verdict does not
//       confuse an in-object `escape:` with a global write.
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s: String) = Option(s).getOrElse("").replace("\n", " ").replace("\t", " ").take(200)
  def w(n: String) = new java.io.PrintWriter(new java.io.File(s"$outDir/$n"), "UTF-8")

  val securityMembers = Set("escape", "sanitize", "encode", "escapeHtml",
    "escapeMarkup", "purify", "clean", "filterXSS", "escapeExpression")

  // import bindings: local name -> true (bound by require()/import in this file)
  // read from require_bindings.tsv if present; else detect require() locally.
  val importLocals = scala.collection.mutable.Map[String, scala.collection.mutable.Set[String]]()
  val rbFile = new java.io.File(s"$outDir/require_bindings.tsv")
  if (rbFile.exists()) {
    scala.io.Source.fromFile(rbFile).getLines().foreach { ln =>
      val xs = ln.split("\t")
      if (xs.length == 4 && xs(2).nonEmpty)
        importLocals.getOrElseUpdate(xs(0), scala.collection.mutable.Set()).add(xs(2))
    }
  }
  // fallback / augmentation: any local assigned from a require(...) call
  cpg.assignment.l.foreach { a =>
    val rhs = a.argument.l.find(_.argumentIndex == 2).map(x => Option(x.code).getOrElse("")).getOrElse("")
    val lhs = a.argument.l.find(_.argumentIndex == 1).collect { case i: nodes.Identifier => i.name }
    if (rhs.matches("""(?s).*\brequire\s*\(.*""") || rhs.matches("""(?s).*\bimport\b.*"""))
      lhs.foreach(n => importLocals.getOrElseUpdate(a.method.filename, scala.collection.mutable.Set()).add(n))
  }
  def isImport(file: String, base: String): Boolean =
    importLocals.get(file).exists(_.contains(base))

  def isIdentityMethod(m: nodes.Method): Boolean = {
    val ps = m.parameter.l.filter(_.index > 0)
    val rets = m.ast.isReturn.l
    ps.size == 1 && rets.size == 1 && {
      val pn = ps.head.name
      rets.head.astChildren.l.headOption.exists(c => Option(c.code).getOrElse("").trim == pn)
    }
  }
  // Resolve a MethodRef/closure rhs to its Method to test identity, plus a
  // code fallback for `(t) => t` / `x => x` / `function(t){return t}`.
  def rhsIdentity(a: nodes.Call): Boolean = {
    val rhs = a.argument.l.find(_.argumentIndex == 2)
    val viaMethod = rhs.collect { case mr: nodes.MethodRef => mr }.flatMap(mr =>
      cpg.method.fullNameExact(mr.methodFullName).headOption)
    if (viaMethod.exists(isIdentityMethod)) true
    else {
      val rc = rhs.map(x => Option(x.code).getOrElse("")).getOrElse("")
      rc.replaceAll("\\s", "").matches("""\(?(\w+)\)?=>\1""") ||
        rc.replaceAll("\\s", "").matches("""function\(?(\w+)\)?\{return\1;?\}""")
    }
  }

  // ---- singleton_writes.tsv ------------------------------------------------
  val sw = w("singleton_writes.tsv")
  try cpg.assignment.l.foreach { a =>
    val lhs = a.argument.l.find(_.argumentIndex == 1)
    lhs.foreach {
      case fa: nodes.Call if fa.name == "<operator>.fieldAccess" =>
        val base = fa.argument.l.find(_.argumentIndex == 1).map(x => Option(x.code).getOrElse("")).getOrElse("")
        val member = fa.argument.l.find(_.argumentIndex == 2).map(x => Option(x.code).getOrElse("")).getOrElse("")
        if (securityMembers.contains(member)) {
          val file = a.method.filename
          // base is a simple identifier (not a temp from an object literal)
          val baseIsIdent = base.matches("""[A-Za-z_$][\w$]*""") && !base.startsWith("_tmp")
          val imported = baseIsIdent && isImport(file, base)
          val ident = rhsIdentity(a)
          val rhsCode = a.argument.l.find(_.argumentIndex == 2).map(x => Option(x.code).getOrElse("")).getOrElse("")
          sw.println(Seq(cl(file), cl(a.method.fullName),
            a.lineNumber.map(_.toString).getOrElse(""), cl(base), cl(member),
            imported.toString, ident.toString, cl(rhsCode)).mkString("\t"))
        }
      case _ => ()
    }
  } finally sw.close()

  // ---- percall_overrides.tsv ----------------------------------------------
  // A security-member override that lives INSIDE an options object literal
  // passed to a render/template call -- the safe per-call pattern. Detected by:
  // an object-literal assignment `_tmp.member = fn` whose temp flows into a
  // render(...) call as a later argument.
  val po = w("percall_overrides.tsv")
  try cpg.method.isExternal(false).l.foreach { m =>
    val renderCalls = m.call.l.filter(c =>
      c.name == "render" || Option(c.code).getOrElse("").matches("""(?s).*\.render\s*\(.*"""))
    // object-literal temps that set a security member
    val optTemps = m.assignment.l.flatMap { a =>
      a.argument.l.find(_.argumentIndex == 1).collect {
        case fa: nodes.Call if fa.name == "<operator>.fieldAccess" =>
          val base = fa.argument.l.find(_.argumentIndex == 1).map(x => Option(x.code).getOrElse("")).getOrElse("")
          val member = fa.argument.l.find(_.argumentIndex == 2).map(x => Option(x.code).getOrElse("")).getOrElse("")
          if (securityMembers.contains(member) && (base.startsWith("_tmp") || base.startsWith("renderConfig") || base.matches("""[a-z]\w*[Cc]onfig"""))) Some((base, member)) else None
      }.flatten
    }.toSet
    if (renderCalls.nonEmpty && optTemps.nonEmpty) {
      // any render call with >=4 args (action, view, partials, options) OR whose
      // args mention a config local -> treat the override as per-call.
      renderCalls.foreach { rc =>
        val argN = rc.argument.l.count(_.argumentIndex >= 1)
        val argCode = rc.argument.l.filter(_.argumentIndex >= 1).map(a => Option(a.code).getOrElse("")).mkString(" ")
        optTemps.foreach { case (base, member) =>
          val mentionsConfig = argN >= 4 || argCode.matches(s"""(?s).*\\b${java.util.regex.Pattern.quote(base)}\\b.*""") ||
            argCode.matches("""(?s).*[Cc]onfig.*""")
          if (mentionsConfig)
            po.println(Seq(cl(m.filename), cl(m.fullName),
              rc.lineNumber.map(_.toString).getOrElse(""), "render", cl(member)).mkString("\t"))
        }
      }
    }
  } finally po.close()

  // ---- security_member_reads.tsv ------------------------------------------
  // Files that READ/call a security member without assigning it, so the verdict
  // can distinguish "reads escape, never mutates" (safe) from "no activity".
  val sr = w("security_member_reads.tsv")
  try cpg.method.isExternal(false).l.foreach { m =>
    m.call.name("<operator>.fieldAccess").l.foreach { fa =>
      val member = fa.argument.l.find(_.argumentIndex == 2).map(x => Option(x.code).getOrElse("")).getOrElse("")
      // a fieldAccess that is NOT the LHS of an assignment
      val isAssignLhs = fa.astParent match {
        case p: nodes.Call => p.name == "<operator>.assignment" && fa.argumentIndex == 1
        case _ => false
      }
      if (securityMembers.contains(member) && !isAssignLhs) {
        sr.println(Seq(cl(m.filename), cl(member),
          fa.lineNumber.map(_.toString).getOrElse("")).mkString("\t"))
      }
    }
  } finally sr.close()

  println(s"GS1_FACTS_COMPLETE: $outDir")
}
