// JS-PROV-R38 support exporter.
//
// The review package ships the CONSUMERS (framework_registration.py,
// context_state_flow.py) but not the gate-side exporter that produced
// registrations.tsv / callback_args.tsv / ctx_state.tsv / method_params.tsv.
// This script reconstructs those files against the exact schemas the shipped
// consumers parse, and adds ONE new file:
//
//   registration_order.tsv  (call_id, filename, line)
//
// emitted SEPARATELY per the R33 lesson: registrations.tsv has multiple
// independent readers, so ordering evidence is an opt-in file, never a new
// column. R38's mount/ordering logic is the only consumer.
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s: String) = Option(s).getOrElse("").replace("\n", " ").replace("\t", " ").take(120)
  def w(name: String) = new java.io.PrintWriter(new java.io.File(s"$outDir/$name"), "UTF-8")

  // ---- method_params.tsv: method_fullname, index, name, type, hint ----------
  val mp = w("method_params.tsv")
  try cpg.method.isExternal(false).l.foreach { m =>
    m.parameter.l.foreach { p =>
      mp.println(Seq(cl(m.fullName), p.index.toString, cl(p.name), cl(p.typeFullName), "").mkString("\t"))
    }
  } finally mp.close()

  // ---- registrations.tsv (9 cols) + registration_order.tsv (3 cols) --------
  // call_id, name, methodFullName, in_method, recv_name, recv_type,
  // param_method, param_index, nargs
  val verbs = Set("get", "post", "put", "delete", "patch", "all", "use")
  val rg = w("registrations.tsv")
  val ro = w("registration_order.tsv")
  try {
    cpg.call.l.filter(c => verbs.contains(c.name)).foreach { c =>
      val recv = c.argument.l.find(_.argumentIndex == 0)
      val (rn, rt) = recv match {
        case Some(i: nodes.Identifier) => (i.name, i.typeFullName)
        case Some(a)                   => (a.code, "")
        case None                      => ("", "")
      }
      // If the receiver identifier names a parameter of the enclosing method,
      // record (param_method, param_index) so the R08 receiver-domain path
      // applies; otherwise leave blank -> DIRECT receiver path (R29).
      val encl = c.method
      val prm = recv match {
        case Some(i: nodes.Identifier) => encl.parameter.l.find(_.name == i.name)
        case _ => None
      }
      val (pm, pi) = prm.map(p => (encl.fullName, p.index.toString)).getOrElse(("", ""))
      val nargs = c.argument.l.count(_.argumentIndex >= 1)
      rg.println(Seq(c.id.toString, cl(c.name), cl(c.methodFullName), cl(encl.fullName),
        cl(rn), cl(rt), cl(pm), pi, nargs.toString).mkString("\t"))
      ro.println(Seq(c.id.toString, cl(encl.filename),
        c.lineNumber.map(_.toString).getOrElse("")).mkString("\t"))
    }
  } finally { rg.close(); ro.close() }

  // ---- callback_args.tsv (8 cols) -------------------------------------------
  // call_id, call_name, arg_index, node_label, code, resolved, ftype, arg_id
  val cb = w("callback_args.tsv")
  try cpg.call.l.filter(c => verbs.contains(c.name)).foreach { c =>
    c.argument.l.filter(_.argumentIndex >= 1).foreach { a =>
      val resolved = a match {
        case mr: nodes.MethodRef => mr.methodFullName
        case i: nodes.Identifier => i.typeFullName // may be a method fullName or a lambda type
        case _ => ""
      }
      val ftype = a match {
        case i: nodes.Identifier => i.typeFullName
        case cc: nodes.Call      => cc.typeFullName
        case _                   => ""
      }
      cb.println(Seq(c.id.toString, cl(c.name), a.argumentIndex.toString, cl(a.label),
        cl(a.code), cl(resolved), cl(ftype), a.id.toString).mkString("\t"))
    }
  } finally cb.close()

  // ---- ctx_state.tsv (7 cols) ----------------------------------------------
  // method, WRITE|READ, path, source, order, next_order, conditional
  //
  // Context identity is POSITIONAL: parameter index 1 of the containing
  // method, never by name (R11/R12 convention). A field-access chain rooted
  // at that parameter yields a property path; assignment LHS -> WRITE,
  // anything else -> READ. `order` is the source line; `next_order` is the
  // line of the first call named `next` in the method (-1 when absent).
  // `conditional` is true iff a ControlStructure lies between the access and
  // the method root.
  val cs = w("ctx_state.tsv")
  try {
    cpg.method.isExternal(false).l.foreach { m =>
      val ctxName = m.parameter.l.find(_.index == 1).map(_.name)
      ctxName.foreach { cn =>
        val nextLine = m.call.nameExact("next").lineNumber.l.sorted.headOption
          .map(_.toString).getOrElse("-1")
        // maximal fieldAccess chains only (parent is not itself a fieldAccess)
        val fas = m.call.nameExact("<operator>.fieldAccess").l.filter { fa =>
          fa.astParent match {
            case p: nodes.Call => p.name != "<operator>.fieldAccess"
            case _             => true
          }
        }
        fas.foreach { fa =>
          val code = Option(fa.code).getOrElse("")
          if (code.startsWith(cn + ".")) {
            val path = code.stripPrefix(cn + ".")
            if (path.nonEmpty && !path.contains("(")) {
              val isWriteLhs = fa.astParent match {
                case p: nodes.Call => p.name == "<operator>.assignment" && fa.argumentIndex == 1
                case _             => false
              }
              val src = if (isWriteLhs) fa.astParent match {
                case p: nodes.Call =>
                  p.argument.l.find(_.argumentIndex == 2).map(_.code).getOrElse("")
                case _ => ""
              } else ""
              val cond = fa.inAst.l.exists {
                case _: nodes.ControlStructure => true
                case _ => false
              }
              cs.println(Seq(cl(m.fullName), if (isWriteLhs) "WRITE" else "READ",
                cl(path), cl(src),
                fa.lineNumber.map(_.toString).getOrElse("-1"), nextLine,
                cond.toString).mkString("\t"))
            }
          }
        }
      }
    }
  } finally cs.close()

  // ---- default_export_identifier.tsv (2 cols): file, identifier_name -------
  // R38 mount evidence: `module.exports = router` names WHICH local the file
  // exports. module_exports.tsv records only the RHS TYPE (the R34 wrong-record
  // shape), so a file registering routes on two routers but exporting one would
  // over-join without this. SEPARATE FILE (R33 rule); R38 is the only consumer.
  val de = w("default_export_identifier.tsv")
  try cpg.assignment.l.foreach { a =>
    val lhsIsModuleExports = a.argument.l.find(_.argumentIndex == 1)
      .exists(_.code.trim == "module.exports")
    if (lhsIsModuleExports) {
      a.argument.l.find(_.argumentIndex == 2).foreach {
        case i: nodes.Identifier =>
          de.println(Seq(cl(a.method.filename), cl(i.name)).mkString("\t"))
        case _ => ()
      }
    }
  } finally de.close()

  // ---- router_routes_export.tsv (2 cols): file, router_local ---------------
  // R39: `module.exports = router.routes()` exports the router's dispatch
  // MIDDLEWARE, not the router object. Neither module_exports.tsv (rhs is a
  // type) nor default_export_identifier.tsv (rhs is not an identifier) records
  // WHICH router the middleware came from. SEPARATE FILE (R33 rule).
  val rr = w("router_routes_export.tsv")
  try cpg.assignment.l.foreach { a =>
    val lhsIsModuleExports = a.argument.l.find(_.argumentIndex == 1)
      .exists(_.code.trim == "module.exports")
    if (lhsIsModuleExports) {
      a.argument.l.find(_.argumentIndex == 2).foreach {
        case c: nodes.Call if c.name == "routes" =>
          c.argument.l.find(_.argumentIndex == 0).foreach {
            case i: nodes.Identifier =>
              rr.println(Seq(cl(a.method.filename), cl(i.name)).mkString("\t"))
            case _ => ()
          }
        case _ => ()
      }
    }
  } finally rr.close()

  println(s"R38_FACTS_COMPLETE: $outDir")
}
