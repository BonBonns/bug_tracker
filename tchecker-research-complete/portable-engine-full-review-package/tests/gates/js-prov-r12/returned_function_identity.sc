// JS-PROV-R12-1 — Higher-order returned-function identity, promoted as a
// STANDALONE primitive rather than buried inside the state-flow join.
//
//   CALL -> callee METHOD -> RETURN -> METHOD_REF -> returned METHOD
//
// CONTRACT: the returned function must be DIRECTLY returned by the callee.
// Descendant RETURNs belonging to nested methods are NOT followed.
//
// This is a general JS/TS higher-order-function identity traversal. It is NOT
// Koa- or framework-specific: any `f(x)` whose callee returns a function
// literal resolves here. Discovered while characterizing Koa's
// `validate(schema)` (JS-PROV-R11), but deliberately kept separate so other
// analyses (callback registration, event handlers, decorators, middleware in
// other frameworks) can reuse it.
@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s:String)=Option(s).getOrElse("").replace("\n"," ").replace("\t"," ").take(80)
  val w=new java.io.PrintWriter(new java.io.File(s"$outDir/returned_function_identity.tsv"),"UTF-8")
  try cpg.method.l.foreach{ m =>
    // FROZEN CONTRACT (JS-PROV-R13 review): DIRECTLY returned only. Filtering
    // on `_.method.fullName == m.fullName` excludes RETURNs that belong to
    // NESTED methods. Without this, a module program node inherits the RETURN
    // of a function declared inside it -- AST containment, not symbol identity,
    // and it would let a module resolve to a lambda it does not export.
    val returned = m.ast.isReturn.l.filter(_.method.fullName == m.fullName).flatMap(_.astChildren.l)
      .collect{case mr: io.shiftleft.codepropertygraph.generated.nodes.MethodRef => mr}
    returned.foreach{ mr =>
      w.println(Seq(cl(m.fullName), cl(mr.methodFullName), cl(m.methodReturn.typeFullName)).mkString("\t"))
    }
  } finally w.close()
}
