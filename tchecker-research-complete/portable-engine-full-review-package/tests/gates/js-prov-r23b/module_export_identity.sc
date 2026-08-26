// JS-PROV-R14 — raw facts for module specifier resolution.
//  (a) require() bindings: specifier literal + the local it is assigned to
//  (b) export assignments: file + member name + RHS method identity
//  (c) call sites whose receiver is a require-bound local
@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s:String)=Option(s).getOrElse("").replace("\n"," ").replace("\t"," ").take(90)
  val rq=new java.io.PrintWriter(new java.io.File(s"$outDir/require_bindings.tsv"),"UTF-8")
  try cpg.call.nameExact("require").l.foreach{ c =>
    val spec = c.argument.l.collectFirst{case l: io.shiftleft.codepropertygraph.generated.nodes.Literal => l.code.replaceAll("^['\"]|['\"]$","")}
    val local = c.inAssignment.l.flatMap(_.argument.l.filter(_.argumentIndex==1))
      .collectFirst{case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => i.name}
    spec.foreach{ s => rq.println(Seq(cl(c.method.filename), cl(s), cl(local.getOrElse("")), c.id).mkString("\t")) }
  } finally rq.close()

  val ex=new java.io.PrintWriter(new java.io.File(s"$outDir/module_exports.tsv"),"UTF-8")
  try cpg.assignment.l.filter(a=>a.code.contains("exports")).foreach{ a =>
    val args=a.argument.l.sortBy(_.argumentIndex)
    val lhs=args.headOption.map(x=>cl(x.code)).getOrElse("")
    // member name: `exports.X` / `module.exports.X` -> X ; `module.exports` -> "" (default)
    val member = { val t=lhs.trim
      if (t=="module.exports"||t=="exports") "" else t.split('.').lastOption.getOrElse("") }
    val rhs=args.lift(1)
    val rhsMethod = rhs.map{
      case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => i.typeFullName
      case m: io.shiftleft.codepropertygraph.generated.nodes.MethodRef => m.methodFullName
      case o => "" }.getOrElse("")
    val rhsKind = rhs.map(_.label).getOrElse("")
    // JS-PROV-R26: for a RE-EXPORT the RHS is a field access on an imported
    // module object (`exports.f = _lib.f`). Record the BASE LOCAL and MEMBER
    // structurally so the chain can be followed, rather than parsing the code
    // string (JS-PROV-R13: code strings are not identities).
    val (reBase, reMember) = rhs match {
      case Some(c: io.shiftleft.codepropertygraph.generated.nodes.Call) if c.name=="<operator>.fieldAccess" =>
        val fa = c.argument.l.sortBy(_.argumentIndex)
        (fa.headOption.collect{case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier=>i.name}.getOrElse(""),
         fa.lift(1).map(_.code).getOrElse(""))
      case _ => ("","")
    }
    ex.println(Seq(cl(a.method.filename), member, cl(rhsMethod), rhsKind, cl(a.code),
                   cl(reBase), cl(reMember)).mkString("\t"))
  } finally ex.close()

  val ic=new java.io.PrintWriter(new java.io.File(s"$outDir/import_calls.tsv"),"UTF-8")
  try cpg.call.l.foreach{ c =>
    val recv=c.argument.l.find(_.argumentIndex==0)
    // direct: m1(1)  -> callee name is the local itself
    // member: m2.validate(1) -> receiver is fieldAccess(local, member)
    recv.foreach{
      case fa: io.shiftleft.codepropertygraph.generated.nodes.Call if fa.name=="<operator>.fieldAccess" =>
        val fargs=fa.argument.l.sortBy(_.argumentIndex)
        val base=fargs.headOption.collect{case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier=>i.name}
        val mem=fargs.lift(1).map(_.code)
        base.foreach{b=> ic.println(Seq(c.id, cl(c.method.filename), b, mem.getOrElse(""), cl(c.name), cl(c.code)).mkString("\t"))}
      case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier =>
        ic.println(Seq(c.id, cl(c.method.filename), i.name, "", cl(c.name), cl(c.code)).mkString("\t"))
      case _ =>
    }
  } finally ic.close()
}
