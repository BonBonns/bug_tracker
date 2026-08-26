@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  def cl(s:String)=Option(s).getOrElse("").replace("\n"," ").take(66)
  println("=== ESM EXPORT-SIDE representation ===")
  cpg.assignment.l.filter(a=>a.code.contains("exports")||a.code.contains("export ")).foreach{a=>
    val rhs=a.argument.l.find(_.argumentIndex==2)
    val id=rhs.map{case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier=>s"IDENT ${i.name} type=${i.typeFullName}"
                   case m: io.shiftleft.codepropertygraph.generated.nodes.MethodRef=>s"METHOD_REF ${m.methodFullName}"
                   case o=>s"${o.label} ${cl(o.code)}"}.getOrElse("?")
    println(s"  ${a.method.filename}%-14s | ${cl(a.code)} | RHS=$id")}
  println("=== IMPORT nodes ===")
  cpg.imports.l.foreach{i=>println(s"  ${cl(i.code)}  explicit=${i.isExplicit.getOrElse(false)}  entity=${i.importedEntity.getOrElse("-")}  as=${i.importedAs.getOrElse("-")}")}
}
