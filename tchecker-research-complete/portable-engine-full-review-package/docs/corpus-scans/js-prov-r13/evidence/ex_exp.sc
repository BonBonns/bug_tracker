@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s:String)=Option(s).getOrElse("").replace("\n"," ").replace("\t"," ").take(70)
  println("=== EXPORT ASSIGNMENTS ===")
  cpg.assignment.l.filter(a=>a.code.contains("exports")).foreach{a=>
    val rhs=a.argument.l.find(_.argumentIndex==2)
    val rhsId=rhs.map{case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier=>s"IDENT ${i.name} type=${i.typeFullName}"
                      case m: io.shiftleft.codepropertygraph.generated.nodes.MethodRef=>s"METHOD_REF ${m.methodFullName}"
                      case o=>s"${o.label} ${cl(o.code)}"}.getOrElse("?")
    println(s"  ${a.method.filename}%s | ${cl(a.code)} | RHS=$rhsId")
  }
  println("=== require() BINDINGS ===")
  cpg.call.nameExact("require").l.foreach{c=>
    println(s"  ${c.method.filename} ${cl(c.code)} -> assigned: ${c.inAssignment.l.map(x=>cl(x.code)).mkString(",")} typeFullName=${c.typeFullName}")}
  println("=== CALLBACK-POSITION CALLS m*(1) / m*.validate(1) ===")
  cpg.call.l.filter(c=>c.code.matches("m\\d(\\.validate)?\\(1\\)")).foreach{c=>
    println(s"  ${cl(c.code)} name=${c.name} mfn=${c.methodFullName} callees=[${c.callee.fullName.l.mkString(",")}]")}
}
