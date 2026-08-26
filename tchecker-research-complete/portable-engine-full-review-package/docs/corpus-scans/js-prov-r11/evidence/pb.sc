@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("=== CORPUS-B: ctx.validatedData reads and their handlers ===")
  cpg.call.nameExact("<operator>.fieldAccess").l.filter(_.code.contains("validatedData")).map(c=>(c.method.fullName,c.code.replace("\n"," "))).distinct.sortBy(_._1).foreach{case(m,c)=>println(s"  READ  ${m.take(58)}  $c")}
  println("=== CORPUS-B: writes to ctx.validatedData (any) ===")
  cpg.call.nameExact("<operator>.assignment").l.filter(_.code.contains("validatedData")).foreach{c=>println(s"  WRITE ${c.method.fullName.take(58)}  ${c.code.replace("\n"," ").take(60)}")}
  println("=== CORPUS-B: validate middleware wrapper return chain ===")
  cpg.method.l.filter(m=>m.filename.contains("validate.middleware")).foreach{m=>
    println(s"  method=${m.fullName} params=${m.parameter.l.sortBy(_.index).map(_.name).mkString(",")}")
    m.ast.isReturn.l.foreach{r=>println(s"    RETURN children=${r.astChildren.l.map(x=>s"${x.label}:${x match{case mr: io.shiftleft.codepropertygraph.generated.nodes.MethodRef=>mr.methodFullName; case o=>o.code.replace("\n"," ").take(30)}}").mkString(",")}")}
  }
}
