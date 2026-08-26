@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("=== Q1: wrapper `validate` return chain ===")
  cpg.method.nameExact("validate").l.foreach{m=>
    println(s"  method=${m.fullName} ret=${m.methodReturn.typeFullName}")
    m.ast.isReturn.l.foreach{r=>
      println(s"    RETURN code=${r.code.replace("\n"," ").take(40)} children=${r.astChildren.l.map(c=>s"${c.label}:${c match {case mr: io.shiftleft.codepropertygraph.generated.nodes.MethodRef=>mr.methodFullName; case o=>o.code.replace("\n"," ").take(28)}}").mkString(",")}")}
  }
  println("=== Q8: ctx writes/reads with position relative to next() ===")
  cpg.method.l.filter(m=>m.name.matches("producer.*|consumer.*|afterWriter|condWriter|bodyWriter|queryWriter|constWriter|derivedWriter|<lambda>.*")).foreach{m=>
    val nextLines = m.ast.isCall.nameExact("next").l.flatMap(_.lineNumber).toList
    val nl = if(nextLines.isEmpty) -1 else nextLines.min
    val fa = m.ast.isCall.nameExact("<operator>.assignment").l.filter(_.code.contains("ctx."))
    val rd = m.ast.isCall.nameExact("<operator>.fieldAccess").l.filter(c=>c.code.startsWith("ctx.")).map(_.code).distinct
    if(fa.nonEmpty||rd.nonEmpty)
      println(s"  ${m.name}%s nextLine=$nl WRITES=${fa.map(c=>s"${c.code.replace("\n"," ").take(46)}@L${c.lineNumber.getOrElse(0)}").mkString(" ; ")} READS=${rd.mkString(",")}")
  }
}
