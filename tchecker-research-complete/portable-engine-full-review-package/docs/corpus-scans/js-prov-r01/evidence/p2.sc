@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("=== REGISTRATION + HANDLER IDENTITY ===")
  cpg.call.l.filter(c => c.methodFullName.matches(".*(express|fastify|koa|hapi).*") || c.code.startsWith("notFramework.post") || c.code.startsWith("exports.handler")).foreach { c =>
    val lit = c.argument.l.collect{case l: io.shiftleft.codepropertygraph.generated.nodes.Literal => l.code}.mkString(",")
    if (Set("post","get","use","route").contains(c.name) || c.code.startsWith("notFramework.post")) {
      println(f"  ${c.name}%-7s mfn=${c.methodFullName}%-46s lit=$lit")
      c.argument.l.sortBy(_.argumentIndex).foreach { a => a match {
        case m: io.shiftleft.codepropertygraph.generated.nodes.MethodRef => println(s"      arg${a.argumentIndex} METHOD_REF -> ${m.methodFullName}")
        case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => println(s"      arg${a.argumentIndex} IDENT ${i.name} type=${i.typeFullName}")
        case o => if (a.argumentIndex>1) println(s"      arg${a.argumentIndex} ${o.label} ${o.code.replace("\n","").take(38)}")
      }}
    }
  }
  println("=== HAPI route object / SERVERLESS export ===")
  cpg.call.nameExact("route").l.foreach { c => println(s"  route args=${c.argument.l.map(_.code.replace("\n","").take(60)).mkString(" ;; ")}") }
  cpg.assignment.l.filter(_.code.startsWith("exports.handler")).foreach { a => println(s"  ${a.code.replace("\n","").take(70)}") }
  println("=== HANDLER PARAM ROLES ===")
  cpg.method.l.filter(m => m.name.startsWith("<lambda>") || Set("fake","fakeFastify","namedHandler","mw","ordinaryHelper","nonHttp").contains(m.name)).foreach { m =>
    println(f"  ${m.name}%-16s ${m.fullName}%-40s params=${m.parameter.l.sortBy(_.index).map(p=>s"${p.index}:${p.name}").mkString(",")}")
  }
}
