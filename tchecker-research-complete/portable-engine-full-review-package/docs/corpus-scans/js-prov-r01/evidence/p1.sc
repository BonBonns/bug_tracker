@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("=== FRAMEWORK OBJECT IDENTITY (type recovery on the receiver) ===")
  List("app","router","fastify","koaApp","hapiServer","notFramework").foreach { n =>
    cpg.identifier.nameExact(n).l.map(_.typeFullName).distinct.foreach { t => println(f"  $n%-14s type=$t") }
  }
  println("=== REGISTRATION CALLS: methodFullName provenance ===")
  cpg.call.l.filter(c => Set("post","get","use","route","server","Router").contains(c.name)).foreach { c =>
    val lit = c.argument.l.collect{case l: io.shiftleft.codepropertygraph.generated.nodes.Literal => l.code}.mkString(",")
    println(f"  ${c.name}%-8s mfn=${c.methodFullName}%-52s lit=$lit")
  }
}
