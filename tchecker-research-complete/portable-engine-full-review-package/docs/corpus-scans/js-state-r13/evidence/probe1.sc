@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("=== LINK 1: import/require identity ===")
  cpg.call.nameExact("require").l.foreach { c =>
    println(s"  require args=${c.argument.l.map(_.code).mkString(",")} -> assigned in: ${c.inAssignment.l.map(_.code).mkString(" | ")}")
  }
  cpg.imports.l.foreach { i => println(s"  IMPORT code=${i.code}") }
  println("=== LINK 2/3: route registration call sites ===")
  cpg.call.l.filter(c => Set("post","get","use","Router").contains(c.name)).foreach { c =>
    val recv = c.receiver.l.map(_.code).mkString(",")
    println(s"  call name=${c.name} mfn=${c.methodFullName} recv=[$recv] code=${c.code.replace("\n","\\n").take(70)}")
  }
  println("=== LINK 4: callback identity (METHOD_REF args to registration) ===")
  cpg.call.l.filter(c => Set("post","get").contains(c.name)).foreach { c =>
    c.argument.l.sortBy(_.argumentIndex).foreach { a =>
      println(s"  ${c.name} arg${a.argumentIndex} label=${a.label} code=${a.code.replace("\n","\\n").take(50)}" +
        (a match {
          case m: io.shiftleft.codepropertygraph.generated.nodes.MethodRef => s"  METHOD_REF-> ${m.methodFullName}"
          case _ => "" }))
    }
  }
}
