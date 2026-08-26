@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("=== Object.create argument (can null-prototype be PROVEN?) ===")
  cpg.call.nameExact("create").l.foreach { c =>
    c.argument.l.sortBy(_.argumentIndex).foreach { a =>
      println(s"  create arg${a.argumentIndex} label=${a.label} code=${a.code} type=${a match {
        case l: io.shiftleft.codepropertygraph.generated.nodes.Literal => l.typeFullName
        case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => i.typeFullName
        case o => o.label }}")
    }
  }
  println("=== KEY provenance: is the index key a PARAM, module const, or literal? ===")
  cpg.call.nameExact("<operator>.indexAccess").l.filter(_.method.name.startsWith("t")).foreach { c =>
    val key = c.argument.l.sortBy(_.argumentIndex).lift(1)
    key.foreach {
      case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier =>
        val refs = i.refOut.l.map(r => s"${r.label}:${r.label}").mkString(",")
        println(s"  ${c.method.name} key=${i.name} REF->[$refs]")
      case l: io.shiftleft.codepropertygraph.generated.nodes.Literal =>
        println(s"  ${c.method.name} key=LITERAL ${l.code}")
      case o => println(s"  ${c.method.name} key=${o.label}")
    }
  }
}
