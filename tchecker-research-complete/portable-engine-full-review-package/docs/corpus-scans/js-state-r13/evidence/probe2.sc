@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("=== LINK 5: callback parameter identity/role ===")
  cpg.method.l.filter(m => m.name.startsWith("<lambda>") || Set("handler","fake").contains(m.name)).foreach { m =>
    val ps = m.parameter.l.sortBy(_.index).map(p => s"idx${p.index}:${p.name}:${p.typeFullName}").mkString("  ")
    println(s"  ${m.name} (${m.fullName})  params: $ps")
  }
  println("=== LINK 6: property paths read inside each handler ===")
  cpg.method.l.filter(m => m.name.startsWith("<lambda>") || Set("handler","fake","otherFamilies").contains(m.name)).foreach { m =>
    val fas = m.ast.isCall.nameExact("<operator>.fieldAccess","<operator>.indexAccess").l
      .map(_.code.replace("\n","")).distinct
    if (fas.nonEmpty) println(s"  ${m.name}: ${fas.mkString(" | ")}")
  }
  println("=== T7: does IDENTIFIER 'handler' resolve to a METHOD? ===")
  cpg.call.nameExact("post").l.filter(_.code.contains("t7")).foreach { c =>
    c.argument.l.filter(_.argumentIndex==2).foreach { a =>
      a match {
        case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier =>
          println(s"  handler ident type=${i.typeFullName} hints=[${i.dynamicTypeHintFullName.l.mkString("|")}] REF->${i.refOut.l.map(_.label).mkString(",")}")
        case o => println(s"  label=${o.label}")
      }
    }
  }
  println("=== T3 destructuring: how is ({body}, res) represented? ===")
  cpg.method.nameExact("<lambda>1").l.foreach { m =>
    m.parameter.l.sortBy(_.index).foreach { p => println(s"  param idx${p.index} name=${p.name} code=${p.code}") }
    m.ast.isCall.l.take(8).foreach { c => println(s"    call ${c.name} code=${c.code.replace("\n","")}") }
  }
}
