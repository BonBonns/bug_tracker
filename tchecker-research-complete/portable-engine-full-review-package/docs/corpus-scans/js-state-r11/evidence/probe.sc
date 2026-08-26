@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  cpg.call.filter(c => Set("<operator>.equals","<operator>.notEquals").contains(c.name)).l.foreach { c =>
    println(s"### ${c.method.name} | ${c.code.replace("\n","\\n")}")
    c.argument.l.sortBy(_.argumentIndex).foreach { a =>
      val st = a match {
        case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => i.typeFullName
        case l: io.shiftleft.codepropertygraph.generated.nodes.Literal => l.typeFullName
        case k: io.shiftleft.codepropertygraph.generated.nodes.Call => k.typeFullName
        case _ => "<n/a>"
      }
      val hints = a match {
        case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => i.dynamicTypeHintFullName.l.mkString("|")
        case k: io.shiftleft.codepropertygraph.generated.nodes.Call => k.dynamicTypeHintFullName.l.mkString("|")
        case _ => ""
      }
      // producer: what was this local last assigned from?
      val producer = a match {
        case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier =>
          i.refOut.l.collectAll[io.shiftleft.codepropertygraph.generated.nodes.Local]
           .flatMap(_.referencingIdentifiers.l)
           .flatMap(_.inCall.nameExact("<operator>.assignment").l)
           .map(_.code.replace("\n","\\n")).distinct.mkString(" ;; ")
        case _ => ""
      }
      println(s"    arg${a.argumentIndex} label=${a.label} code=${a.code} STATIC=$st HINTS=[$hints] PRODUCER=[$producer]")
    }
  }
}
