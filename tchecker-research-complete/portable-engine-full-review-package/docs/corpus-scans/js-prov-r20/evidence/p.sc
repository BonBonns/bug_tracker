@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("=== DECORATOR -> PARAMETER BINDING (names deliberately misleading) ===")
  cpg.typeDecl.l.filter(_.annotation.nonEmpty).foreach{td=>
    println(s"  CLASS ${td.name} annotations=[${td.annotation.name.l.mkString(",")}]")
    td.method.l.filter(_.annotation.nonEmpty).foreach{m=>
      val verb=m.annotation.name.l.mkString(",")
      val ps=m.parameter.l.sortBy(_.index).filter(_.index>0).map{p=>
        val ann=p.annotation.l.map{a=>
          val args=a.parameterAssign.l.map(_.code).mkString("|")
          s"${a.name}${if(args.nonEmpty)"("+args+")" else ""}"}.mkString("+")
        s"idx${p.index}:${p.name}->[${if(ann.isEmpty)"NONE" else ann}]"}.mkString("  ")
      println(s"    ${m.name}%-4s verb=$verb  $ps")}
    val undec = td.method.l.filter(_.annotation.isEmpty).map(_.name).filterNot(_.startsWith("<"))
    if(undec.nonEmpty) println(s"    UNDECORATED methods: ${undec.mkString(",")}")
  }
  println("=== UNDECORATED CLASS control ===")
  cpg.typeDecl.nameExact("NotAController").l.foreach{td=>
    println(s"  ${td.name} classAnn=[${td.annotation.name.l.mkString(",")}] methods=${td.method.l.map(m=>s"${m.name}:ann=${m.annotation.name.l.size}").mkString(",")}")}
}
