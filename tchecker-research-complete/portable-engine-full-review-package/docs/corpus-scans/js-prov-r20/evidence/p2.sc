@main def exec(cpgFile: String, mode: String) = {
  importCpg(cpgFile)
  if (mode=="alias") {
    println("=== a9: alias + destructuring downstream of @Body() param ===")
    cpg.method.nameExact("a9").l.foreach{m=>
      val bp=m.parameter.l.find(_.index==1)
      println(s"  decorated param: ${bp.map(_.name).getOrElse("?")} ann=${bp.map(_.annotation.name.l.mkString(",")).getOrElse("")}")
      m.ast.isCall.nameExact("<operator>.assignment").l.foreach{a=>
        println(s"    ASSIGN ${a.code.replace("\n"," ").take(44)}")}
      bp.foreach{p=> println(s"    REF'd by identifiers: ${p.referencingIdentifiers.l.map(i=>i.code+"@"+i.lineNumber.getOrElse(0)).mkString(", ")}")}
    }
    println("=== decorator ARGUMENT recovery (@Param('id')) ===")
    cpg.annotation.l.filter(a=>Set("Param","Headers","Query","Body").contains(a.name)).take(6).foreach{a=>
      println(s"    ${a.name} code=${a.code} paramAssigns=${a.parameterAssign.l.size} children=${a.astChildren.l.map(_.label).mkString(",")}")}
  } else {
    println("=== REAL CORPUS (truthy): decorated params by family ===")
    var b=0;var q=0;var pm=0;var h=0;var other=0;var meth=0
    cpg.typeDecl.l.filter(_.annotation.name(".*Controller.*").nonEmpty).foreach{td=>
      td.method.l.filter(_.annotation.name("Get|Post|Put|Delete|Patch").nonEmpty).foreach{m=>
        meth+=1
        m.parameter.l.filter(_.index>0).foreach{p=>
          p.annotation.name.l.foreach{
            case "Body"=>b+=1; case "Query"=>q+=1; case "Param"=>pm+=1; case "Headers"=>h+=1
            case _=>other+=1}}}}
    println(s"    route methods=$meth  BODY=$b QUERY=$q PARAM=$pm HEADERS=$h  other-decorators=$other")
  }
}
