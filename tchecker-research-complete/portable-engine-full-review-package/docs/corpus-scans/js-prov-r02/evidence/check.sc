@main def exec(cpgFile: String, mode: String) = {
  importCpg(cpgFile)
  if (mode == "annotation") {
    println("=== ANNOTATION PROVENANCE (NestJS) ===")
    val ctrls = cpg.typeDecl.l.filter(_.annotation.name(".*Controller.*").nonEmpty)
    println(s"CONTROLLER_CLASSES_RECOGNIZED=${ctrls.size}")
    var recognized=0; var partial=0
    var body=0; var query=0; var param=0; var headers=0
    ctrls.foreach { t =>
      t.method.l.filter(_.annotation.name("Get|Post|Put|Delete|Patch").nonEmpty).foreach { m =>
        val verb = m.annotation.name("Get|Post|Put|Delete|Patch").name.headOption.getOrElse("?")
        val ps = m.parameter.l.sortBy(_.index).filter(_.index>0)
        val anns = ps.map(p => (p.index, p.name, p.annotation.name.l))
        val withAnn = anns.filter(_._3.nonEmpty)
        if (withAnn.nonEmpty) recognized+=1 else partial+=1
        withAnn.foreach { case (i,n,a) =>
          a.foreach { an => an match {
            case "Body" => body+=1; case "Query" => query+=1
            case "Param" => param+=1; case "Headers" => headers+=1; case _ => } }
        }
        println(s"  HANDLER ${t.name}.${m.name} verb=$verb params=${anns.map{case(i,n,a)=>s"$i:$n[${a.mkString(",")}]"}.mkString(" ")}")
      }
    }
    println(s"HANDLERS_RECOGNIZED=$recognized HANDLERS_PARTIAL=$partial")
    println(s"BODY=$body QUERY=$query PARAM=$param HEADERS=$headers")
  } else {
    println("=== REGISTRATION PROVENANCE (Koa) ===")
    cpg.identifier.l.filter(i => Set("app","router").contains(i.name)).map(i=>(i.name,i.typeFullName)).distinct.foreach{
      case (n,t) => println(s"  OBJ $n type=$t") }
    cpg.call.l.filter(c => Set("get","post","put","delete","patch","use").contains(c.name)).foreach { c =>
      if (c.methodFullName.matches(".*(koa|router|Router).*"))
        println(s"  REG ${c.name} mfn=${c.methodFullName} args=${c.argument.l.sortBy(_.argumentIndex).map(a=>a match {
          case m: io.shiftleft.codepropertygraph.generated.nodes.MethodRef => s"${a.argumentIndex}:METHOD_REF(${m.methodFullName})"
          case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => s"${a.argumentIndex}:IDENT(${i.name}:${i.typeFullName})"
          case o => s"${a.argumentIndex}:${o.label}" }).mkString(" ")}")
    }
  }
}
