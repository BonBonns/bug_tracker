@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  val names = Set("Customs","DB","OtpRedisAdapter","ScopeSetLike")
  println("=== TYPE_DECLs for collision names ===")
  cpg.typeDecl.l.filter(td=>names.contains(td.name)).foreach{td=>
    println(f"  ${td.name}%-18s id=${td.id}%-14s full=${td.fullName}%-58s ext=${td.isExternal}%-6s file=${td.filename}")}
  println("=== identifiers/params typed to a collision name: which decl did they bind? ===")
  cpg.parameter.l.filter(p=>names.exists(n=>p.typeFullName.endsWith(":"+n)||p.typeFullName==n)).take(40).foreach{p=>
    println(f"  PARAM ${p.name}%-14s type=${p.typeFullName}%-50s inMethodFile=${p.method.filename}")}
  println("=== malformed full names (colon where dot belongs: ':ts::' ) ===")
  val mal = cpg.all.collectAll[io.shiftleft.codepropertygraph.generated.nodes.Identifier].l
      .flatMap(i=>List(i.typeFullName)++i.dynamicTypeHintFullName.l).filter(_.matches(".*:(ts|js|mjs)::.*"))
  println(s"  malformed occurrences on identifiers = ${mal.size}")
  mal.distinct.take(8).foreach{m=>println(s"    $m")}
}
