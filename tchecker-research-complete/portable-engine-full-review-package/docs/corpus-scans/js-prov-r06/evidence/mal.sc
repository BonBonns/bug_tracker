@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  val ids = cpg.all.collectAll[io.shiftleft.codepropertygraph.generated.nodes.Identifier].l
  val tot = ids.size
  val malT = ids.count(i=>i.typeFullName.matches(".*:(ts|js|mjs)::.*"))
  val malH = ids.count(i=>i.dynamicTypeHintFullName.l.exists(_.matches(".*:(ts|js|mjs)::.*")))
  val anyT = ids.count(_.typeFullName=="ANY")
  println(s"IDENTIFIERS=$tot  ANY=$anyT  MALFORMED_typeFullName=$malT  MALFORMED_in_hints=$malH")
  val ps = cpg.parameter.l
  println(s"PARAMS=${ps.size} ANY=${ps.count(_.typeFullName=="ANY")} MALFORMED=${ps.count(_.typeFullName.matches(".*:(ts|js|mjs)::.*"))}")
  println("sample malformed hints:")
  ids.flatMap(_.dynamicTypeHintFullName.l).filter(_.matches(".*:(ts|js|mjs)::.*")).distinct.take(5).foreach(m=>println(s"   $m"))
}
