@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  def t(a: io.shiftleft.codepropertygraph.generated.nodes.Expression): String = a match {
    case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => i.typeFullName
    case c: io.shiftleft.codepropertygraph.generated.nodes.Call => c.typeFullName
    case o => o.label }
  cpg.call.l.filter(c => Set("g","g2","g3").contains(c.name)).foreach { c =>
    val callee = c.callee.fullName.l.mkString(",")
    val args = c.argument.l.sortBy(_.argumentIndex).map(a=>s"${a.argumentIndex}:${a.code.take(20)}:${t(a)}").mkString("  ")
    val params = cpg.method.fullNameExact(c.callee.fullName.l.headOption.getOrElse("")).l
      .flatMap(_.parameter.l).sortBy(_.index).map(p=>s"${p.index}:${p.name}:${p.typeFullName}").mkString("  ")
    println(s"CALL ${c.name} callee=[$callee]")
    println(s"   ARGS   $args")
    println(s"   PARAMS $params")
  }
}
