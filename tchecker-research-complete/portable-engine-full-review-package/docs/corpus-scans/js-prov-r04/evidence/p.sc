@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  def atype(a: io.shiftleft.codepropertygraph.generated.nodes.Expression): String = a match {
    case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => i.typeFullName
    case c: io.shiftleft.codepropertygraph.generated.nodes.Call => c.typeFullName
    case l: io.shiftleft.codepropertygraph.generated.nodes.Literal => l.typeFullName
    case m: io.shiftleft.codepropertygraph.generated.nodes.MethodRef => m.methodFullName
    case o => o.label
  }
  println("=== CALLSITES: callee resolution + arg types + callee param decl types ===")
  cpg.call.l.filter(c => c.name.startsWith("r1_")||c.name.startsWith("r2_")||c.name.startsWith("r3_")||
                        c.name.startsWith("r4_")||c.name.startsWith("r5")||c.name.startsWith("r6")||
                        c.name.startsWith("r7_")||c.name.startsWith("r8_")||c.name.startsWith("r9_")).foreach { c =>
    val callees = c.callee.fullName.l
    val args = c.argument.l.sortBy(_.argumentIndex).map(a => s"${a.argumentIndex}:${a.code.take(16)}:${atype(a)}").mkString(" ")
    val params = callees.headOption.flatMap(fn => cpg.method.fullNameExact(fn).l.headOption)
      .map(_.parameter.l.sortBy(_.index).map(p=>s"${p.index}:${p.name}:${p.typeFullName}").mkString(" ")).getOrElse("-")
    println(s"  ${c.name}  callees=[${callees.mkString(",")}]")
    println(s"      ARGS   $args")
    println(s"      PARAMS $params")
  }
}
