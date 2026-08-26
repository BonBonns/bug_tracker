@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  def t(a: io.shiftleft.codepropertygraph.generated.nodes.Expression): (String,String) = a match {
    case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => (i.typeFullName, i.dynamicTypeHintFullName.l.mkString("|"))
    case c: io.shiftleft.codepropertygraph.generated.nodes.Call => (c.typeFullName, c.dynamicTypeHintFullName.l.mkString("|"))
    case o => (o.label,"")
  }
  println("=== CALLSITE ARG TYPES + CALLEE PARAM TYPES ===")
  cpg.call.l.filter(c=>c.name.matches("f\\d|fAlias|idg|f7")).sortBy(_.lineNumber.getOrElse(0)).foreach { c =>
    val params = cpg.method.fullNameExact(c.callee.fullName.l.headOption.getOrElse("")).l
      .flatMap(_.parameter.l).sortBy(_.index).filter(_.index>0)
      .map(p=>s"${p.index}:${p.typeFullName}${if(p.dynamicTypeHintFullName.l.nonEmpty)"/hints="+p.dynamicTypeHintFullName.l.mkString("|") else ""}").mkString(" ")
    val args = c.argument.l.sortBy(_.argumentIndex).filter(_.argumentIndex>0).map{a=>
      val (ty,h)=t(a); s"${a.code.take(22)} => $ty${if(h.nonEmpty)" /hints="+h else ""}"}.mkString(" ; ")
    println(f"  ${c.name}%-7s L${c.lineNumber.getOrElse(0)}%-4s ARG[$args]  PARAM[$params]")
  }
  println("=== TYPE_DECL IDENTITIES (is there a structural id beyond the string?) ===")
  cpg.typeDecl.l.filter(td=>Set("Router","Widget","ConcreteA","ConcreteB","RealRouter","HandlerLike","RouterAlias").contains(td.name))
    .foreach{td=>println(f"  name=${td.name}%-12s id=${td.id}%-14s fullName=${td.fullName}%-46s ext=${td.isExternal} file=${td.filename}")}
  println("=== TYPE nodes referenced (fullName -> TYPE_DECL link) ===")
  cpg.typ.l.filter(t=>t.name.contains("Router")||t.name.contains("Widget")||t.name.contains("Concrete")||t.name.contains("Handler"))
    .foreach{ty=>println(f"  TYPE ${ty.name}%-28s full=${ty.fullName}%-46s decl=${ty.referencedTypeDecl.l.map(d=>s"${d.id}:${d.filename}").mkString(",")}")}
}
