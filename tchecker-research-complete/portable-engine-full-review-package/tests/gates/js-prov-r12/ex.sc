@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  val w = new java.io.PrintWriter(new java.io.File(s"$outDir/callsites.tsv"),"UTF-8")
  try cpg.call.l.foreach { c =>
    val callees = c.callee.l
    if (callees.size == 1) {
      val m = callees.head
      c.argument.l.sortBy(_.argumentIndex).foreach { a =>
        val (kind, ty) = a match {
          case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => ("IDENTIFIER", i.typeFullName)
          case x: io.shiftleft.codepropertygraph.generated.nodes.Call => ("CALL", x.typeFullName)
          case l: io.shiftleft.codepropertygraph.generated.nodes.Literal => ("LITERAL", l.typeFullName)
          case o => (o.label, "")
        }
        val hints = a match {
          case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => i.dynamicTypeHintFullName.l.mkString("|")
          case x: io.shiftleft.codepropertygraph.generated.nodes.Call => x.dynamicTypeHintFullName.l.mkString("|")
          case _ => "" }
        val p = m.parameter.l.find(_.index == a.argumentIndex)
        w.println(Seq(c.id, m.id, m.fullName.replace("\n"," ").replace("\t"," "), a.argumentIndex, kind, ty, hints,
          p.map(_.name).getOrElse(""), p.map(_.typeFullName).getOrElse(""),
          p.map(_.isVariadic).getOrElse(false), p.map(_.code.replace("\n"," ").replace("\t"," ").take(40)).getOrElse("")).mkString("\t"))
      }
    }
  } finally w.close()
  val t = new java.io.PrintWriter(new java.io.File(s"$outDir/typedecls.tsv"),"UTF-8")
  try cpg.typeDecl.l.foreach{td=>t.println(Seq(td.id,td.name,td.fullName,td.isExternal).mkString("\t"))} finally t.close()
}
