@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  val w = new java.io.PrintWriter(new java.io.File(s"$outDir/registrations.tsv"),"UTF-8")
  def clean(s:String) = Option(s).getOrElse("").replace("\n"," ").replace("\t"," ").take(60)
  try cpg.call.l.foreach { c =>
    val recv = c.argument.l.find(_.argumentIndex == 0)
    recv.foreach {
      case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier =>
        // receiver -> REF -> is it a METHOD_PARAMETER_IN? if so record (method, index)
        val refs = i.refOut.l
        val asParam = refs.collectFirst {
          case p: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn =>
            (p.method.fullName, p.index)
        }
        w.println(Seq(
          c.id, clean(c.name), clean(c.methodFullName), clean(c.method.fullName),
          i.name, i.typeFullName,
          asParam.map(_._1).getOrElse(""), asParam.map(_._2.toString).getOrElse(""),
          c.argument.l.size
        ).mkString("\t"))
      case _ =>
    }
  } finally w.close()
}
