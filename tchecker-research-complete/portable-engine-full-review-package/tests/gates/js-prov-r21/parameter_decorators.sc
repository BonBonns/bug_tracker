// JS-PROV-R21 — parameter decorator facts. Emits the decorator NAME only.
// The annotation's ARGUMENT is deliberately NOT emitted: JS-PROV-R20 measured
// that `@Param('id')` exposes no parameterAssign and no AST children, so the
// key exists only inside the annotation's code string -- and code strings are
// not identities (JS-PROV-R13).
@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s:String)=Option(s).getOrElse("").replace("\n"," ").replace("\t"," ").take(80)
  val w=new java.io.PrintWriter(new java.io.File(s"$outDir/param_decorators.tsv"),"UTF-8")
  try cpg.typeDecl.l.foreach{ td =>
    val classAnn = td.annotation.name.l.mkString("|")
    td.method.l.foreach{ m =>
      val methAnn = m.annotation.name.l.mkString("|")
      m.parameter.l.filter(_.index>0).sortBy(_.index).foreach{ p =>
        val pann = p.annotation.name.l.mkString("|")
        w.println(Seq(cl(td.fullName), classAnn, cl(m.fullName), methAnn,
                      p.index, cl(p.name), pann).mkString("\t"))
      }
    }
  } finally w.close()
}
