@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s:String)=Option(s).getOrElse("").replace("\n"," ").replace("\t"," ").take(70)
  val w=new java.io.PrintWriter(new java.io.File(s"$outDir/callback_args.tsv"),"UTF-8")
  try cpg.call.l.foreach{c=>
    c.argument.l.sortBy(_.argumentIndex).foreach{a=>
      val (nodeT, resolved, ftype) = a match {
        case m: io.shiftleft.codepropertygraph.generated.nodes.MethodRef => ("METHOD_REF", m.methodFullName, "")
        case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier =>
          val refM = i.refOut.l.collectFirst{
            case l: io.shiftleft.codepropertygraph.generated.nodes.Local =>
              // local assigned from a METHOD_REF?
              l.referencingIdentifiers.l.flatMap(_.inCall.nameExact("<operator>.assignment").l)
               .flatMap(_.argument.l).collectFirst{case mr: io.shiftleft.codepropertygraph.generated.nodes.MethodRef=>mr.methodFullName}.getOrElse("")
          }.getOrElse("")
          ("IDENTIFIER", if(refM.nonEmpty) refM else i.typeFullName, i.typeFullName)
        case x: io.shiftleft.codepropertygraph.generated.nodes.Call => ("CALL", x.methodFullName, x.typeFullName)
        case l: io.shiftleft.codepropertygraph.generated.nodes.Literal => ("LITERAL","",l.typeFullName)
        case o => (o.label,"","")
      }
      w.println(Seq(c.id, cl(c.name), a.argumentIndex, nodeT, cl(a.code), cl(resolved), cl(ftype)).mkString("\t"))
    }
  } finally w.close()
  val p=new java.io.PrintWriter(new java.io.File(s"$outDir/method_params.tsv"),"UTF-8")
  try cpg.method.l.foreach{m=> m.parameter.l.sortBy(_.index).foreach{pp=>
    p.println(Seq(cl(m.fullName), pp.index, cl(pp.name), cl(pp.typeFullName), cl(pp.dynamicTypeHintFullName.l.mkString("|"))).mkString("\t"))}}
  finally p.close()
}
