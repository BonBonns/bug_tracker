@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s:String)=Option(s).getOrElse("").replace("\n"," ").replace("\t"," ").take(80)
  // Walk a fieldAccess chain to its root identifier + build the property path.
  def rootAndPath(e: io.shiftleft.codepropertygraph.generated.nodes.Expression): (Option[io.shiftleft.codepropertygraph.generated.nodes.Identifier], List[String]) = e match {
    case c: io.shiftleft.codepropertygraph.generated.nodes.Call if c.name=="<operator>.fieldAccess" =>
      val args = c.argument.l.sortBy(_.argumentIndex)
      val fld = args.lift(1).map(_.code).getOrElse("?")
      val (r,p) = args.headOption.map(rootAndPath).getOrElse((None,Nil))
      (r, p :+ fld)
    case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => (Some(i), Nil)
    case _ => (None, Nil)
  }
  val w=new java.io.PrintWriter(new java.io.File(s"$outDir/ctx_state.tsv"),"UTF-8")
  try cpg.method.l.foreach{ m =>
    val ctxParam = m.parameter.l.find(_.index==1)          // POSITIONAL, never by name
    ctxParam.foreach{ cp =>
      val stmts = m.block.astChildren.l.sortBy(_.order)
      // next() = a call on the parameter at index 2 (positional), else any bare call to it
      val nextParam = m.parameter.l.find(_.index==2).map(_.name)
      val nextOrd = stmts.find(s => nextParam.exists(n => s.code.contains(n+"("))).map(_.order)
      def ordOf(n: io.shiftleft.codepropertygraph.generated.nodes.AstNode): Int =
        n.inAst.l.collectFirst{ case b if stmts.map(_.id).contains(b.id) => b.order }.getOrElse(-1)
      // WRITES: assignment whose LHS root REFs the context parameter
      m.ast.isCall.nameExact("<operator>.assignment").l.foreach{ a =>
        val args=a.argument.l.sortBy(_.argumentIndex)
        args.headOption.foreach{ lhs =>
          val (root,path)=rootAndPath(lhs)
          val isCtx = root.exists(_.refOut.l.exists(_.id == cp.id))
          if (isCtx && path.nonEmpty) {
            val o = ordOf(a)
            val cond = a.inAst.l.exists(_.isInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.ControlStructure])
            w.println(Seq(cl(m.fullName),"WRITE",path.mkString("."),cl(args.lift(1).map(_.code).getOrElse("")),o,nextOrd.getOrElse(-1),cond).mkString("\t"))
          }
        }
      }
      // READS: fieldAccess whose root REFs the context parameter and isn't an assignment LHS
      m.ast.isCall.nameExact("<operator>.fieldAccess").l.foreach{ fa =>
        val (root,path)=rootAndPath(fa)
        val isCtx = root.exists(_.refOut.l.exists(_.id == cp.id))
        val isLhs = fa.inCall.l.exists(c=>c.name=="<operator>.assignment" && c.argument.l.headOption.exists(_.id==fa.id))
        if (isCtx && path.nonEmpty && !isLhs)
          w.println(Seq(cl(m.fullName),"READ",path.mkString("."),"",ordOf(fa),nextOrd.getOrElse(-1),false).mkString("\t"))
      }
    }
  } finally w.close()
}
