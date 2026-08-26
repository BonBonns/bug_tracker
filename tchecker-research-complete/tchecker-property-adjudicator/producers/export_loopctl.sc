// JS-PROV-LV2 — loop control-EFFECT structure (validation-bypass class extension).
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s: String) = Option(s).getOrElse("").replace("\n", " ").replace("\t", " ").take(60)
  def retVal(r: nodes.Return): Boolean = {
    val rc = Option(r.code).getOrElse("").trim
    r.astChildren.l.nonEmpty && rc != "return" && rc != "return;" &&
      !rc.matches("""return\s+(undefined|null|false)\s*;?""")
  }
  val w = new java.io.PrintWriter(new java.io.File(s"$outDir/loopctl.tsv"), "UTF-8")
  def loops(m: nodes.Method) = m.ast.isControlStructure.l.filter(cs =>
    Set("FOR", "WHILE", "DO").contains(cs.controlStructureType) && cs.method.id == m.id)
  try {
    cpg.method.isExternal(false).l.foreach { m =>
      loops(m).foreach { loop =>
        val loopLine = loop.lineNumber.map(_.toInt).getOrElse(-1)
        loop.ast.isReturn.l.filter(_.method.id == m.id).foreach { r =>
          w.println(Seq(cl(m.fullName), loopLine.toString, "RETURN", r.id.toString,
            r.lineNumber.map(_.toString).getOrElse(""), "ENCLOSING", "-",
            retVal(r).toString, cl(Option(r.code).getOrElse("").trim)).mkString("\t"))
        }
        loop.ast.isControlStructure.l.filter(c => Set("BREAK", "CONTINUE").contains(c.controlStructureType))
          .filter(c => c.inAst.collectAll[nodes.ControlStructure].l
            .find(cs => Set("FOR", "WHILE", "DO").contains(cs.controlStructureType)).map(_.id).contains(loop.id))
          .foreach { c =>
            w.println(Seq(cl(m.fullName), loopLine.toString, c.controlStructureType,
              c.id.toString, c.lineNumber.map(_.toString).getOrElse(""),
              "ENCLOSING", "-", "false", "").mkString("\t"))
          }
      }
    }
    cpg.call.l.foreach { call =>
      call.argument.collectAll[nodes.MethodRef].foreach { mr =>
        cpg.method.fullNameExact(mr.methodFullName).foreach { closure =>
          closure.ast.isReturn.l.filter(_.method.id == closure.id).foreach { r =>
            w.println(Seq(cl(call.method.fullName), call.lineNumber.map(_.toString).getOrElse(""),
              "RETURN", r.id.toString, r.lineNumber.map(_.toString).getOrElse(""),
              "CALLBACK", cl(call.name), retVal(r).toString,
              cl(Option(r.code).getOrElse("").trim)).mkString("\t"))
          }
        }
      }
    }
  } finally w.close()
  println(s"LOOPCTL_COMPLETE: $outDir")
}
