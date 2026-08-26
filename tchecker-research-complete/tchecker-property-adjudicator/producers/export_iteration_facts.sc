// JS-PROV-LV2 — callback-iteration control-effect facts (validation-bypass class).
// The FOR/WHILE producer (export_loop_facts) does not see returns inside iterator-
// method callbacks (arr.forEach(x => { ... return; })). This captures them and the
// iterator API identity, so the evidence model can distinguish:
//   - a callback return whose iterator IGNORES it (forEach/map) -> continue-like
//   - a callback return that SHORT-CIRCUITS (some/every/find) -> terminates outer
//   - an UNKNOWN iterator helper -> control effect UNRESOLVED
//
// iteration_facts.tsv:
//   file, method, iterator_call_node, iterator_name, iterator_known(true|false),
//   callback_method_id, return_node, return_line, returns_value(true|false)
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s: String) = Option(s).getOrElse("").replace("\n", " ").replace("\t", " ").take(80)
  val KNOWN = Set("forEach", "map", "filter", "some", "every", "find", "findIndex", "reduce", "flatMap")
  val w = new java.io.PrintWriter(new java.io.File(s"$outDir/iteration_facts.tsv"), "UTF-8")
  try {
    cpg.call.l.filter(c => !c.name.startsWith("<operator>")).foreach { c =>
      val iterName = c.name
      val cbs = c.argument.collectAll[nodes.MethodRef].l
      cbs.foreach { ref =>
        val cbOpt = Option(ref.referencedMethod)
        cbOpt.foreach { cb =>
          val known = KNOWN.contains(iterName)
          // returns whose nearest enclosing method is THIS callback (not a deeper nested fn)
          cb.ast.isReturn.l.filter { r =>
            r.method.id == cb.id
          }.foreach { r =>
            val rc = Option(r.code).getOrElse("").trim
            val returnsValue = r.astChildren.l.nonEmpty && rc != "return" && rc != "return;" &&
              !rc.matches("""return\s+(undefined|null|false)\s*;?""")
            w.println(Seq(cl(c.method.filename), cl(c.method.fullName), c.id.toString,
              cl(iterName), known.toString, cb.id.toString, r.id.toString,
              r.lineNumber.map(_.toString).getOrElse(""), returnsValue.toString).mkString("\t"))
          }
        }
      }
    }
  } finally w.close()
  println(s"ITERATION_FACTS_COMPLETE: $outDir")
}
