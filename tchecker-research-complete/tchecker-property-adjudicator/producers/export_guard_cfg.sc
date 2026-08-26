// JS-PROV-GF2 — guard control-flow STRUCTURE (class-extension producer).
// Emits the control-flow structure the fallthrough verdict collapses to a boolean,
// so the canonical evidence model can preserve it. Establishes only structure; no
// security heuristics.
//
// guard_cfg.tsv:
//   method, kind(GUARD|SINK), node_id, line, condition_compound(true|false|-),
//   enclosing_branch_id, guard_condition_code
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s: String) = Option(s).getOrElse("").replace("\n", " ").replace("\t", " ").take(80)
  val w = new java.io.PrintWriter(new java.io.File(s"$outDir/guard_cfg.tsv"), "UTF-8")

  // nearest enclosing IF control structure id (branch identity), for coverage.
  def enclosingIf(n: nodes.Call): Option[nodes.ControlStructure] =
    n.inAst.collectAll[nodes.ControlStructure].filter(_.controlStructureType == "IF").l.headOption
  def enclosingBranch(n: nodes.Call): String =
    enclosingIf(n).map(_.id.toString).getOrElse("")

  try {
    // collect guard IF-condition node ids (a sink dominated by one is guarded)
    val guardCondIds = scala.collection.mutable.Set[Long]()
    // guard calls = deny/guard-ish bare or returned calls inside a conditional
    cpg.call.l.filter(c => c.name.matches("(?i).*deny.*|.*guard.*|.*forbid.*|.*reject.*")).foreach { c =>
      val m = c.method
      val ifNode = enclosingIf(c)
      val cond = ifNode.flatMap(_.condition.headOption)
      cond.foreach(x => guardCondIds += x.id)
      val condCode = cond.map(x => Option(x.code).getOrElse("")).getOrElse("")
      val compound = condCode.contains("&&") || condCode.contains("||")
      w.println(Seq(cl(m.fullName), "GUARD", c.id.toString,
        c.lineNumber.map(_.toString).getOrElse(""), compound.toString,
        ifNode.map(_.id.toString).getOrElse(""), cl(condCode)).mkString("\t"))
    }
    // sensitive ops (DB writes); guarded = dominated by a guard condition
    cpg.call.name("update").l.foreach { c =>
      val m = c.method
      val domIds = c.dominatedBy.id.toSet
      val guarded = domIds.exists(guardCondIds.contains)
      w.println(Seq(cl(m.fullName), "SINK", c.id.toString,
        c.lineNumber.map(_.toString).getOrElse(""), guarded.toString,
        enclosingBranch(c), "").mkString("\t"))
    }
  } finally w.close()
  println(s"GUARD_CFG_COMPLETE: $outDir")
}
