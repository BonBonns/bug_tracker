// JS-PROV-PATHFLOW — path flow-context extractor.
// Exposes the fact-established transitions BETWEEN path nodes: the reachableByFlows
// dataflow path from the established source to the established sink. For each consecutive
// pair of flow elements it emits the transition with a relation_kind CLASSIFIED FROM CPG
// node structure only (never from source text). If the structure does not establish a
// kind, relation_kind = UNKNOWN. No transitions are invented.
//
// path_flow_context.tsv: sink_node, source_node, seq, from_node, to_node, relation_kind,
//                        from_code, to_code, containing_statement, containing_function
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import scala.io.Source

@main def exec(cpgFile: String, rawDir: String) = {
  importCpg(cpgFile)
  implicit val ec: EngineContext = EngineContext()
  def cl(s: String) = Option(s).getOrElse("").replace("\t", " ").replace("\n", " ").take(160)
  def rd(f: String): List[Array[String]] = {
    val p = new java.io.File(s"$rawDir/$f")
    if (p.exists) { val s = Source.fromFile(p); try s.getLines().map(_.split("\t", -1)).toList finally s.close() } else Nil
  }
  def stmt(n: nodes.AstNode): String = {
    var cur = n; var g = 0
    while (cur.astParent != null && !cur.astParent.isInstanceOf[nodes.Block]
           && !cur.astParent.isInstanceOf[nodes.Method] && g < 60) { cur = cur.astParent; g += 1 }
    cur.code
  }
  def fn(n: nodes.AstNode): String = {
    var cur: nodes.AstNode = n; var g = 0
    while (cur != null && !cur.isInstanceOf[nodes.Method] && g < 200) { cur = cur.astParent; g += 1 }
    if (cur != null && cur.isInstanceOf[nodes.Method]) cur.asInstanceOf[nodes.Method].fullName else ""
  }
  // relation kind from CPG structure of the target (and source) node only
  def relKind(from: nodes.AstNode, to: nodes.AstNode): String = to match {
    case _: nodes.MethodParameterIn  => "ARGUMENT_TO_PARAMETER"
    case c: nodes.Call if c.name == "<operator>.fieldAccess"  => "PROPERTY_READ"
    case c: nodes.Call if c.name == "<operator>.assignment"   => "ASSIGNMENT"
    case c: nodes.Call if c.name.startsWith("<operator>")     => "UNKNOWN"
    case _: nodes.Call =>
      from match { case fc: nodes.Call if !fc.name.startsWith("<operator>") => "RETURN_TO_CALL"
                   case _ => "ARGUMENT_TO_PARAMETER" }
    case _: nodes.Identifier =>
      from match { case fc: nodes.Call if !fc.name.startsWith("<operator>") => "CALL_RESULT_TO_LOCAL"
                   case _: nodes.Identifier => "ALIAS"
                   case _: nodes.MethodParameterIn => "ALIAS"
                   case _ => "UNKNOWN" }
    case _ => "UNKNOWN"
  }

  val srcf = rd("source_facts.tsv").filter(r => r.length >= 6 && r(4) == "ESTABLISHED")
  val w = new java.io.PrintWriter(new java.io.File(s"$rawDir/path_flow_context.tsv"), "UTF-8")
  // one established (sink, source) pair per row; compute a single representative flow
  srcf.map(r => (r(0), r(2))).distinct.foreach { case (sinkId, srcId) =>
    val srcT = cpg.all.id(srcId.toLong).collectAll[nodes.Expression]
    val snkT = cpg.all.id(sinkId.toLong).collectAll[nodes.Expression]
    val flows = snkT.reachableByFlows(srcT).l
    flows.headOption.foreach { f =>
      val els = f.elements
      els.sliding(2).zipWithIndex.foreach {
        case (Seq(a, b), i) =>
          w.println(Seq(sinkId, srcId, i.toString, a.id.toString, b.id.toString, relKind(a, b),
                        cl(a.code), cl(b.code), cl(stmt(b)), cl(fn(b))).mkString("\t"))
        case _ =>
      }
    }
  }
  w.close()
  println(s"PATH_FLOW_CONTEXT_COMPLETE: $rawDir/path_flow_context.tsv")
}
