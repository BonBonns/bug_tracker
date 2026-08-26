// Stages all three sources (request.payload/query/headers) for the permanent source-coverage
// fixture, computed through the SAME frozen classifier used everywhere else this session. Asserts
// (via printed outcomes) that all three survive enumeration as independent alternatives.
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

val COMPARISON = Set("<operator>.equals","<operator>.notEquals","<operator>.logicalAnd","<operator>.logicalOr")
val SIZE_INFLUENCING = Set("toLowerCase","toUpperCase","trim","concat")
val BOUNDING = Set("slice","substring","substr","charAt","at")

@main def exec(cpgFile: String, rawDir: String, sinkId: String) = {
  importCpg(cpgFile)
  implicit val ec: EngineContext = EngineContext()
  def sharedComparison(a: nodes.AstNode, b: nodes.AstNode): Boolean = {
    val pa = a.astParent; val pb = b.astParent
    pa != null && pb != null && pa.id == pb.id && (pa match { case c: nodes.Call => COMPARISON.contains(c.name); case _ => false })
  }
  def calleeName(c: nodes.Call): String = if (c.name == "<operator>.fieldAccess") c.code.split("\\.").lastOption.getOrElse(c.name) else c.name
  def structural(a: nodes.AstNode, b: nodes.AstNode, entered: Set[String]): String =
    if (sharedComparison(a,b)) "CONTROL_DEPENDENCE" else b match {
      case c: nodes.Call if c.id.toString == sinkId => "ARG_INTO_SINK"
      case _: nodes.MethodParameterIn => "ARGUMENT_TO_PARAMETER"
      case _: nodes.MethodParameterOut => "VALUE_PRESERVING_FLOW"
      case c: nodes.Call if c.name == "<operator>.fieldAccess" => "PROPERTY_READ"
      case c: nodes.Call if c.name == "<operator>.assignment" => "VALUE_PRESERVING_FLOW"
      case c: nodes.Call if COMPARISON.contains(c.name) => "CONTROL_DEPENDENCE"
      case c: nodes.Call if !c.name.startsWith("<operator>") =>
        val nm = calleeName(c)
        if (SIZE_INFLUENCING.contains(nm) || BOUNDING.contains(nm) || entered.contains(nm)) "VALUE_TRANSFORM" else "LOOKUP_KEY_INFLUENCE"
      case _: nodes.Identifier => "VALUE_PRESERVING_FLOW"
      case _ => "UNKNOWN"
    }
  def propEffect(struct: String): String = struct match {
    case "ARG_INTO_SINK" | "VALUE_PRESERVING_FLOW" | "PROPERTY_READ" | "ARGUMENT_TO_PARAMETER" => "PRESERVES_PROPERTY"
    case "CONTROL_DEPENDENCE" => "BREAKS_PROPERTY"
    case "LOOKUP_KEY_INFLUENCE" => "UNKNOWN"
    case "VALUE_TRANSFORM" => "TRANSFORMS_PROPERTY"
    case _ => "PASS_THROUGH"
  }
  def pathOutcome(effects: Seq[String]): String =
    if (effects.contains("BREAKS_PROPERTY")) "BROKEN" else if (effects.contains("UNKNOWN")) "OPEN" else "ESTABLISHED"

  val sink = cpg.call.id(sinkId.toLong).head
  val sourceDefs = Seq(("HTTP_BODY", "request.payload"), ("HTTP_QUERY", "request.query"), ("HTTP_HEADERS", "request.headers"))
  new java.io.File(rawDir).mkdirs()
  val sf = new java.io.PrintWriter(s"$rawDir/source_facts.tsv")
  val pr = new java.io.PrintWriter(s"$rawDir/propagation_relations.tsv")
  val po = new java.io.PrintWriter(s"$rawDir/property_outcome.tsv")
  val ti = new java.io.PrintWriter(s"$rawDir/transform_identity.tsv")
  sourceDefs.foreach { case (fam, pat) =>
    val src = cpg.call.name("<operator>.fieldAccess").code(java.util.regex.Pattern.quote(pat)).head
    val flows = cpg.all.id(sinkId.toLong).collectAll[nodes.Expression].reachableByFlows(Iterator(src: nodes.Expression)).l
    println(s"ASSERT family=$fam node=${src.id} flows_found=${flows.size}")
    if (flows.nonEmpty) {
      val entered = flows.flatMap(_.elements.flatMap { case p: nodes.MethodParameterIn => Some(p.method.name); case _ => None }).toSet
      val perPath = flows.map(f => pathOutcome(f.elements.sliding(2).collect{case Seq(a,b)=>propEffect(structural(a,b,entered))}.toSeq))
      val outcome = if (perPath.contains("ESTABLISHED")) "ESTABLISHED" else if (perPath.contains("OPEN")) "OPEN" else "BROKEN"
      println(s"ASSERT family=$fam outcome=$outcome")
      sf.println(Seq(sinkId, sink.lineNumber.getOrElse(-1), src.id, fam, "ESTABLISHED", "","","","","","","").mkString("\t"))
      pr.println(Seq(sinkId,"","",src.id,src.lineNumber.getOrElse(-1),pat,"","","").mkString("\t"))
      po.println(Seq(sinkId, src.id, outcome, "-1", "-1").mkString("\t"))
    }
  }
  sf.close(); pr.close(); po.close(); ti.close()
  println("STAGE_COMPLETE")
}
