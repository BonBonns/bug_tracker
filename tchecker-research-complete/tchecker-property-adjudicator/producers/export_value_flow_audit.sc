// JS-PROV-VALUEAUDIT — attacker-value-preservation audit over an established path.
// reachableByFlows establishes data-dependence REACHABILITY, not attacker-VALUE preservation.
// This audit classifies each consecutive edge of the established source->sink flow by its
// semantic flow kind, using CPG STRUCTURE ONLY, and reports the FIRST edge at which
// attacker-value preservation is no longer established.
//
// Edge kinds:
//   VALUE_PRESERVING_FLOW      assignment / alias of the same value
//   VALUE_TRANSFORM            call whose RESOLVED definition returns an arg-derived value
//   PROPERTY_READ              field/element extracted from a live value
//   ARGUMENT_TO_PARAMETER      value passed into a callee parameter (still live inside callee)
//   LOOKUP_KEY_INFLUENCE       value is an argument to a call whose RESULT is a separate,
//                              non-arg-derived value (callee definition UNKNOWN) -> value NOT
//                              preserved into that result
//   CONTROL_DEPENDENCE         value is an operand of a comparison/boolean; the co-operand or
//                              boolean result is NOT the value
//   RECEIVER_OR_ARG_ARTIFACT   receiver<->call or co-argument stitch (not a value carry)
//   RETURN_VALUE_DEPENDENCE    result of an unresolved call; not established as arg-derived
//   UNKNOWN
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import scala.io.Source

@main def exec(cpgFile: String, rawDir: String) = {
  importCpg(cpgFile)
  implicit val ec: EngineContext = EngineContext()
  val COMPARISON = Set("<operator>.equals", "<operator>.notEquals", "<operator>.logicalAnd",
    "<operator>.logicalOr", "<operator>.logicalNot", "buffersAreEqual", "<operator>.strictEquals",
    "<operator>.strictNotEquals", "<operator>.lessThan", "<operator>.greaterThan")
  def rd(f: String): List[Array[String]] = {
    val p = new java.io.File(s"$rawDir/$f"); if (!p.exists) return Nil
    val s = Source.fromFile(p); try s.getLines().map(_.split("\t", -1)).toList finally s.close()
  }
  // resolved (value-preserving-capable) call nodes from the definition resolver
  val resolved = rd("definition_resolution.tsv").filter(r => r.length >= 3 && r(2) == "ESTABLISHED").map(_(0)).toSet

  def callOf(n: nodes.AstNode): Option[nodes.Call] = n match {
    case c: nodes.Call => Some(c)
    case _ => n.astParent match { case c: nodes.Call => Some(c); case _ => None }
  }
  def isArgOf(n: nodes.AstNode, c: nodes.Call): Boolean = c.argument.exists(_.id == n.id)

  def classify(a: nodes.AstNode, b: nodes.AstNode, sinkId: String): String = b match {
    case c: nodes.Call if c.id.toString == sinkId => "VALUE_PRESERVING_FLOW"  // arg serialized by the sink
    case _: nodes.MethodParameterIn  => "ARGUMENT_TO_PARAMETER"
    case _: nodes.MethodParameterOut => "VALUE_PRESERVING_FLOW"    // param carried back, same value
    case c: nodes.Call if c.name == "<operator>.fieldAccess" => "PROPERTY_READ"
    case c: nodes.Call if c.name == "<operator>.assignment"  => "VALUE_PRESERVING_FLOW"
    case c: nodes.Call if COMPARISON.contains(c.name)        => "CONTROL_DEPENDENCE"
    case c: nodes.Call if !c.name.startsWith("<operator>") =>
      if (isArgOf(a, c)) { if (resolved.contains(c.id.toString)) "VALUE_TRANSFORM" else "LOOKUP_KEY_INFLUENCE" }
      else "RECEIVER_OR_ARG_ARTIFACT"                              // a is the receiver, not the argument
    case _: nodes.Identifier =>
      a match {
        case ac: nodes.Call if COMPARISON.contains(ac.name)       => "CONTROL_DEPENDENCE"
        case ac: nodes.Call if !ac.name.startsWith("<operator>")  =>
          if (resolved.contains(ac.id.toString)) "VALUE_TRANSFORM" else "RETURN_VALUE_DEPENDENCE"
        case ac: nodes.Call if ac.name == "<operator>.fieldAccess" => "VALUE_PRESERVING_FLOW" // field value assigned
        case _ =>
          if (a.code.trim == b.code.trim) "VALUE_PRESERVING_FLOW"  // alias of the SAME value
          else "RECEIVER_OR_ARG_ARTIFACT"                          // receiver/co-arg stitch (noise, non-decisive)
      }
    case _ => "UNKNOWN"
  }
  val PRESERVING = Set("VALUE_PRESERVING_FLOW", "VALUE_TRANSFORM", "PROPERTY_READ", "ARGUMENT_TO_PARAMETER")
  val BREAKING = Set("LOOKUP_KEY_INFLUENCE", "CONTROL_DEPENDENCE")  // decisive attacker-value non-preservation

  val srcf = rd("source_facts.tsv").filter(r => r.length >= 6 && r(4) == "ESTABLISHED")
  val w = new java.io.PrintWriter(new java.io.File(s"$rawDir/value_flow_audit.tsv"), "UTF-8")
  w.println(Seq("sink","source","seq","from","to","edge_kind","attacker_value_preserved","from_code","to_code").mkString("\t"))
  srcf.map(r => (r(0), r(2))).distinct.foreach { case (sinkId, srcId) =>
    val flows = cpg.all.id(sinkId.toLong).collectAll[nodes.Expression].reachableByFlows(
                  cpg.all.id(srcId.toLong).collectAll[nodes.Expression]).l
    flows.headOption.foreach { f =>
      var live = true; var firstBreak = -1
      f.elements.sliding(2).zipWithIndex.foreach {
        case (Seq(a, b), i) =>
          val k = classify(a, b, sinkId)
          if (live && BREAKING.contains(k)) { firstBreak = i; live = false }
          w.println(Seq(sinkId, srcId, i.toString, a.id.toString, b.id.toString, k,
                        (if (firstBreak < 0) "yes" else "no"),
                        a.code.replace("\t"," ").replace("\n"," ").take(50),
                        b.code.replace("\t"," ").replace("\n"," ").take(50)).mkString("\t"))
        case _ =>
      }
      println(s"AUDIT sink=$sinkId source=$srcId firstBreakEdge=$firstBreak (of ${f.elements.size-1})")
    }
  }
  w.close()
  println(s"VALUE_FLOW_AUDIT_COMPLETE: $rawDir/value_flow_audit.tsv")
}
