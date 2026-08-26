// JS-PROV-PROPERTY — security-property propagation over an established path.
// The tracked property for serialize-DoS is ATTACKER_CONTROL_OF_SERIALIZED_SIZE_OR_STRUCTURE.
// Each edge carries TWO independent dimensions:
//   structural_relation : how the value moves in the CPG (VALUE_PRESERVING_FLOW, PROPERTY_READ,
//                         LOOKUP_KEY_INFLUENCE, CONTROL_DEPENDENCE, VALUE_TRANSFORM, ...)
//   property_effect     : whether the SECURITY PROPERTY survives the edge
//                         PRESERVES_PROPERTY | TRANSFORMS_PROPERTY | BREAKS_PROPERTY
//                         | PASS_THROUGH (structural noise) | UNKNOWN (needs semantic review)
// Structural edge kind is NOT conflated with property effect. An UNKNOWN property effect is
// never silently treated as preserving.
//
// Per source->sink alternative the outcome is:
//   BROKEN      a BREAKS_PROPERTY edge occurs before the sink (property cannot reach the sink)
//   OPEN        no break, but a property-UNKNOWN transform is on the necessary path
//   ESTABLISHED property preserved/transformed-but-preserved through every edge to the sink
//
// property_propagation.tsv: sink, source, seq, from, to, structural_relation, property_effect,
//                           property_state, from_code, to_code
// property_outcome.tsv:     sink, source, outcome, firstBreakSeq, firstUnknownSeq
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import scala.io.Source

@main def exec(cpgFile: String, rawDir: String) = {
  importCpg(cpgFile)
  implicit val ec: EngineContext = EngineContext()
  val COMPARISON = Set("<operator>.equals","<operator>.notEquals","<operator>.logicalAnd",
    "<operator>.logicalOr","<operator>.logicalNot","buffersAreEqual","<operator>.strictEquals",
    "<operator>.strictNotEquals","<operator>.lessThan","<operator>.greaterThan")
  // known builtins whose size-provenance effect is decided by structure alone
  val SIZE_INFLUENCING = Set("toLowerCase","toUpperCase","trim","trimStart","trimEnd","normalize",
    "concat","padStart","padEnd","replace","replaceAll")            // attacker size-influence survives
  val BOUNDING = Set("slice","substring","substr","charAt","at")     // fixed/attacker-independent bound
  def rd(f: String): List[Array[String]] = {
    val p = new java.io.File(s"$rawDir/$f"); if (!p.exists) return Nil
    val s = Source.fromFile(p); try s.getLines().map(_.split("\t", -1)).toList finally s.close()
  }
  val resolved = rd("definition_resolution.tsv").filter(r => r.length >= 3 && r(2) == "ESTABLISHED").map(_(0)).toSet
  def isArgOf(n: nodes.AstNode, c: nodes.Call) = c.argument.exists(_.id == n.id)
  // a and b are distinct operands of the same comparison (reachableByFlows stitches operands
  // directly, skipping the comparison call node) -> not a value flow, a control/comparison stitch
  def sharedComparison(a: nodes.AstNode, b: nodes.AstNode): Boolean = {
    val pa = a.astParent; val pb = b.astParent
    pa != null && pb != null && pa.id == pb.id && (pa match {
      case c: nodes.Call => COMPARISON.contains(c.name); case _ => false })
  }
  def calleeName(c: nodes.Call): String = {
    if (c.name == "<operator>.fieldAccess") c.code.split("\\.").lastOption.getOrElse(c.name)
    else c.name
  }
  def hasNumericLiteralArg(c: nodes.Call): Boolean =
    c.argument.collectAll[nodes.Literal].exists(l => l.code.matches("-?\\d+"))

  // structural relation from CPG structure only
  def structural(a: nodes.AstNode, b: nodes.AstNode, sinkId: String, entered: Set[String]): String =
    if (sharedComparison(a, b)) "CONTROL_DEPENDENCE" else b match {
    case c: nodes.Call if c.id.toString == sinkId => "ARG_INTO_SINK"
    case _: nodes.MethodParameterIn  => "ARGUMENT_TO_PARAMETER"
    case _: nodes.MethodParameterOut => "VALUE_PRESERVING_FLOW"
    case c: nodes.Call if c.name == "<operator>.fieldAccess" => "PROPERTY_READ"
    case c: nodes.Call if c.name == "<operator>.assignment"  => "VALUE_PRESERVING_FLOW"
    case c: nodes.Call if COMPARISON.contains(c.name)        => "CONTROL_DEPENDENCE"
    case c: nodes.Call if !c.name.startsWith("<operator>") =>
      if (isArgOf(a, c)) {
        val nm = calleeName(c)
        // a transform is traced only if it is a known builtin OR the flow physically entered
        // the callee body (its parameter is on the path). Otherwise the call's result is a
        // black-box value (DB/lookup/external) whose size is not derived from the argument.
        if (SIZE_INFLUENCING.contains(nm) || BOUNDING.contains(nm) || entered.contains(nm)) "VALUE_TRANSFORM"
        else "LOOKUP_KEY_INFLUENCE"
      } else "RECEIVER_OR_ARG_ARTIFACT"
    case _: nodes.Identifier =>
      a match {
        case ac: nodes.Call if COMPARISON.contains(ac.name)      => "CONTROL_DEPENDENCE"
        case ac: nodes.Call if ac.name == "<operator>.fieldAccess" => "VALUE_PRESERVING_FLOW"
        case ac: nodes.Call if !ac.name.startsWith("<operator>") =>
          val nm = calleeName(ac)
          if (SIZE_INFLUENCING.contains(nm) || BOUNDING.contains(nm) || entered.contains(nm)) "VALUE_TRANSFORM"
          else "RETURN_VALUE_DEPENDENCE"
        case _ => if (a.code.trim == b.code.trim) "VALUE_PRESERVING_FLOW" else "RECEIVER_OR_ARG_ARTIFACT"
      }
    case _ => "UNKNOWN"
  }
  // property effect for ATTACKER_CONTROL_OF_SERIALIZED_SIZE_OR_STRUCTURE
  def propEffect(struct: String, a: nodes.AstNode, b: nodes.AstNode): String = struct match {
    case "ARG_INTO_SINK" | "VALUE_PRESERVING_FLOW" | "PROPERTY_READ" | "ARGUMENT_TO_PARAMETER" => "PRESERVES_PROPERTY"
    case "CONTROL_DEPENDENCE" => "BREAKS_PROPERTY"                 // comparison co-operand: definite break
    case "RECEIVER_OR_ARG_ARTIFACT" => "PASS_THROUGH"
    // A lookup key / black-box return does not ESTABLISH size preservation, but neither does its
    // structure prove a break: the returned value's size-provenance is UNKNOWN -> semantic review.
    case "LOOKUP_KEY_INFLUENCE" | "RETURN_VALUE_DEPENDENCE" => "UNKNOWN"
    case "VALUE_TRANSFORM" =>
      val call = (b match { case c: nodes.Call if !c.name.startsWith("<operator>") => Some(c)
                            case _ => a match { case c: nodes.Call if !c.name.startsWith("<operator>") => Some(c); case _ => None } })
      call match {
        case Some(c) =>
          val nm = calleeName(c)
          if (BOUNDING.contains(nm) && hasNumericLiteralArg(c)) "BREAKS_PROPERTY"       // slice(0,32): definite bound
          else if (SIZE_INFLUENCING.contains(nm)) "TRANSFORMS_PROPERTY"                 // toLowerCase: size-influence survives
          else "UNKNOWN"                                                                // user-defined transform: semantic review
        case None => "UNKNOWN"
      }
    case _ => "PASS_THROUGH"
  }

  val srcf = rd("source_facts.tsv").filter(r => r.length >= 6 && r(4) == "ESTABLISHED")
  val w = new java.io.PrintWriter(new java.io.File(s"$rawDir/property_propagation.tsv"), "UTF-8")
  val o = new java.io.PrintWriter(new java.io.File(s"$rawDir/property_outcome.tsv"), "UTF-8")
  w.println(Seq("sink","source","seq","from","to","structural_relation","property_effect","property_state","from_code","to_code").mkString("\t"))
  o.println(Seq("sink","source","outcome","firstBreakSeq","firstUnknownSeq").mkString("\t"))
  // ---- outcome lattice (made explicit so OPEN/BROKEN/NO_FLOW cannot later be collapsed) ----
  // Single alternative (edges composed left-to-right along ONE source->sink path):
  //   PRESERVES + PRESERVES            -> PRESERVES
  //   PRESERVES + TRANSFORMS           -> PRESERVES (attacker size-influence survives)
  //   <anything> + BREAKS              -> BROKEN     (a definite break dominates)
  //   <anything> + UNKNOWN (no break)  -> OPEN        (UNKNOWN is INFECTIOUS along the path)
  // => per-alternative outcome: BROKEN if any BREAKS; else OPEN if any UNKNOWN; else ESTABLISHED.
  def composeAlternative(firstBreak: Int, firstUnknown: Int): String =
    if (firstBreak >= 0) "BROKEN" else if (firstUnknown >= 0) "OPEN" else "ESTABLISHED"
  // Alternatives are EXISTENTIAL: one surviving alternative establishes the (sink,source).
  //   NO_FLOW (no structural relation at all) is kept DISTINCT from BROKEN (relation existed but
  //   the property was demonstrably destroyed) and OPEN (relation existed, semantics unmodeled).
  def joinExistential(ocs: Seq[String]): String =
    if (ocs.isEmpty) "NO_FLOW"
    else if (ocs.contains("ESTABLISHED")) "ESTABLISHED"
    else if (ocs.contains("OPEN")) "OPEN"
    else if (ocs.contains("BROKEN")) "BROKEN"
    else "NO_FLOW"

  srcf.map(r => (r(0), r(2))).distinct.foreach { case (sinkId, srcId) =>
    val flows = cpg.all.id(sinkId.toLong).collectAll[nodes.Expression].reachableByFlows(
                  cpg.all.id(srcId.toLong).collectAll[nodes.Expression]).l.take(12)
    val evaluated = flows.map { f =>
      var fb = -1; var fu = -1
      val entered = f.elements.collect { case p: nodes.MethodParameterIn => p.method.name }.toSet
      val edges = f.elements.sliding(2).zipWithIndex.map {
        case (Seq(a, b), i) =>
          val st = structural(a, b, sinkId, entered); val pe = propEffect(st, a, b)
          if (pe == "BREAKS_PROPERTY" && fb < 0) fb = i
          if (pe == "UNKNOWN" && fu < 0) fu = i
          (i, a, b, st, pe)
        case _ => (-1, null, null, "", "")
      }.toList
      (composeAlternative(fb, fu), fb, fu, edges)
    }
    val outcome = joinExistential(evaluated.map(_._1))
    // emit the decisive alternative (the one realizing the joined outcome), if any
    val decisive = evaluated.find(_._1 == outcome)
    decisive.foreach { case (_, fb, fu, edges) =>
      edges.foreach { case (i, a, b, st, pe) =>
        if (a != null) {
          val state = if (fb >= 0 && i >= fb) "DEAD" else if (fu >= 0 && i >= fu) "UNRESOLVED" else "LIVE"
          w.println(Seq(sinkId, srcId, i.toString, a.id.toString, b.id.toString, st, pe, state,
                        a.code.replace("\t"," ").replace("\n"," ").take(48),
                        b.code.replace("\t"," ").replace("\n"," ").take(48)).mkString("\t"))
        }
      }
    }
    val fb = decisive.map(_._2).getOrElse(-1); val fu = decisive.map(_._3).getOrElse(-1)
    o.println(Seq(sinkId, srcId, outcome, fb.toString, fu.toString).mkString("\t"))
    println(s"OUTCOME sink=$sinkId src=$srcId -> $outcome (alternatives=${flows.size} break=$fb unknown=$fu)")
  }
  w.close(); o.close()
  println(s"PROPERTY_PROPAGATION_COMPLETE: $rawDir")
}
