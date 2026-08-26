// Enumeration audit: for every reachableByFlows PATH from a request source to a stringify sink,
// emit the per-edge structural_relation / property_effect using the SAME frozen classifier as
// export_property_propagation.sc. No classifier change. Python then measures spurious enumeration.
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile)
  implicit val ec: EngineContext = EngineContext()

  val COMPARISON = Set("<operator>.equals","<operator>.notEquals","<operator>.logicalAnd",
    "<operator>.logicalOr","<operator>.logicalNot","buffersAreEqual","<operator>.strictEquals",
    "<operator>.strictNotEquals","<operator>.lessThan","<operator>.greaterThan")
  val SIZE_INFLUENCING = Set("toLowerCase","toUpperCase","trim","trimStart","trimEnd","normalize",
    "concat","padStart","padEnd","replace","replaceAll")
  val BOUNDING = Set("slice","substring","substr","charAt","at")

  def isArgOf(n: nodes.AstNode, c: nodes.Call) = c.argument.exists(_.id == n.id)
  def sharedComparison(a: nodes.AstNode, b: nodes.AstNode): Boolean = {
    val pa = a.astParent; val pb = b.astParent
    pa != null && pb != null && pa.id == pb.id && (pa match {
      case c: nodes.Call => COMPARISON.contains(c.name); case _ => false })
  }
  def calleeName(c: nodes.Call): String =
    if (c.name == "<operator>.fieldAccess") c.code.split("\\.").lastOption.getOrElse(c.name) else c.name
  def hasNumericLiteralArg(c: nodes.Call): Boolean =
    c.argument.collectAll[nodes.Literal].exists(l => l.code.matches("-?\\d+"))

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
  def propEffect(struct: String, a: nodes.AstNode, b: nodes.AstNode): String = struct match {
    case "ARG_INTO_SINK" | "VALUE_PRESERVING_FLOW" | "PROPERTY_READ" | "ARGUMENT_TO_PARAMETER" => "PRESERVES_PROPERTY"
    case "CONTROL_DEPENDENCE" => "BREAKS_PROPERTY"
    case "RECEIVER_OR_ARG_ARTIFACT" => "PASS_THROUGH"
    case "LOOKUP_KEY_INFLUENCE" | "RETURN_VALUE_DEPENDENCE" => "UNKNOWN"
    case "VALUE_TRANSFORM" =>
      val call = (b match { case c: nodes.Call if !c.name.startsWith("<operator>") => Some(c)
                            case _ => a match { case c: nodes.Call if !c.name.startsWith("<operator>") => Some(c); case _ => None } })
      call match {
        case Some(c) =>
          val nm = calleeName(c)
          if (BOUNDING.contains(nm) && hasNumericLiteralArg(c)) "BREAKS_PROPERTY"
          else if (SIZE_INFLUENCING.contains(nm)) "TRANSFORMS_PROPERTY"
          else "UNKNOWN"
        case None => "UNKNOWN"
      }
    case _ => "PASS_THROUGH"
  }

  val sinks = cpg.call.name("stringify").l
  val sources = cpg.call.name("<operator>.fieldAccess").code(".*this\\.(bodyParams|queryParams|urlParams).*").l
  System.err.println(s"sinks=${sinks.size} sources=${sources.size}")

  val w = new java.io.PrintWriter(new java.io.File(s"$outDir/enumeration_audit.tsv"), "UTF-8")
  w.println(Seq("path_id","sink_id","source_code","seq","from_code","to_code","structural_relation","property_effect").mkString("\t"))
  var pid = 0
  sinks.foreach { sk =>
    val flows = cpg.all.id(sk.id).collectAll[nodes.Expression].reachableByFlows(sources.iterator).l.take(60)   // cap per sink
    flows.foreach { f =>
      val els = f.elements
      if (els.size >= 2) {
        val entered = els.collect { case p: nodes.MethodParameterIn => p.method.name }.toSet
        val srcCode = els.head.code.replace("\t"," ").replace("\n"," ").take(40)
        els.sliding(2).zipWithIndex.foreach { case (Seq(a, b), i) =>
          val st = structural(a, b, sk.id.toString, entered)
          val pe = propEffect(st, a, b)
          w.println(Seq(pid, sk.id, srcCode, i,
                        a.code.replace("\t"," ").replace("\n"," ").take(40),
                        b.code.replace("\t"," ").replace("\n"," ").take(40), st, pe).mkString("\t"))
        }
        pid += 1
      }
    }
  }
  w.close()
  System.err.println(s"AUDIT_COMPLETE paths=$pid -> $outDir/enumeration_audit.tsv")
}
