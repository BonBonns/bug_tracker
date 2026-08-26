// Multi-alternative measurement: for each sink id, find ALL distinct source origins (not just
// flows.head as the batch stager did), and classify each origin's property outcome separately
// (reusing the frozen classifier verbatim). Answers: how many candidates have >1 distinct origin,
// and does the origin used in staging (the first one found) match the origin actually driving the
// candidate's join_existential outcome. No classifier or adjudicator change; measurement only.
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

@main def exec(cpgFile: String, sinkListFile: String, outDir: String) = {
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
  def pathOutcome(effects: Seq[String]): String =
    if (effects.contains("BREAKS_PROPERTY")) "BROKEN"
    else if (effects.contains("UNKNOWN")) "OPEN"
    else "ESTABLISHED"
  def joinExistential(outcomes: Seq[String]): String =
    if (outcomes.contains("ESTABLISHED")) "ESTABLISHED"
    else if (outcomes.contains("OPEN")) "OPEN"
    else if (outcomes.contains("BROKEN")) "BROKEN"
    else "NO_FLOW"

  val sinkIds = scala.io.Source.fromFile(sinkListFile).getLines().map(_.trim).filter(_.nonEmpty).toList
  val w = new java.io.PrintWriter(new java.io.File(s"$outDir/multi_alt_measurement.tsv"))
  w.println(Seq("sink_id","n_distinct_origins","first_origin_id","first_origin_outcome",
                "joined_outcome","first_matches_joined","origin_outcomes").mkString("\t"))

  sinkIds.foreach { sinkIdStr =>
    try {
      val sinkId = sinkIdStr.toLong
      val sk = cpg.call.id(sinkId).headOption
      if (sk.isDefined) {
        val sink = sk.get
        val sinkFile = sink.file.name.headOption.getOrElse("?")
        val sources = cpg.call.name("<operator>.fieldAccess")
          .code("this\\.(bodyParams|queryParams|urlParams)(\\..*)?")
          .filter(_.file.name.headOption.contains(sinkFile)).l
        val flows = cpg.all.id(sinkId).collectAll[nodes.Expression]
          .reachableByFlows(sources.iterator.map(n => n: nodes.Expression)).l.take(30)
        if (flows.nonEmpty) {
          // group flows by DISTINCT ORIGIN (first element's id)
          val byOrigin = flows.groupBy(_.elements.head.id)
          val originIds = byOrigin.keys.toList
          val outcomesPerOrigin = originIds.map { oid =>
            val oflows = byOrigin(oid)
            val entered = oflows.flatMap(_.elements.flatMap {
              case p: nodes.MethodParameterIn => Some(p.method.name); case _ => None
            }).toSet
            val perPath = oflows.map { f =>
              val effects = f.elements.sliding(2).collect {
                case Seq(a, b) => propEffect(structural(a, b, sinkIdStr, entered), a, b)
              }.toSeq
              pathOutcome(effects)
            }
            (oid, joinExistential(perPath))
          }
          val joined = joinExistential(outcomesPerOrigin.map(_._2))
          val firstOriginId = flows.head.elements.head.id
          val firstOutcome = outcomesPerOrigin.find(_._1 == firstOriginId).map(_._2).getOrElse("?")
          val matches = if (firstOutcome == joined) "YES" else "NO_MISMATCH"
          val summary = outcomesPerOrigin.map{case(o,oc)=>s"$o:$oc"}.mkString(";")
          w.println(Seq(sinkIdStr, originIds.size, firstOriginId, firstOutcome, joined, matches, summary).mkString("\t"))
          w.flush()
          System.err.println(s"[$sinkIdStr] origins=${originIds.size} first=$firstOutcome joined=$joined match=$matches")
        } else {
          System.err.println(s"[$sinkIdStr] no flow")
        }
      } else {
        System.err.println(s"[$sinkIdStr] sink not found")
      }
    } catch { case e: Exception => System.err.println(s"[$sinkIdStr] ERROR: ${e.getMessage.take(150)}") }
  }
  w.close()
  System.err.println("MULTI_ALT_MEASUREMENT_COMPLETE")
}
