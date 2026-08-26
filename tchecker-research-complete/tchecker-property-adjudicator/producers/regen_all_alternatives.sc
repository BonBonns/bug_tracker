// Regenerates ALL FOUR alternatives (o0 HTTP_BODY, o1 cross-file HTTP_BODY, o2 HTTP_QUERY,
// o3 HTTP_HEADERS) for the customs.js candidate from scratch, in ONE pass, using the identical
// current methodology throughout (reachableByFlows + the frozen structural/property classifier +
// enclosingCall-based on-path transform enumeration). No hand-patching, no reuse of the older
// hand-staged o0/o1/o2 facts. Overwrites source_facts.tsv, propagation_relations.tsv,
// property_outcome.tsv, transform_identity.tsv for this sink entirely.
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

val COMPARISON = Set("<operator>.equals","<operator>.notEquals","<operator>.logicalAnd",
  "<operator>.logicalOr","<operator>.logicalNot","buffersAreEqual","<operator>.strictEquals",
  "<operator>.strictNotEquals","<operator>.lessThan","<operator>.greaterThan")
val SIZE_INFLUENCING = Set("toLowerCase","toUpperCase","trim","trimStart","trimEnd","normalize",
  "concat","padStart","padEnd","replace","replaceAll")
val BOUNDING = Set("slice","substring","substr","charAt","at")
val BUILTIN = Set("stringify","parse","keys","values","map","filter","forEach","join","split")

@main def exec(cpgFile: String, rawDir: String, sinkId: String) = {
  importCpg(cpgFile)
  implicit val ec: EngineContext = EngineContext()

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
  def structural(a: nodes.AstNode, b: nodes.AstNode, entered: Set[String]): String =
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
  def enclosingCall(n: nodes.AstNode): Option[nodes.Call] = {
    var cur: nodes.AstNode = n; var hops = 0
    while (hops < 6) {
      val p = scala.util.Try(cur.astParent).toOption
      p match { case Some(c: nodes.Call) => return Some(c); case Some(null) => return None
                case Some(pp) => cur = pp; hops += 1; case None => return None }
    }
    None
  }

  val sink = cpg.call.id(sinkId.toLong).head
  // the four origins, identified precisely and independently (see find_all_origins.sc output)
  val origins = Seq(
    ("HTTP_BODY",    30064771225L),  // o0: request.payload, customs.js:130
    ("HTTP_BODY",    30064772713L),  // o1: request.payload, emails.js:980 (cross-file)
    ("HTTP_QUERY",   30064771228L),  // o2: request.query, customs.js:134
    ("HTTP_HEADERS", 30064771231L)   // o3: request.headers, customs.js:135
  )

  new java.io.File(rawDir).mkdirs()
  val sf = new java.io.PrintWriter(s"$rawDir/source_facts.tsv")
  val pr = new java.io.PrintWriter(s"$rawDir/propagation_relations.tsv")
  val po = new java.io.PrintWriter(s"$rawDir/property_outcome.tsv")
  val ti = new java.io.PrintWriter(s"$rawDir/transform_identity.tsv")

  origins.foreach { case (fam, srcId) =>
    val srcNode = cpg.all.id(srcId).collectAll[nodes.Expression].head
    val flows = cpg.all.id(sinkId.toLong).collectAll[nodes.Expression]
      .reachableByFlows(Iterator(srcNode)).l
    println(s"REGEN family=$fam node=$srcId flows_found=${flows.size}")
    if (flows.nonEmpty) {
      val entered = flows.flatMap(_.elements.flatMap {
        case p: nodes.MethodParameterIn => Some(p.method.name); case _ => None
      }).toSet
      val perPath = flows.map { f =>
        val effects = f.elements.sliding(2).collect { case Seq(a,b) => propEffect(structural(a,b,entered), a, b) }.toSeq
        pathOutcome(effects)
      }
      val outcome = if (perPath.contains("ESTABLISHED")) "ESTABLISHED" else if (perPath.contains("OPEN")) "OPEN" else "BROKEN"
      println(s"REGEN family=$fam outcome=$outcome")

      // on-path transform enumeration: SAME rule for every origin, no exceptions.
      // A call is counted as a genuine on-path transform ONLY when found via a flow element that
      // is NOT a bare Identifier. Confirmed by direct inspection of o1's full flow trace: genuine
      // transforms (sanitizePayload, makeRequest) are found via structurally rich elements --
      // object literals, call-result/RET steps -- where the call's own contribution is what
      // continues toward the sink. Spurious matches (toOpts, db.account, a forwarding call like
      // customs.checkAuthenticated) were found via a BARE identifier (e.g. "uid") that merely sits
      // in that call's argument list while the value that actually continues to the sink is the
      // SAME unchanged identifier, reached via a separate alias/parameter-passing path that
      // bypasses the call's own result entirely -- confirmed by checking that none of those calls'
      // own return values ever appear as a later flow element on the same path.
      val seen = scala.collection.mutable.LinkedHashSet[Long]()
      val xforms = scala.collection.mutable.ListBuffer[nodes.Call]()
      flows.foreach { f =>
        f.elements.foreach { e =>
          val isBareIdentifier = e.isInstanceOf[nodes.Identifier]
          if (!isBareIdentifier) {
            enclosingCall(e).foreach { c =>
              if (!c.name.startsWith("<operator>") && !BUILTIN.contains(c.name) &&
                  c.argument.exists(_.id == e.id) && !seen.contains(c.id) && c.id.toString != sinkId) {
                seen += c.id
                xforms += c
              }
            }
          }
        }
      }
      println(s"REGEN family=$fam xforms=${xforms.map(c => s"${c.name}@${c.lineNumber.getOrElse(-1)}").mkString(",")}")

      val srcLine = srcNode.lineNumber.getOrElse(-1)
      val srcCode = srcNode.code
      sf.println(Seq(sinkId, sink.lineNumber.getOrElse(-1), srcId, fam, "ESTABLISHED", "","","","","","","").mkString("\t"))
      pr.println(Seq(sinkId, "", "", srcId, srcLine, srcCode, "", "", "").mkString("\t"))
      po.println(Seq(sinkId, srcId, outcome, "-1", "-1").mkString("\t"))
      xforms.zipWithIndex.foreach { case (c, order) =>
        val name = if (c.name == "<operator>.fieldAccess") c.code.split("\\.").lastOption.getOrElse(c.name) else c.name
        ti.println(Seq("x", srcId.toString, order.toString, c.id.toString, name, "", "", "UNKNOWN").mkString("\t"))
      }
    }
  }
  sf.close(); pr.close(); po.close(); ti.close()
  println("REGEN_COMPLETE")
}
