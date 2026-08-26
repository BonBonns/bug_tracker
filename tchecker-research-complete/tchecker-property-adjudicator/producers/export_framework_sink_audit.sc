// Framework sink model measurement: widen the sink set from literal JSON.stringify/EJSON.stringify
// to ALSO include API.v1.success(...) / API.v1.failure(...) calls (established as a sound staging
// point for response.body -> JSON.stringify(body) in packages/http-router/src/Router.ts; see
// FRAMEWORK_SINK_CHARACTERIZATION.md). Reuses the EXACT frozen property-layer classifier -- no
// classifier change. Emits one row per (sink, has-flow) candidate for tallying in Python.
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

@main def exec(cpgFile: String, outDir: String, fileFilter: String) = {
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
  // existential join across edges of one path: BREAKS dominant, else UNKNOWN infectious -> OPEN, else ESTABLISHED
  def pathOutcome(effects: Seq[String]): String =
    if (effects.contains("BREAKS_PROPERTY")) "BROKEN"
    else if (effects.contains("UNKNOWN")) "OPEN"
    else "ESTABLISHED"
  // join across alternatives (existential): ESTABLISHED > OPEN > BROKEN > NO_FLOW
  def joinExistential(outcomes: Seq[String]): String =
    if (outcomes.contains("ESTABLISHED")) "ESTABLISHED"
    else if (outcomes.contains("OPEN")) "OPEN"
    else if (outcomes.contains("BROKEN")) "BROKEN"
    else "NO_FLOW"

  // SINK SETS: baseline (literal) vs framework (new). Restricted to files matching fileFilter
  // for batching, and (for the expensive framework set) sources are paired PER SINK FILE only --
  // this matches the realistic case (a handler reads its own params and returns success/failure
  // in the same function) and avoids an O(sinks x all-sources) global sweep.
  val literalSinks = cpg.call.name("stringify").filter(_.file.name.headOption.exists(_.matches(fileFilter))).l
  val frameworkSinks = cpg.call.name("success", "failure")
    .code(".*API\\.v[0-9]+\\.(success|failure)\\(.*")
    .filter(_.file.name.headOption.exists(_.matches(fileFilter))).l
  val allSources = cpg.call.name("<operator>.fieldAccess")
    .code("this\\.(bodyParams|queryParams|urlParams)(\\..*)?").l

  System.err.println(s"[$fileFilter] literal sinks=${literalSinks.size} framework sinks=${frameworkSinks.size}")

  val w = new java.io.PrintWriter(new java.io.File(s"$outDir/framework_sink_audit_${fileFilter.hashCode}.tsv"), "UTF-8")
  w.println(Seq("sink_kind","sink_id","sink_line","sink_file","sink_code","n_flows","outcome").mkString("\t"))

  def audit(sinks: List[nodes.Call], kind: String) = {
    sinks.foreach { sk =>
      val sinkFile = sk.file.name.headOption.getOrElse("?")
      val sameFileSources = allSources.filter(_.file.name.headOption.contains(sinkFile))
      val flows = if (sameFileSources.isEmpty) Nil else
        cpg.all.id(sk.id).collectAll[nodes.Expression]
          .reachableByFlows(sameFileSources.iterator.map(n => n: nodes.Expression)).l.take(20)
      val outcome = if (flows.isEmpty) "NO_FLOW" else {
        val entered = flows.flatMap(_.elements.collect { case p: nodes.MethodParameterIn => p.method.name }).toSet
        val perPath = flows.map { f =>
          val effects = f.elements.sliding(2).collect {
            case Seq(a, b) => propEffect(structural(a, b, sk.id.toString, entered), a, b)
          }.toSeq
          pathOutcome(effects)
        }
        joinExistential(perPath)
      }
      val file = sk.file.name.headOption.getOrElse("?").split("/").takeRight(2).mkString("/")
      w.println(Seq(kind, sk.id, sk.lineNumber.getOrElse(0), file,
                    sk.code.replace("\t"," ").replace("\n"," ").take(60), flows.size, outcome).mkString("\t"))
      w.flush()
    }
  }
  audit(literalSinks, "LITERAL_STRINGIFY")
  audit(frameworkSinks, "FRAMEWORK_SUCCESS_FAILURE")
  w.close()
  System.err.println(s"FRAMEWORK_SINK_AUDIT_COMPLETE[$fileFilter] -> $outDir/framework_sink_audit_${fileFilter.hashCode}.tsv")
}
