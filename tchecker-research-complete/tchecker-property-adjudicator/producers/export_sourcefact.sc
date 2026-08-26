// JS-PROV-SRC — production SourceFact producer.
//
// Hierarchy:  ESTABLISHED provenance origin  >  lexical detector hint  >  UNKNOWN
//
//   * PROVENANCE (authoritative): the analyzer's dataflow engine establishes that
//     the value at the sink ORIGINATES at a specific node (root of an established
//     reachableByFlows path, following interprocedural/alias hops). Recorded as
//     established_by=STATIC_PROVENANCE, status=ESTABLISHED.
//   * LEXICAL_HINT (weaker): a request-shaped node the detector recognizes. It is
//     NEVER promoted to an authoritative source; it is preserved separately. If it
//     does not lie on an established flow to the sink, the authoritative origin
//     stays UNKNOWN.
//   * Provenance NEVER loses to a lexical hint. If they disagree, provenance wins
//     and the disagreement is recorded.
//   * Join to propagation is by STABLE CPG node id, never code strings.
//
// Emits source_facts.tsv:
//   sink_node, sink_line, source_node, origin_family, status(ESTABLISHED|UNKNOWN),
//   established_by(STATIC_PROVENANCE|LEXICAL_HINT|NONE), qualification, provenance,
//   lexical_hint_node, disagreement, multi_origin(true|false), origin_count
import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  implicit val ec: EngineContext = EngineContext()
  def cl(s: String) = Option(s).getOrElse("").replace("\n", " ").replace("\t", " ").take(60)
  def lnOf(n: nodes.StoredNode) = n match { case c: nodes.CfgNode => c.lineNumber.map(_.toString).getOrElse(""); case _ => "" }
  def codeOf(n: nodes.StoredNode) = n match { case a: nodes.AstNode => Option(a.code).getOrElse(""); case _ => "" }
  val w = new java.io.PrintWriter(new java.io.File(s"$outDir/source_facts.tsv"), "UTF-8")

  // external-input recognition (used ONLY to (a) seed provenance candidates and
  // (b) record lexical hints). Recognition alone never establishes a source.
  def isReq(code: String) = code.matches("""(?s).*\breq(uest)?\.(body|payload|query|params)\b.*""")
  def originFamily(code: String) =
    if (code.matches("""(?s).*\.(body|payload)\b.*""")) "HTTP_BODY"
    else if (code.matches("""(?s).*\.query\b.*""")) "HTTP_QUERY"
    else if (code.matches("""(?s).*\.params\b.*""")) "HTTP_PARAMS"
    else "HTTP_INPUT"

  def reqNodes = cpg.call.name("<operator>.fieldAccess").filter(c => isReq(c.code))
  def sinkArgs = cpg.call.name("stringify").argument.argumentIndex(1)
  val sinkCallByArg = cpg.call.name("stringify").l.flatMap(c => c.argument.argumentIndex(1).l.map(a => a.id -> c)).toMap

  try {
    val flows = sinkArgs.reachableByFlows(reqNodes).l
    val bySink = flows.groupBy(_.elements.last.id)

    sinkArgs.l.foreach { snkArg =>
      val sinkCall = sinkCallByArg.get(snkArg.id)
      val sinkNode = sinkCall.map(_.id).getOrElse(snkArg.id)
      val sinkLine = sinkCall.map(lnOf).getOrElse(lnOf(snkArg))

      // ALL distinct provenance-established origin roots for this sink (multiple
      // reaching definitions -> multiple origins; do NOT collapse to one).
      val provRoots: List[nodes.StoredNode] =
        bySink.get(snkArg.id).map(_.map(_.elements.head).distinctBy(_.id)).getOrElse(Nil)
      val rootIds = provRoots.map(_.id).toSet

      // ALL recognized request nodes in the sink's method (not just the first)
      val reqInMethod: List[nodes.Call] =
        sinkCall.map(sc => sc.method.ast.isCall.filter(c => isReq(c.code) && c.name == "<operator>.fieldAccess").l).getOrElse(Nil)
      // lexical-hint-only nodes = recognized req nodes NOT among the established roots
      val hintOnly = reqInMethod.filter(c => !rootIds.contains(c.id)).distinctBy(_.id)

      provRoots match {
        case Nil =>
          if (hintOnly.nonEmpty)
            hintOnly.foreach { hint =>
              w.println(Seq(sinkNode.toString, sinkLine, "", "", "UNKNOWN", "LEXICAL_HINT",
                "recognized-not-established", "detector lexical recognition (weaker)",
                hint.id.toString, "false", "false", "0").mkString("\t"))
            }
          else
            w.println(Seq(sinkNode.toString, sinkLine, "", "", "UNKNOWN", "NONE",
              "no-source", "neither provenance nor lexical", "", "false", "false", "0").mkString("\t"))
        case roots =>
          val multi = roots.size > 1
          val disagree = hintOnly.nonEmpty   // provenance established X; lexical also recognized a node it did NOT establish
          // one row per ESTABLISHED origin (shared multi flag + count)
          roots.foreach { root =>
            w.println(Seq(sinkNode.toString, sinkLine, root.id.toString,
              originFamily(codeOf(root)), "ESTABLISHED", "STATIC_PROVENANCE",
              (if (multi) "multi-origin (ambiguous reaching defs)" else "origin-of-flow (dataflow-established)"),
              "oss_dataflow.reachableByFlows root",
              hintOnly.headOption.map(_.id.toString).getOrElse(""), disagree.toString,
              multi.toString, roots.size.toString).mkString("\t"))
          }
          // AND one row per recognized req node that is NOT established (weaker,
          // preserved separately -- control #3). Never promoted.
          hintOnly.foreach { hint =>
            w.println(Seq(sinkNode.toString, sinkLine, "", "", "UNKNOWN", "LEXICAL_HINT",
              "recognized-not-established (coexists with established origin)",
              "detector lexical recognition (weaker)",
              hint.id.toString, "false", "false", roots.size.toString).mkString("\t"))
          }
      }
    }
  } finally w.close()
  println(s"SOURCE_FACTS_COMPLETE: $outDir")
}
