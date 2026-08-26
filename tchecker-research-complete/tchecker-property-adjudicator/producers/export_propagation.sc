// JS-PROV-PROP — production relation-preservation producer.
//
// Preserves the source -> transform(s) -> sink relationship that the analyzer's
// OWN dataflow engine (OSS dataflow / DDG, reachableByFlows) establishes. This is
// NOT the proof shim: no lexical code-string walk, no single-file assumption.
//
//   * relation established by data-dependence (reachableByFlows), not string match
//   * every node carries a STABLE CPG node id; code is display-only, never identity
//   * transform order is taken from the established flow
//   * interprocedural only where the dataflow engine resolves the hop; unresolved
//     hops are simply absent from the flow -> we ABSTAIN, never bridge
//   * every emitted relation carries provenance (the mechanism that established it)
//   * transform IDENTITY resolution is deferred to a join with the existing R-series
//     identity facts (require_bindings/import_bindings) -- this producer emits the
//     callee node id + name and does not re-derive identity (no logic duplication)
//
// Emits propagation_relations.tsv (one row per established or abstained sink):
//   sink_node, sink_line, status(ESTABLISHED|ABSTAINED), source_node, source_line,
//   source_code, transform_chain (order:callNode:callee ; ...), qualification,
//   provenance
//
// Gated: only the sink nodes handed in (here: JSON.stringify calls) are analyzed.
import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  implicit val ec: EngineContext = EngineContext()
  def cl(s: String) = Option(s).getOrElse("").replace("\n", " ").replace("\t", " ").take(80)
  def ln(n: nodes.StoredNode) = n match {
    case c: nodes.CfgNode => c.lineNumber.map(_.toString).getOrElse("")
    case _ => ""
  }
  val w = new java.io.PrintWriter(new java.io.File(s"$outDir/propagation_relations.tsv"), "UTF-8")

  // request-shaped source seed. NOTE: this endpoint is provisional — the SourceFact
  // hierarchy milestone replaces it with the provenance-engine origin. The RELATION
  // being productionized here (transform chain + order + identity join) is dataflow-
  // based regardless of how the source endpoint is chosen.
  //
  // 2026-08-24 FIX: hand-tracing server/fxa.js:39 (JSON.stringify({ token })) back to
  // its origin found middleware/auth.js:67 `req.header('Authorization')` -> token ->
  // fxa.verify(token) -> body: JSON.stringify({ token }) -- a real flow the seed
  // missed entirely, because req.header(...)/req.get(...) are CALLS, not the
  // <operator>.fieldAccess pattern the seed matched on. Added as a second source
  // class (call-shaped, not field-access-shaped) rather than folded into the same
  // regex, since header/get sources have a materially different node type.
  def srcsFieldAccess = cpg.call.name("<operator>.fieldAccess")
    .filter(_.code.matches("""(?s).*\breq(uest)?\.(body|payload|query|params)\b.*"""))
  def srcsHeaderCall = cpg.call.name("header", "get")
    .filter(_.code.matches("""(?s).*\breq(uest)?\.(header|get)\(.*"""))
  // 2026-08-24 FIX: server/routes/ws.js parses attacker-controlled WebSocket payloads
  // (`const fileInfo = JSON.parse(message)`) and several JSON.stringify sinks
  // downstream trace back to `message`, but no req.* source ever touches this file --
  // the seed had no source class for it at all. Scoped strictly to the parameter
  // actually bound as the callback of `.on('message', ...)`/`.once('message', ...)`
  // (via METHOD_REF -> referencedMethod), NOT a bare name match on "message" --
  // app/ui/okDialog.js also has an unrelated parameter named `message` (a dialog
  // string) that a name-only match would have wrongly pulled in as a source.
  def srcsWsMessage = cpg.call.name("on", "once")
    .filter(_.code.contains("'message'"))
    .argument.argumentIndex(2).isMethodRef.referencedMethod
    .parameter.filter(_.index == 1)
  def srcs = srcsFieldAccess ++ srcsHeaderCall ++ srcsWsMessage

  // gated sink set: JSON.stringify argument (the serialize class)
  def sinkArgs = cpg.call.name("stringify").argument.argumentIndex(1)

  try {
    // map each sink-arg node to the stringify call that owns it (for reporting)
    val sinkCallByArg = cpg.call.name("stringify").l.flatMap { c =>
      c.argument.argumentIndex(1).l.map(a => a.id -> c)
    }.toMap

    val flows = sinkArgs.reachableByFlows(srcs).l
    // group flows by their terminal (sink-arg) node id
    val bySink = flows.groupBy(p => p.elements.last.id)

    // ---- INTERPROCEDURAL REQUIRE-BRIDGE (2026-08-24, generalized to N hops) --
    // jssrc2cpg does not link CommonJS `require()` imports into call edges: a
    // call to an imported function resolves to a LOCAL EXTERNAL PHANTOM method
    // of the same name, not the real cross-file definition. reachableByFlows
    // therefore cannot step from a call argument into the real callee body, so
    // every cross-file source->sink path is missed (all sinks ABSTAINED even
    // when a real flow exists, e.g. report.js req.body.reason -> statReportEvent
    // -> amplitude.js JSON.stringify). This bridge stitches such paths by
    // repeatedly applying the same two-step hop:
    //   HOP-IN:  frontier -> call-argument(index k) of an unlinked call
    //   HOP-OUT: real-callee parameter(index k) becomes the new frontier
    // and checking after every hop whether the frontier already reaches a
    // gated sink directly. Originally single-hop only; generalized because
    // hand-tracing server/initScript.js found a real 3-hop chain
    // (req.params.id -> storage.metadata() -> routes().toString() -> layout()
    // -> initScript() -> JSON.stringify) that a single hop cannot reach.
    // Each origin's shortest chain to a given sink is kept (BFS: hop N only
    // extends nodes not already reached at an earlier hop).
    val realDefsByName: Map[String, List[nodes.Method]] =
      cpg.method.isExternal(false).l.groupBy(_.name)
    // require()-path guard (2026-08-24): pure name matching produces real false
    // positives -- hand-tracing found server/storage/s3.js's `this.s3.upload({...})`
    // (an AWS SDK call; the file only requires 'aws-sdk') was bridged to three
    // unrelated client-side functions also named `upload` in app/api.js,
    // app/fileSender.js, app/ui/archiveTile.js purely because the names matched.
    // This latent flaw predates this session's changes (the original single-hop
    // bridge used the same name-only match); it surfaced once multi-hop chaining
    // gave it more opportunities to fire. Fix: only accept a same-named candidate
    // if the CALLING file actually require()s a path whose basename matches the
    // candidate's file (verified against the legitimate case: report.js's
    // `require('../amplitude')` -> basename "amplitude" matches server/amplitude.js).
    def basenameNoExt(path: String): String =
      path.split("/").last.stripSuffix(".js").stripSuffix(".jsx")
    val requiredBasenamesByFile: Map[String, Set[String]] =
      cpg.call.name("require").argument.argumentIndex(1).isLiteral.l
        .groupBy(_.method.filename)
        .view.mapValues(_.map(lit => basenameNoExt(lit.code.stripPrefix("\"").stripSuffix("\"").stripPrefix("'").stripSuffix("'"))).toSet)
        .toMap
    def realDefsReachableFrom(callerFile: String, name: String): List[nodes.Method] = {
      val required = requiredBasenamesByFile.getOrElse(callerFile, Set.empty)
      realDefsByName.getOrElse(name, Nil).filter(rd => required.contains(basenameNoExt(rd.filename)))
    }
    // calls whose resolved callee is external (phantom) but a require()-reachable
    // real def exists (name match alone is no longer sufficient, see guard above)
    val unlinkedCalls = cpg.call.l.filter { c =>
      val calleeExternal = c.callee.isExternal(true).nonEmpty
      calleeExternal && realDefsReachableFrom(c.method.filename, c.name).nonEmpty
    }
    // sink-arg id -> list of (origin source node, ordered transform-call chain)
    val bridged = scala.collection.mutable.Map[Long, List[(nodes.AstNode, List[nodes.Call])]]()

    case class Tainted(origin: nodes.AstNode, chain: List[nodes.Call])
    val maxHops = 4
    // frontier: node id -> (node, provenance). A node already in the frontier
    // at an earlier hop is never re-added (BFS shortest-chain, avoids cycles).
    var frontier: Map[Long, (nodes.AstNode, Tainted)] =
      srcs.l.map(s => s.id -> (s -> Tainted(s, Nil))).toMap
    val everSeen = scala.collection.mutable.Set[Long](frontier.keySet.toSeq: _*)

    var hop = 0
    while (hop < maxHops && frontier.nonEmpty) {
      val frontierNodes = frontier.values.map(_._1).toList
      // does the current frontier already reach a gated sink directly?
      sinkArgs.reachableByFlows(frontierNodes.iterator).l.foreach { p =>
        val sinkArg = p.elements.last
        val reached = p.elements.head
        frontier.get(reached.id).foreach { case (_, t) =>
          bridged(sinkArg.id) = (t.origin, t.chain) :: bridged.getOrElse(sinkArg.id, Nil)
        }
      }
      // advance the frontier through every unlinked call it can reach
      val next = scala.collection.mutable.Map[Long, (nodes.AstNode, Tainted)]()
      unlinkedCalls.foreach { call =>
        val realDefs = realDefsReachableFrom(call.method.filename, call.name)
        if (realDefs.nonEmpty) {
          val h1 = call.argument.reachableByFlows(frontierNodes.iterator).l
          val byIdx: Map[Int, List[nodes.AstNode]] = h1.flatMap { p =>
            p.elements.last match {
              case e: nodes.Expression if e.argumentIndex > 0 =>
                Some(e.argumentIndex -> p.elements.head)
              case _ => None
            }
          }.groupBy(_._1).view.mapValues(_.map(_._2).distinct).toMap
          if (byIdx.nonEmpty) realDefs.foreach { rd =>
            byIdx.foreach { case (idx, reachedFrom) =>
              rd.parameter.filter(_.index == idx).foreach { param =>
                if (!everSeen.contains(param.id)) {
                  reachedFrom.foreach { rf =>
                    frontier.get(rf.id).foreach { case (_, t) =>
                      if (!next.contains(param.id)) {
                        next(param.id) = (param, Tainted(t.origin, t.chain :+ call))
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
      next.keySet.foreach(everSeen += _)
      frontier = next.toMap
      hop += 1
    }
    // ------------------------------------------------------------------------

    // every gated sink: ESTABLISHED if a flow exists, else ABSTAINED
    sinkArgs.l.foreach { snkArg =>
      val sinkCall = sinkCallByArg.get(snkArg.id)
      val sinkNode = sinkCall.map(_.id).getOrElse(snkArg.id)
      val sinkLine = sinkCall.map(c => ln(c)).getOrElse(ln(snkArg))
      val direct = bySink.get(snkArg.id)
      val viaBridge = bridged.get(snkArg.id)
      (direct, viaBridge) match {
        case (Some(ps), _) =>
          // one row PER DISTINCT ORIGIN root (multi reaching defs stay separate,
          // not merged); if several flows share a root, keep the shortest.
          ps.groupBy(_.elements.head.id).foreach { case (_, group) =>
            val p = group.minBy(_.elements.size)
            val els = p.elements
            val source = els.head
            val transforms = els.collect { case c: nodes.Call => c }.filter { c =>
              !c.name.startsWith("<operator>") && c.name != "stringify" &&
              c.id != source.id
            }.zipWithIndex.map { case (c, i) => s"$i:${c.id}:${cl(c.name)}" }
            w.println(Seq(
              sinkNode.toString, sinkLine, "ESTABLISHED",
              source.id.toString, ln(source), cl(source.code),
              transforms.mkString(" ; "),
              "ESTABLISHED_DATAFLOW(may; not proven necessary)",
              "oss_dataflow.reachableByFlows(DDG); identity via R14/R23b join"
            ).mkString("\t"))
          }
        case (None, Some(bridges)) =>
          // 2026-08-24 FIX: this branch was previously unreachable -- `bridged` was
          // computed above but never consulted here, so every cross-file path (the
          // exact case the bridge comment describes, e.g. report.js req.body.reason
          // -> statReportEvent -> amplitude.js JSON.stringify) fell through to
          // ABSTAINED even though the two-hop dataflow had already been established.
          bridges.groupBy(_._1.id).foreach { case (_, group) =>
            val (source, chain) = group.head
            val transforms = chain.zipWithIndex.map { case (c, i) => s"$i:${c.id}:${cl(c.name)}" }
            w.println(Seq(
              sinkNode.toString, sinkLine, "ESTABLISHED_INTERPROC",
              source.id.toString, ln(source), cl(source.code),
              transforms.mkString(" ; "),
              "ESTABLISHED_INTERPROC(may; via require-bridge, not proven necessary)",
              "oss_dataflow HOP1(source->call-arg) + HOP2(real-callee-param->sink); require() phantom-callee bridge"
            ).mkString("\t"))
          }
        case (None, None) =>
          w.println(Seq(
            sinkNode.toString, sinkLine, "ABSTAINED",
            "", "", "", "", "UNRESOLVED",
            "no data-dependence flow from a request source established (no bridge)"
          ).mkString("\t"))
      }
    }
  } finally w.close()
  println(s"PROP_RELATIONS_COMPLETE: $outDir")
}
