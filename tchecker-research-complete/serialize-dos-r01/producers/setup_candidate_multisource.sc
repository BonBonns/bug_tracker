// setup_candidate_multisource.sc — SERIALIZE-DOS-R03 source-occurrence correction.
//
// NEW producer revision. Does NOT modify the frozen
// tchecker-property-adjudicator/producers/setup_candidate.sc, which is preserved
// byte-for-byte and remains runnable exactly as before.
//
// THE BUG THIS FIXES
// -------------------
// setup_candidate.sc selects the sink via `cpg.call.name("stringify").headOption` and
// the source via `cpg.call.codeExact(srcPattern).headOption` -- both single, arbitrary
// "first" picks in whatever order Joern's own traversal happens to return. When the
// same source pattern's text appears more than once on the candidate's real flow (e.g.
// once as a ternary's CONDITION and again, separately, as the argument actually passed
// to the sink), `.headOption` can pick the non-flowing occurrence, producing a false
// `NO_FLOW` even though a real flow exists from a DIFFERENT occurrence of the
// identical text. Confirmed on the real `@8crafter/leveldb-zlib`... no -- confirmed on
// the real `motifer@26.1.1` package: see
// serialize-dos-r01/study/blind_motifer_review/MOTIFER_MANUAL_REVIEW.md Sec.3 for the
// full, independently-verified diagnosis (a standalone script using the SAME
// `reachableByFlows` API this file uses, run without editing any frozen analyzer,
// showed the argument's own `req.body` occurrence -- not the ternary condition's --
// is the one with a real flow, and it is id-identical to the sink's own argument).
//
// THE FIX
// -------
// Enumerate EVERY matching sink call and EVERY matching source occurrence -- never
// `.headOption` on either side. Compute a real Joern dataflow (`reachableByFlows`) for
// EVERY (sink, source) pair in that complete cross-product. Never guess, never rank,
// never pick a "most likely" pair -- the dataflow engine itself decides which pairs
// have a real flow.
//
// TWO OUTPUT LAYERS
// ------------------
// 1. LEGACY-COMPATIBLE (same schema as setup_candidate.sc's own output; unchanged
//    downstream): source_facts.tsv / propagation_relations.tsv / transform_identity.tsv
//    get ONE ROW PER (sink, source) PAIR THAT HAS A REAL FLOW (flows.nonEmpty) --
//    never a "first occurrence" row, and never a row for a pair with zero flows (a
//    pair that never flows contributes nothing to any finding either way; filtering it
//    here, using the SAME reachableByFlows call this file already needs for
//    multisource_evidence.tsv below, avoids a redundant second computation
//    downstream). This means the FROZEN export_property_propagation.sc,
//    export_trace_identity.sc, and adjudicate_js.py run COMPLETELY UNMODIFIED on this
//    output: export_property_propagation.sc already loops over every DISTINCT
//    (sink, source) row (never assumed to be exactly one), and adjudicate_js.py's own
//    documented "multi-origin existential join" already combines multiple surviving
//    sources per sink into one disposition -- this producer's only job is to stop
//    silently starving that existing machinery of the occurrences setup_candidate.sc's
//    `.headOption` would have dropped.
// 2. NEW, node-identity-preserving evidence (this producer's own contribution, not
//    replicated anywhere else): multisource_evidence.tsv -- one row per (sink, source)
//    pair CONSIDERED (both flowing and non-flowing), keyed by each side's real Joern
//    node id, never merging two distinct source (or sink) node ids into one record
//    even when their `.code` text is byte-identical. Deduplication happens only at the
//    FINDING level (per sink -- see adjudicate_js.py's own per-sink, multi-origin
//    join, invoked once per distinct sink id present in source_facts.tsv), never at
//    the evidence level: every occurrence this file considered remains individually
//    inspectable here.
//
// multisource_evidence.tsv (7 cols): sink_id, sink_line, source_id, source_line,
//                                     source_code, has_flow, flow_count
//
// Usage: joern --script setup_candidate_multisource.sc --param cpgFile=<cpg>
//        --param rawDir=<dir> --param srcPattern="req.body"
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

@main def exec(cpgFile: String, rawDir: String, srcPattern: String) = {
  importCpg(cpgFile)
  implicit val ec: EngineContext = EngineContext()
  new java.io.File(rawDir).mkdirs()
  val BUILTIN = Set("stringify","parse","keys","values","map","filter","forEach","join","split",
    "push","test","then","catch","from","update","digest","toString","hex")

  // EVERY matching sink -- never .headOption.
  val sinks = cpg.call.name("stringify").l
  // EVERY matching source occurrence -- never .headOption. Same fallback precedence as
  // setup_candidate.sc (exact match preferred; substring match only when there is no
  // exact match at all), but now ALL matches at whichever precedence level fires, not
  // just the first.
  val exactSrcs = cpg.call.codeExact(srcPattern).l
  val srcs = if (exactSrcs.nonEmpty) exactSrcs
             else cpg.call.code(".*" + java.util.regex.Pattern.quote(srcPattern) + ".*").l

  if (sinks.isEmpty || srcs.isEmpty) {
    println(s"SETUP_CANDIDATE_MULTISOURCE fail: sinks=${sinks.size} sources=${srcs.size} (pattern=$srcPattern)")
  } else {
    def enclosingCall(n: nodes.AstNode): Option[nodes.Call] = {
      var cur: nodes.AstNode = n; var out: Option[nodes.Call] = None; var i = 0
      while (out.isEmpty && cur != null && i < 6) {
        cur match { case c: nodes.Call if !c.name.startsWith("<operator>") => out = Some(c); case _ => }
        cur = cur.astParent; i += 1
      }
      out
    }

    val sf = new java.io.PrintWriter(new java.io.File(s"$rawDir/source_facts.tsv"), "UTF-8")
    val pr = new java.io.PrintWriter(new java.io.File(s"$rawDir/propagation_relations.tsv"), "UTF-8")
    val ti = new java.io.PrintWriter(new java.io.File(s"$rawDir/transform_identity.tsv"), "UTF-8")
    val me = new java.io.PrintWriter(new java.io.File(s"$rawDir/multisource_evidence.tsv"), "UTF-8")

    var flowingPairs = 0
    for (sk <- sinks; sc <- srcs) {
      val sinkLine = sk.lineNumber.map(_.toString).getOrElse("0")
      val srcLine = sc.lineNumber.map(_.toString).getOrElse("0")
      val flows = cpg.all.id(sk.id).collectAll[nodes.Expression]
                    .reachableByFlows(cpg.all.id(sc.id).collectAll[nodes.Expression]).l
      val hasFlow = flows.nonEmpty
      me.println(Seq(sk.id.toString, sinkLine, sc.id.toString, srcLine, srcPattern,
        hasFlow.toString, flows.size.toString).mkString("\t"))

      if (hasFlow) {
        flowingPairs += 1
        // source_facts (12 cols): sink, sink_line, source, source_code, status, +7 pad --
        // SAME schema as setup_candidate.sc; status is the same static "ESTABLISHED"
        // placeholder that file always wrote (the REAL disposition is computed
        // downstream, unchanged, by export_property_propagation.sc's own
        // reachableByFlows check on this exact pair).
        sf.println((Seq(sk.id, sinkLine, sc.id, srcPattern, "ESTABLISHED") ++ Seq.fill(7)("")).mkString("\t"))
        // propagation_relations (9 cols): sink,_,_,source,src_line,src_code,_,_,_
        pr.println(Seq(sk.id, "", "", sc.id, srcLine, srcPattern, "", "", "").mkString("\t"))
        // transforms on this pair's own flow, scoped to this source id (same shape as
        // setup_candidate.sc, generalized to run once per surviving pair instead of once
        // globally).
        val seen = scala.collection.mutable.LinkedHashSet[String]()
        var order = 0
        flows.headOption.foreach { f =>
          f.elements.foreach { e =>
            enclosingCall(e).foreach { c =>
              if (!BUILTIN.contains(c.name) && c.argument.exists(_.id == e.id) && !seen.contains(c.id.toString)) {
                seen += c.id.toString
                ti.println(Seq("x", sc.id.toString, order.toString, c.id.toString, c.name, "", "", "UNKNOWN").mkString("\t"))
                order += 1
              }
            }
          }
        }
      }
    }
    sf.close(); pr.close(); ti.close(); me.close()
    // definition_resolution left empty (import-based resolver adds rows when it resolves imports) --
    // same as setup_candidate.sc.
    new java.io.PrintWriter(new java.io.File(s"$rawDir/definition_resolution.tsv"), "UTF-8").close()

    val sinkIds = sinks.map(_.id).distinct
    println(s"SETUP_CANDIDATE_MULTISOURCE ok: sinks=${sinks.size} (distinct ids=${sinkIds.size}) " +
      s"sources=${srcs.size} pairs_considered=${sinks.size * srcs.size} pairs_with_flow=$flowingPairs")
    println(s"SETUP_CANDIDATE_MULTISOURCE sink_ids=${sinkIds.mkString(",")}")
  }
}
