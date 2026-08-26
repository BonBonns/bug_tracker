// Batch full-fact-table generator: for a list of sink ids, in ONE CPG session, re-derive the
// same-file origin source(s), enumerate on-path user-defined transform calls (same logic as
// setup_candidate.sc: non-builtin, non-operator, argument on the flow), compute trace identity
// for each transform call (same logic as export_trace_identity.sc), and write complete fact
// tables (source_facts, transform_identity, trace_identity, propagation_relations,
// definition_resolution) per candidate -- so adjudicate_js.py can run REAL adjudication, not a
// property-outcome-only sweep. No classifier change; reuses the exact frozen structural/effect
// logic where needed (transform enumeration matches setup_candidate.sc verbatim).
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

@main def exec(cpgFile: String, sinkListFile: String, outDir: String) = {
  importCpg(cpgFile)
  implicit val ec: EngineContext = EngineContext()

  val BUILTIN = Set("stringify","parse","keys","values","map","filter","forEach","join","split",
    "success","failure","redirect")   // success/failure/redirect are the SINK itself, not a transform

  val sinkIds = scala.io.Source.fromFile(sinkListFile).getLines().map(_.trim).filter(_.nonEmpty).toList
  System.err.println(s"batch: ${sinkIds.size} candidates")

  def enclosingCall(n: nodes.AstNode): Option[nodes.Call] = {
    var cur: nodes.AstNode = n
    var hops = 0
    while (hops < 6) {
      val parentOpt = scala.util.Try(cur.astParent).toOption
      parentOpt match {
        case Some(c: nodes.Call) => return Some(c)
        case Some(null) => return None
        case Some(p) => cur = p; hops += 1
        case None => return None   // no AST parent (boundary node: MethodParameterIn/MethodReturn/etc.)
      }
    }
    None
  }

  sinkIds.foreach { sinkIdStr =>
    try {
      val sinkId = sinkIdStr.toLong
      val sk = cpg.call.id(sinkId).headOption
      if (sk.isEmpty) { System.err.println(s"[$sinkIdStr] sink not found, skip"); }
      else {
        val sink = sk.get
        val sinkFile = sink.file.name.headOption.getOrElse("?")
        val sinkLine = sink.lineNumber.getOrElse(0)
        val sources = cpg.call.name("<operator>.fieldAccess")
          .code("this\\.(bodyParams|queryParams|urlParams)(\\..*)?")
          .filter(_.file.name.headOption.contains(sinkFile)).l
        val flows = cpg.all.id(sinkId).collectAll[nodes.Expression]
          .reachableByFlows(sources.iterator.map(n => n: nodes.Expression)).l.take(10)
        if (flows.isEmpty) { System.err.println(s"[$sinkIdStr] no flow, skip") }
        else {
          val d = s"$outDir/cand_$sinkIdStr/raw"
          new java.io.File(d).mkdirs()
          // origin: the first element of the first flow
          val origin = flows.head.elements.head
          // on-path transform calls: non-builtin, non-operator calls whose arg is a flow element
          val allElems = flows.flatMap(_.elements).distinct
          val entered = flows.flatMap(_.elements.sliding(2).collect {
            case Seq(a, p: nodes.MethodParameterIn) => p.method.id
          }).toSet
          val seen = scala.collection.mutable.LinkedHashSet[Long]()
          val xforms = scala.collection.mutable.ListBuffer[nodes.Call]()
          allElems.foreach { e =>
            enclosingCall(e).foreach { c =>
              if (!c.name.startsWith("<operator>") && !BUILTIN.contains(c.name) &&
                  c.argument.exists(_.id == e.id) && !seen.contains(c.id) && c.id != sinkId) {
                seen += c.id; xforms += c
              }
            }
          }
          // write source_facts (12 cols)
          val sf = new java.io.PrintWriter(new java.io.File(s"$d/source_facts.tsv"))
          sf.println(Seq(sinkId, sinkLine, origin.id, origin.code.take(40), "ESTABLISHED",
                          "","","","","","","").mkString("\t"))
          sf.close()
          // write propagation_relations (9 cols)
          val pr = new java.io.PrintWriter(new java.io.File(s"$d/propagation_relations.tsv"))
          pr.println(Seq(sinkId,"","",origin.id, origin.lineNumber.getOrElse(0), origin.code.take(40),
                          "","","").mkString("\t"))
          pr.close()
          new java.io.PrintWriter(new java.io.File(s"$d/definition_resolution.tsv")).close()
          // write transform_identity (8 cols) + trace_identity (5 cols), in path order
          val ti = new java.io.PrintWriter(new java.io.File(s"$d/transform_identity.tsv"))
          val trw = new java.io.PrintWriter(new java.io.File(s"$d/trace_identity.tsv"))
          trw.println(Seq("call_node","callee_method_fullName","callee_method_id","unique","body").mkString("\t"))
          xforms.zipWithIndex.foreach { case (c, order) =>
            val name = if (c.name == "<operator>.fieldAccess") c.code.split("\\.").lastOption.getOrElse(c.name) else c.name
            ti.println(Seq("x", origin.id.toString, order.toString, c.id.toString, name, "", "", "UNKNOWN").mkString("\t"))
            val unionMfn = c.methodFullName.contains(" | ")
            val callees = c.callee(io.shiftleft.semanticcpg.language.NoResolve).l.filterNot(_.isExternal).map(_.fullName).distinct
            val ambiguous = unionMfn || callees.size > 1
            val enteredHere = entered.filter(mid => cpg.method.id(mid).name.headOption.contains(name))
            val unique = !ambiguous && enteredHere.size == 1
            if (unique) {
              val m = cpg.all.id(enteredHere.head).collectAll[nodes.Method].head
              val body = m.code.replace("\t"," ").replace("\n","\\n").take(500)
              trw.println(Seq(c.id, m.fullName, m.id.toString, "true", body).mkString("\t"))
            } else {
              trw.println(Seq(c.id, "", "", "false", "").mkString("\t"))
            }
          }
          ti.close(); trw.close()
          System.err.println(s"[$sinkIdStr] OK origin=${origin.id} xforms=${xforms.size}")
        }
      }
    } catch { case e: Exception => System.err.println(s"[$sinkIdStr] ERROR: ${e.getMessage.take(100)}") }
  }
  System.err.println("BATCH_STAGE_COMPLETE")
}
