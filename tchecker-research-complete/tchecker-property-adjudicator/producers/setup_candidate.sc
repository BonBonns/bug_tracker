// setup_candidate.sc — generic front-door for the serialize-DoS pipeline.
// Given a CPG and a source pattern (e.g. "req.body"), finds the JSON.stringify sink, the source,
// and the user-defined transform calls on the source->sink flow, and writes the fact tables the
// property-propagation / trace-identity producers and the adjudicator consume.
//
// Usage: joern --script setup_candidate.sc --param cpgFile=<cpg> --param rawDir=<dir> --param srcPattern="req.body"
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

  val sinkOpt = cpg.call.name("stringify").headOption
  val srcOpt  = cpg.call.codeExact(srcPattern).headOption
    .orElse(cpg.call.code(".*" + java.util.regex.Pattern.quote(srcPattern) + ".*").headOption)
  (sinkOpt, srcOpt) match {
    case (Some(sk), Some(sc)) =>
      val sinkLine = sk.lineNumber.map(_.toString).getOrElse("0")
      val srcLine  = sc.lineNumber.map(_.toString).getOrElse("0")
      // source_facts (12 cols): sink, sink_line, source, source_code, status, +7 pad
      val sf = new java.io.PrintWriter(new java.io.File(s"$rawDir/source_facts.tsv"), "UTF-8")
      sf.println((Seq(sk.id, sinkLine, sc.id, srcPattern, "ESTABLISHED") ++ Seq.fill(7)("")).mkString("\t")); sf.close()
      // propagation_relations (9 cols): sink,_,_,source,src_line,src_code,_,_,_
      val pr = new java.io.PrintWriter(new java.io.File(s"$rawDir/propagation_relations.tsv"), "UTF-8")
      pr.println(Seq(sk.id, "", "", sc.id, srcLine, srcPattern, "", "", "").mkString("\t")); pr.close()
      // transforms: user-defined, non-builtin, non-operator calls whose argument is on the flow
      def enclosingCall(n: nodes.AstNode): Option[nodes.Call] = {
        var cur: nodes.AstNode = n; var out: Option[nodes.Call] = None; var i = 0
        while (out.isEmpty && cur != null && i < 6) {
          cur match { case c: nodes.Call if !c.name.startsWith("<operator>") => out = Some(c); case _ => }
          cur = cur.astParent; i += 1
        }
        out
      }
      val flow = cpg.all.id(sk.id).collectAll[nodes.Expression]
                   .reachableByFlows(cpg.all.id(sc.id).collectAll[nodes.Expression]).headOption
      val seen = scala.collection.mutable.LinkedHashSet[String]()
      val ti = new java.io.PrintWriter(new java.io.File(s"$rawDir/transform_identity.tsv"), "UTF-8")
      var order = 0
      flow.foreach { f =>
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
      ti.close()
      // definition_resolution left empty (import-based resolver adds rows when it resolves imports)
      new java.io.PrintWriter(new java.io.File(s"$rawDir/definition_resolution.tsv"), "UTF-8").close()
      println(s"SETUP_CANDIDATE ok: sink=${sk.id} source=${sc.id} transforms=$order")
    case _ =>
      println(s"SETUP_CANDIDATE fail: sink=${sinkOpt.isDefined} source=${srcOpt.isDefined} (pattern=$srcPattern)")
  }
}
