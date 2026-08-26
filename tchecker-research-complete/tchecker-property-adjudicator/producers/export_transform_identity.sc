// JS-PROV-XFID — per-origin transform identity, fact-backed.
// For each established (source -> sink) pair, attribute the ordered transform chain to
// THAT origin by ARGUMENT DATA-DEPENDENCE (the source value flows into the transform's
// argument) -- a stable structural relation, never code text / name string / source line.
// Each transform's identity is resolved via the R14/R23b import bindings (cpg.imports):
// callee -> imported member @ module specifier. If unresolved -> UNKNOWN (abstain).
//
// transform_identity.tsv:
//   sink_node, source_node, order, transform_call_node, callee_name,
//   module_spec, member, identity_status(ESTABLISHED|UNKNOWN)
import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  implicit val ec: EngineContext = EngineContext()
  def cl(s: String) = Option(s).getOrElse("").replace("\n", " ").replace("\t", " ").take(80)
  def ln(n: nodes.AstNode) = n.lineNumber.map(_.toString).getOrElse("")
  val w = new java.io.PrintWriter(new java.io.File(s"$outDir/transform_identity.tsv"), "UTF-8")

  // fact-backed binding table: local-as -> (module spec, member), from imports (R23b/R14)
  case class Bind(spec: String, member: String)
  val binds = scala.collection.mutable.Map[String, Bind]()
  cpg.imports.l.foreach { i =>
    val spec = i.importedEntity.getOrElse("")
    val member = i.importedAs.getOrElse("")
    if (member.nonEmpty) binds(member) = Bind(spec, if (member.nonEmpty) member else "")
  }
  // require-member form `const {x} = require(spec)` also lands in imports on this frontend;
  // fall back to require_bindings if present is not needed here.

  def srcSeeds = cpg.call.name("<operator>.fieldAccess")
    .filter(_.code.matches("""(?s).*\breq(uest)?\.(body|payload|query|params)\b.*"""))

  try {
    val sinkCallByArg = cpg.call.name("stringify").l.flatMap { c =>
      c.argument.argumentIndex(1).l.map(a => a.id -> c) }.toMap
    def sinkArgs = cpg.call.name("stringify").argument.argumentIndex(1)
    val flows = sinkArgs.reachableByFlows(srcSeeds).l
    val bySinkArg = flows.groupBy(p => p.elements.last.id)

    sinkArgs.l.foreach { snkArg =>
      val sinkNode = sinkCallByArg.get(snkArg.id).map(_.id).getOrElse(snkArg.id)
      bySinkArg.getOrElse(snkArg.id, Nil).groupBy(_.elements.head.id).foreach { case (srcId, group) =>
        val source = group.head.elements.head
        val method = source.asInstanceOf[nodes.CfgNode].method
        // candidate transforms in the enclosing method (exclude operators + the sink)
        val candidates = method.ast.isCall.l.filter { c =>
          !c.name.startsWith("<operator>") && c.name != "stringify" && c.id != source.id
        }
        // a transform belongs to THIS origin iff the source value flows into its argument
        val onPath = candidates.filter { c =>
          c.argument.l.exists { arg => arg.reachableBy(source).nonEmpty || arg.id == source.id }
        }.sortBy(c => c.lineNumber.getOrElse(0))
        if (onPath.isEmpty) {
          w.println(Seq(sinkNode.toString, source.id.toString, "0", "", "",
            "", "", "UNKNOWN").mkString("\t"))
        } else onPath.zipWithIndex.foreach { case (c, i) =>
          val b = binds.get(c.name)
          val (spec, member, status) = b match {
            case Some(bd) => (bd.spec, bd.member, "ESTABLISHED")
            case None     => ("", "", "UNKNOWN")
          }
          w.println(Seq(sinkNode.toString, source.id.toString, i.toString, c.id.toString,
            cl(c.name), cl(spec), cl(member), status).mkString("\t"))
        }
      }
    }
  } finally w.close()
  println(s"TRANSFORM_IDENTITY_COMPLETE: $outDir")
}
