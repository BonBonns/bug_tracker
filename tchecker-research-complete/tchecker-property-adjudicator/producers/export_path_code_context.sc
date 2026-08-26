// JS-PROV-PATHCODE — path code-context extractor.
// Attaches ACTUAL code to nodes whose identities the fact layer already established
// (source node, path-step call nodes, sink node). Look-up is by NODE ID only; no code is
// located by name. Emits, per node: exact code, containing statement, containing function.
// Definition bodies are NOT produced here (they come from the frozen definition resolver);
// this producer covers callsite/source/sink context only.
//
// path_code_context.tsv: node_id, role(SOURCE|STEP|SINK), code, containing_statement,
//                        containing_function
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import scala.io.Source

@main def exec(cpgFile: String, rawDir: String) = {
  importCpg(cpgFile)
  def cl(s: String) = Option(s).getOrElse("").replace("\t", " ").replace("\n", " ").take(220)
  def rd(f: String): List[Array[String]] = {
    val p = new java.io.File(s"$rawDir/$f")
    if (p.exists) { val s = Source.fromFile(p); try s.getLines().map(_.split("\t", -1)).toList finally s.close() } else Nil
  }
  // node ids + roles from the established fact layer (never invented here)
  val srcf = rd("source_facts.tsv").filter(r => r.length >= 6 && r(4) == "ESTABLISHED")
  // The production property producers and adjudicator use transform_identity.tsv.
  // Preserve the historical path_transform_identity.tsv fallback, but never require
  // operators to rename the canonical fact table just to obtain code context.
  val canonicalTid = rd("transform_identity.tsv").filter(_.length >= 8)
  val tid = if (canonicalTid.nonEmpty) canonicalTid
            else rd("path_transform_identity.tsv").filter(_.length >= 8)
  val roles = scala.collection.mutable.LinkedHashMap[String, String]()
  srcf.foreach { r => roles(r(2)) = "SOURCE"; roles(r(0)) = "SINK" }
  tid.foreach { r => roles.getOrElseUpdate(r(3), "STEP") }

  def enclosingStatement(n: nodes.AstNode): String = {
    var cur = n; var g = 0
    while (cur.astParent != null && !cur.astParent.isInstanceOf[nodes.Block]
           && !cur.astParent.isInstanceOf[nodes.Method] && g < 60) { cur = cur.astParent; g += 1 }
    cur.code
  }
  def enclosingFunction(n: nodes.AstNode): String = {
    var cur: nodes.AstNode = n; var g = 0
    while (cur != null && !cur.isInstanceOf[nodes.Method] && g < 200) { cur = cur.astParent; g += 1 }
    if (cur != null && cur.isInstanceOf[nodes.Method]) cur.asInstanceOf[nodes.Method].fullName else ""
  }

  val w = new java.io.PrintWriter(new java.io.File(s"$rawDir/path_code_context.tsv"), "UTF-8")
  roles.foreach { case (idStr, role) =>
    cpg.all.id(idStr.toLong).collectAll[nodes.AstNode].foreach { n =>
      w.println(Seq(idStr, role, cl(n.code), cl(enclosingStatement(n)), cl(enclosingFunction(n))).mkString("\t"))
    }
  }
  w.close()
  println(s"PATH_CODE_CONTEXT_COMPLETE: $rawDir/path_code_context.tsv (${roles.size} nodes)")
}
