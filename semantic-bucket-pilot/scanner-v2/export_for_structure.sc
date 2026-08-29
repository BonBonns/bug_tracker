// Export FOR control-structure AST membership for capability 3, as a SEPARATE analysis on
// the CPG (does NOT modify the frozen exporter or the producers' cpp.json). For each FOR
// loop, emits the CPG node ids in its init / condition / update / body AST subtrees. C
// for-loop AST child order: 1=init, 2=condition, 3=update, 4=body. Node ids share the
// cpp.json id space (same CPG). Also emits a BINDING WITNESS -- the condition node's id and
// code -- so capability 3 can cryptographically verify that the cpp.json it reads was
// generated from THIS cpg.bin (node ids are only meaningful within one CPG generation).
@main def exec(cpgFile: String, outFile: String) = {
  importCpg(cpgFile)
  def esc(s: String): String = s.replace("\\", "\\\\").replace("\"", "\\\"")
    .replace("\n", " ").replace("\r", " ").replace("\t", " ")
  val rows = scala.collection.mutable.ArrayBuffer[String]()
  cpg.method.l.foreach { m =>
    m.ast.isControlStructure.l.filter(_.controlStructureType == "FOR").foreach { cs =>
      val ch = cs.astChildren.l
      def ids(o: Int): List[Long] = ch.filter(_.order == o).flatMap(_.ast.id.l).distinct
      val init = ids(1); val cond = ids(2); val upd = ids(3); val body = ids(4)
      val condNode = ch.filter(_.order == 2).headOption
      val wid = condNode.map(_.id).getOrElse(-1L)
      val wcode = condNode.map(n => esc(n.code)).getOrElse("")
      rows += s"""{"method":"${esc(m.name)}","for_id":${cs.id},"init":[${init.mkString(",")}],"cond":[${cond.mkString(",")}],"update":[${upd.mkString(",")}],"body":[${body.mkString(",")}],"witness_id":$wid,"witness_code":"$wcode"}"""
    }
  }
  val out = rows.mkString("[", ",", "]")
  java.nio.file.Files.write(java.nio.file.Paths.get(outFile), out.getBytes)
  println(s"wrote ${rows.size} FOR loops -> $outFile")
}
