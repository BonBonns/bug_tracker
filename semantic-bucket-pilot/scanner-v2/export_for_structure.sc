// Export FOR control-structure AST membership for capability 3, as a SEPARATE analysis on
// the CPG (does NOT modify the frozen exporter or the producers' cpp.json). For each FOR
// loop, emits the CPG node ids in its condition / update / body AST subtrees. C for-loop
// AST child order: 1=init, 2=condition, 3=update, 4=body. Node ids share the cpp.json id
// space (same CPG), so capability 3 can prove that an increment node is in a FOR's UPDATE
// component and that member-write nodes are in that same FOR's BODY -- structural proof,
// not source-line coincidence.
@main def exec(cpgFile: String, outFile: String) = {
  importCpg(cpgFile)
  val rows = scala.collection.mutable.ArrayBuffer[String]()
  cpg.method.l.foreach { m =>
    m.ast.isControlStructure.l.filter(_.controlStructureType == "FOR").foreach { cs =>
      val ch = cs.astChildren.l
      def ids(o: Int): List[Long] = ch.filter(_.order == o).flatMap(_.ast.id.l).distinct
      val cond = ids(2); val upd = ids(3); val body = ids(4)
      val mn = m.name.replace("\\", "\\\\").replace("\"", "\\\"")
      rows += s"""{"method":"$mn","for_id":${cs.id},"cond":[${cond.mkString(",")}],"update":[${upd.mkString(",")}],"body":[${body.mkString(",")}]}"""
    }
  }
  val out = rows.mkString("[", ",", "]")
  java.nio.file.Files.write(java.nio.file.Paths.get(outFile), out.getBytes)
  println(s"wrote ${rows.size} FOR loops -> $outFile")
}
