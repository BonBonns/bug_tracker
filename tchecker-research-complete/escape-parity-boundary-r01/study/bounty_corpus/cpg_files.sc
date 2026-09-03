// Dump every FILE node name in the CPG, one per line, plus a summary count.
// Coverage is then measured as a set intersection against the frozen manifest
// rather than as a ratio between two independently-defined counts.
@main def exec(cpgFile: String, outFile: String) = {
  importCpg(cpgFile)
  val names = cpg.file.name.l
  java.nio.file.Files.write(java.nio.file.Paths.get(outFile),
    names.mkString("\n").getBytes("UTF-8"))
  println(s"CPGCHECK files=${names.size} methods=${cpg.method.size} calls=${cpg.call.size} literals=${cpg.literal.size}")
}
