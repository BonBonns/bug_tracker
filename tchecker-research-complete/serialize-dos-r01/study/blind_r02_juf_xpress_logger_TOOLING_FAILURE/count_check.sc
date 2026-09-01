@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println(s"METHOD_COUNT=${cpg.method.size}")
  println(s"CALL_COUNT=${cpg.call.size}")
  println(s"FILE_COUNT=${cpg.file.size}")
  cpg.file.name.l.foreach(f => println(s"FILE: $f"))
}
