import io.shiftleft.semanticcpg.language._
@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("===FCC_FILES_BEGIN===")
  cpg.file.name.l.sorted.foreach(f => println(s"FCC_FILE|$f"))
  println("===FCC_FILES_END===")
}
