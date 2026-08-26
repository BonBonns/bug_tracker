@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  cpg.call.filter(c => Set("<operator>.equals","<operator>.notEquals").contains(c.name)).l.foreach { c =>
    val as = c.argument.l.sortBy(_.argumentIndex)
    if (as.size==2) println(s"CASE|${c.lineNumber.get}|${as(0).lineNumber.get}|${as(0).columnNumber.get}|${as(0).code.replace("\n","\\n")}|${as(1).lineNumber.get}|${as(1).columnNumber.get}|${c.code.replace("\n","\\n")}")
  }
}
