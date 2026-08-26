@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("=== LAYER 1: ALL properties on each equality-family operator node ===")
  cpg.call.filter(c => Set("<operator>.equals","<operator>.notEquals").contains(c.name)).l.foreach { c =>
    println(s"--- node ${c.id} name=${c.name} code=${c.code.replace("\n","\\n")}")
    c.propertiesMap.forEach((k,v) => println(s"      $k = ${v.toString.replace("\n","\\n")}"))
  }
}
