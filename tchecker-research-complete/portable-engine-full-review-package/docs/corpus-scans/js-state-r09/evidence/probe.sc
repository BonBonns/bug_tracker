@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("=== all equality-ish calls: name / methodFullName / code ===")
  cpg.call.filter(c => c.code.contains("==")).l.foreach { c =>
    println(s"name=${c.name} | mfn=${c.methodFullName} | typeFullName=${c.typeFullName} | code=${c.code}")
  }
}
