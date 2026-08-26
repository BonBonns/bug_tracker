@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("=== LAYER 3: operand span fidelity (can we slice between operands?) ===")
  cpg.call.filter(c => Set("<operator>.equals","<operator>.notEquals").contains(c.name)).l.foreach { c =>
    println(s"--- ${c.code.replace("\n","\\n")}  [node line=${c.lineNumber} col=${c.columnNumber}]")
    c.argument.l.sortBy(_.argumentIndex).foreach { a =>
      println(s"      arg${a.argumentIndex} line=${a.lineNumber} col=${a.columnNumber} code=${a.code.replace("\n","\\n")}")
    }
  }
  println("=== does any node type expose an END offset? checking File/Method offsets ===")
  cpg.method.name("m1_looseEq").l.foreach { m =>
    println(s"method offset=${m.offset} offsetEnd=${m.offsetEnd} lineEnd=${m.lineNumberEnd}")
  }
}
