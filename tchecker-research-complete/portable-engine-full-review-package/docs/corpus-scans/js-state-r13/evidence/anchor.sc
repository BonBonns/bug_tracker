@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("=== ANCHOR: framework import ===")
  cpg.call.nameExact("require").l.take(6).foreach { c => println(s"  ${c.inAssignment.l.map(_.code).mkString(" | ")}") }
  cpg.imports.l.take(8).foreach { i => println(s"  IMPORT ${i.code}") }
  println("=== ANCHOR: /auth registration ===")
  cpg.call.l.filter(c => c.code.contains("'/auth'") || c.code.contains("\"/auth\"")).take(3).foreach { c =>
    println(s"  name=${c.name} mfn=${c.methodFullName}")
    c.argument.l.sortBy(_.argumentIndex).foreach { a =>
      println(s"    arg${a.argumentIndex} label=${a.label} code=${a.code.replace("\n","\\n").take(40)}" +
        (a match { case m: io.shiftleft.codepropertygraph.generated.nodes.MethodRef => s" -> ${m.methodFullName}"; case _ => "" }))
    }
  }
  println("=== ANCHOR: handler params + username provenance ===")
  cpg.method.l.filter(m => m.ast.isCall.code(".*users\\[username\\].*").nonEmpty).foreach { m =>
    println(s"  handler=${m.fullName} params=${m.parameter.l.sortBy(_.index).map(p=>s"idx${p.index}:${p.name}:${p.typeFullName}").mkString("  ")}")
    m.ast.isCall.nameExact("<operator>.assignment").l.filter(_.code.contains("username")).foreach { a =>
      println(s"    ASSIGN ${a.code.replace("\n","")}")
    }
    m.ast.isCall.nameExact("<operator>.fieldAccess").l.filter(_.code.contains("body")).map(_.code).distinct.foreach { c =>
      println(s"    FIELD ${c}")
    }
  }
}
