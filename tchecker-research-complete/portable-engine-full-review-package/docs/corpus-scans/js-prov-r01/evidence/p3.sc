@main def exec(cpgFile: String, mode: String) = {
  importCpg(cpgFile)
  if (mode=="nest") {
    println("=== NESTJS ===")
    cpg.imports.l.foreach{i=>println(s"  IMPORT ${i.code}")}
    cpg.method.l.filter(_.name=="login").foreach{m=>
      println(s"  method=${m.fullName} params=${m.parameter.l.sortBy(_.index).map(p=>s"${p.index}:${p.name}:${p.typeFullName}").mkString(", ")}")
      println(s"  annotations=${m.annotation.l.map(a=>a.name).mkString(",")}")
      m.parameter.l.foreach{p=>println(s"    param ${p.name} annotations=[${p.annotation.l.map(_.name).mkString(",")}] code=${p.code}")}
    }
    cpg.typeDecl.nameExact("UsersController").l.foreach{t=>println(s"  class annotations=${t.annotation.l.map(_.name).mkString(",")}")}
  } else {
    println("=== DESTRUCTURING / ALIAS in <lambda>9 ===")
    cpg.method.nameExact("<lambda>9").l.foreach{m=>
      m.ast.isCall.nameExact("<operator>.assignment").l.foreach{a=>println(s"  ASSIGN ${a.code.replace("\n","")}")}
      m.ast.isCall.nameExact("<operator>.fieldAccess").l.map(_.code.replace("\n","")).distinct.foreach{c=>println(s"  FIELD $c")}
    }
    println("=== HAPI handler reachable inside route object? ===")
    cpg.method.l.filter(m=>m.ast.isCall.code(".*request\\.payload.*").nonEmpty).foreach{m=>
      println(s"  hapi handler=${m.fullName} params=${m.parameter.l.sortBy(_.index).map(p=>s"${p.index}:${p.name}").mkString(",")}")
    }
  }
}
