@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("=== app.post('/auth', ...) registration ===")
  cpg.call.nameExact("post").l.foreach { c =>
    val lit = c.argument.l.collect{case l: io.shiftleft.codepropertygraph.generated.nodes.Literal => l.code}.mkString(",")
    if (lit.contains("auth")) {
      println(s"  name=${c.name} mfn=${c.methodFullName} lit=$lit")
      c.argument.l.sortBy(_.argumentIndex).foreach { a =>
        println(s"    arg${a.argumentIndex} label=${a.label}" +
          (a match { case m: io.shiftleft.codepropertygraph.generated.nodes.MethodRef => s" METHOD_REF -> ${m.methodFullName}"
                     case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => s" ident=${i.code} type=${i.typeFullName}"
                     case o => s" code=${o.code.take(30)}" }))
      }
    }
  }
  println("=== that handler's params + username assignment ===")
  cpg.method.fullName(".*<lambda>.*").l.filter(m => m.ast.isCall.code("users\\[username\\]").nonEmpty).foreach { m =>
    println(s"  handler=${m.fullName}")
    println(s"  params=${m.parameter.l.sortBy(_.index).map(p=>s"idx${p.index}:${p.name}:${p.typeFullName}").mkString("  ")}")
    m.ast.isCall.nameExact("<operator>.assignment").l.filter(_.code.contains("username =")).foreach { a =>
      println(s"    ASSIGN ${a.code.replace("\n","")}")
    }
  }
}
