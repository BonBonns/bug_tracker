@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("=== CALLEE-SIDE: the register lambda's parameter type ===")
  List("resources/account/sign-in/index.js::program:<lambda>0",
       "resources/account/sign-up/index.js::program:<lambda>0").foreach { fn =>
    cpg.method.fullNameExact(fn).l.foreach { m =>
      println(s"  ${m.fullName}")
      m.parameter.l.sortBy(_.index).foreach{p=>println(s"      param${p.index} ${p.name} type=${p.typeFullName} hints=[${p.dynamicTypeHintFullName.l.mkString("|")}]")}
      m.ast.isCall.l.filter(c=>Set("post","get","put","delete").contains(c.name)).foreach{c=>
        println(s"      REG ${c.name} mfn=${c.methodFullName} recv_type=${c.argument.l.headOption.map{case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier=>i.typeFullName; case o=>o.label}.getOrElse("?")}")}
    }
  }
  println("=== IS THE CALL EDGE RESOLVED? (caller -> callee) ===")
  cpg.call.nameExact("register").l.take(3).foreach{c=>
    println(s"  register callee(s)=${c.callee.fullName.l.mkString(",")}  argType=${c.argument.l.filter(_.argumentIndex==1).map{case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier=>i.typeFullName; case o=>o.label}.mkString}")
  }
}
