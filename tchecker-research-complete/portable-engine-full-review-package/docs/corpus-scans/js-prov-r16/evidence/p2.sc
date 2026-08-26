@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("=== a3 = {...body, ...query}: spread children (composition) ===")
  cpg.call.nameExact("<operator>.assignment").l.filter(_.code.contains("a3")).foreach{a=>
    a.argument.l.filter(_.argumentIndex==2).foreach{rhs=>
      println(s"  RHS label=${rhs.label}")
      rhs.ast.isCall.nameExact("<operator>.spread").l.foreach{s=>
        println(s"     SPREAD src=${s.argument.l.map(_.code.replace("\n"," ")).mkString(",")}")}}}
  println("=== a4 = {k:1, ...body} ===")
  cpg.call.nameExact("<operator>.assignment").l.filter(_.code.contains("a4")).foreach{a=>
    a.argument.l.filter(_.argumentIndex==2).foreach{rhs=>
      rhs.ast.isCall.nameExact("<operator>.spread").l.foreach{s=>println(s"     SPREAD src=${s.argument.l.map(_.code).mkString(",")}")}}}
  println("=== destructuring BLOCK internals: const {value} = r ===")
  cpg.method.nameExact("mw").l.foreach{m=>
    m.block.astChildren.l.filter(s=>s.label=="BLOCK"&&s.code.contains("value")).foreach{b=>
      b.ast.isCall.l.take(4).foreach{c=>println(s"     ${c.name} | ${c.code.replace("\n"," ").take(46)}")}}}
  println("=== opaque call r = schema.validate(a3): args + callee ===")
  cpg.call.nameExact("validate").l.foreach{c=>
    println(s"  mfn=${c.methodFullName} callees=${c.callee.l.size} args=${c.argument.l.map(_.code.take(14)).mkString(",")}")}
}
