@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("=== SPREAD representation ===")
  cpg.call.l.filter(c=>c.name.contains("spread")||c.code.contains("...")).map(c=>(c.name,c.code.replace("\n"," ").take(56))).distinct.take(10).foreach{case(n,c)=>println(s"  $n | $c")}
  println("=== assignments in mw (RHS shape) ===")
  cpg.method.nameExact("mw").l.foreach{m=>
    m.block.astChildren.l.sortBy(_.order).foreach{s=>
      println(s"  ord=${s.order} ${s.label} ${s.code.replace("\n"," ").take(64)}")}}
  println("=== destructuring lowering for const {value} = r ===")
  cpg.method.nameExact("mw").l.foreach{m=>
    m.ast.isCall.nameExact("<operator>.assignment").l.filter(a=>a.code.contains("value")||a.code.contains("error")).foreach{a=>
      println(s"  ${a.code.replace("\n"," ").take(60)}")}}
}
