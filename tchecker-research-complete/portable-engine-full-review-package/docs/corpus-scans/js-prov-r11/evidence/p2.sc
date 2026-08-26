@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("=== Q8: write position vs next() -- STRUCTURAL (block child order) ===")
  cpg.method.l.filter(m=>m.name.matches("producer|afterWriter|condWriter|bodyWriter|queryWriter|constWriter|derivedWriter|<lambda>0")).foreach{m=>
    val stmts = m.block.astChildren.l.sortBy(_.order)
    val nextOrd = stmts.filter(s=>s.code.contains("next(")).map(_.order).headOption
    val writes = stmts.filter(s=>s.code.contains("ctx.")&&s.code.contains("=")&&(!s.code.contains("next(")))
      .map(s=>(s.order, s.code.replace("\n"," ").take(38)))
    // conditional writes live inside a CONTROL_STRUCTURE child
    val condW = m.ast.isControlStructure.l.flatMap(cs=>cs.ast.isCall.nameExact("<operator>.assignment").l.map(c=>(cs.order,c.code.replace("\n"," ").take(38))))
    println(s"  ${m.name}: nextOrder=${nextOrd.getOrElse(-1)}")
    writes.foreach{case(o,c)=>println(s"      WRITE order=$o ${if(nextOrd.isDefined && o<nextOrd.get)"BEFORE_NEXT" else if(nextOrd.isDefined)"AFTER_NEXT" else "NO_NEXT"}  $c")}
    condW.foreach{case(o,c)=>println(s"      COND_WRITE(in control structure) order=$o ${if(nextOrd.isDefined && o<nextOrd.get)"BEFORE_NEXT" else "AFTER_NEXT"}  $c")}
  }
}
