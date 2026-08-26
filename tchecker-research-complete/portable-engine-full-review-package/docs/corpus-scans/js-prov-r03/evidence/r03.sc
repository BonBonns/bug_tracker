@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("=== L1: is the Router constructor identity present? ===")
  cpg.call.l.filter(c => c.name=="require" || c.name.contains("alloc")).map(_.code.replace("\n","")).distinct.filter(_.contains("router")).foreach{c=>println(s"  $c")}
  cpg.assignment.l.filter(a=>a.code.contains("Router")).map(_.code.replace("\n","")).distinct.foreach{a=>println(s"  ASSIGN $a")}
  println("=== L2: the 'router' LOCAL in the DEFINING module ===")
  cpg.local.nameExact("router").l.foreach{l=>println(s"  LOCAL router type=${l.typeFullName} file=${l.method.filename}")}
  println("=== L3: register(router) call sites -> argument binding ===")
  cpg.call.nameExact("register").l.foreach{c=>
    println(s"  register mfn=${c.methodFullName} file=${c.method.filename}")
    c.argument.l.sortBy(_.argumentIndex).foreach{a=>a match{
      case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => println(s"      arg${a.argumentIndex} IDENT ${i.name} type=${i.typeFullName}")
      case o => println(s"      arg${a.argumentIndex} ${o.label} ${o.code.replace("\n","").take(40)}")}}
  }
  println("=== L4: the RECEIVING module's exported register fn + its param ===")
  cpg.method.nameExact("register").l.foreach{m=>
    println(s"  method ${m.fullName} params=${m.parameter.l.sortBy(_.index).map(p=>s"${p.index}:${p.name}:${p.typeFullName}").mkString(" ")}")
  }
  println("=== L5: exports/imports graph availability ===")
  cpg.imports.l.take(6).foreach{i=>println(s"  IMPORT ${i.code.replace("\n","")}")}
  cpg.assignment.l.filter(_.code.startsWith("module.exports")).map(_.code.replace("\n","").take(60)).distinct.take(8).foreach{a=>println(s"  EXPORT $a")}
}
