@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("=== INDEX/FIELD READS ===")
  cpg.call.filter(c => Set("<operator>.indexAccess","<operator>.fieldAccess").contains(c.name)).l
    .filter(c => c.method.name.startsWith("t")).foreach { c =>
    val as = c.argument.l.sortBy(_.argumentIndex)
    val base = as.headOption.map(a => s"${a.code}:${a.label}").getOrElse("?")
    val baseType = as.headOption.map {
      case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => i.typeFullName
      case k: io.shiftleft.codepropertygraph.generated.nodes.Call => k.typeFullName
      case o => o.label
    }.getOrElse("?")
    val key = as.lift(1).map(a => s"${a.code}:${a.label}").getOrElse("-")
    println(f"${c.method.name}%-28s ${c.name}%-24s base=$base%-22s baseType=$baseType%-42s key=$key")
  }
  println("=== CALLS that could be guards / storage models ===")
  cpg.call.filter(c => c.method.name.startsWith("t")).l
    .filter(c => Set("hasOwnProperty","hasOwn","call","create","get","set").contains(c.name))
    .foreach { c => println(f"${c.method.name}%-28s name=${c.name}%-16s code=${c.code}") }
  println("=== control structures (guards) ===")
  cpg.controlStructure.l.filter(_.method.name.startsWith("t")).foreach { cs =>
    println(f"${cs.method.name}%-28s cond=${cs.condition.code.headOption.getOrElse("-")}")
  }
}
