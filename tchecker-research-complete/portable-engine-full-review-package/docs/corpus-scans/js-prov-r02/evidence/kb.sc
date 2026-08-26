@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("=== ALL router.<verb> registrations in Koa corpus ===")
  cpg.call.l.filter(c => Set("get","post","put","delete","patch").contains(c.name)).foreach { c =>
    val recv = c.argument.l.headOption.map{ case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => s"${i.name}:${i.typeFullName}"; case o => o.label }.getOrElse("?")
    if (recv.contains("router")) {
      println(s"  ${c.name} mfn=${c.methodFullName} recv=$recv args=${c.argument.l.sortBy(_.argumentIndex).map(a=>a match {
        case m: io.shiftleft.codepropertygraph.generated.nodes.MethodRef => s"${a.argumentIndex}:MREF"
        case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => s"${a.argumentIndex}:ID(${i.name}:${i.typeFullName})"
        case l: io.shiftleft.codepropertygraph.generated.nodes.Literal => s"${a.argumentIndex}:LIT"
        case o => s"${a.argumentIndex}:${o.label}" }).mkString(" ")}")
    }
  }
  println("=== ctx property reads across corpus ===")
  cpg.call.nameExact("<operator>.fieldAccess").l.map(_.code.replace("\n","")).filter(_.startsWith("ctx.")).distinct.take(20).foreach{c=>println(s"  $c")}
}
