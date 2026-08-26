@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  cpg.call.l.filter(c=>Set("get","post").contains(c.name)).sortBy(_.lineNumber.getOrElse(0)).foreach{c=>
    val recv=c.argument.l.headOption.map{case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier=>s"${i.name}:${i.typeFullName}";case o=>o.label}.getOrElse("?")
    val lit=c.argument.l.collect{case l: io.shiftleft.codepropertygraph.generated.nodes.Literal=>l.code}.mkString
    println(f"  $lit%-8s ${c.name}%-5s recv=$recv%-34s mfn=${c.methodFullName}%-40s callees=${c.callee.l.size}[${c.callee.fullName.l.mkString(",")}]")
  }
}
