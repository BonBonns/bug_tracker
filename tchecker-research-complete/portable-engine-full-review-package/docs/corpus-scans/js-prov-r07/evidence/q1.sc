@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("=== Q1/Q2: every router.<verb> registration — 3 evidence levels ===")
  cpg.call.l.filter(c=>Set("get","post","put","delete","patch").contains(c.name)).foreach{c=>
    val recv = c.argument.l.headOption
    val (rid,rty,rh) = recv.map{
      case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => (i.id.toString,i.typeFullName,i.dynamicTypeHintFullName.l.mkString("|"))
      case o => (o.id.toString,o.label,"")}.getOrElse(("-","-",""))
    if (rty=="ANY" || rty.contains("koa") || rty.contains("router")) {
      val callees = c.callee.l
      println(f"  L${c.lineNumber.getOrElse(0)}%-5s ${c.name}%-7s file=${c.method.filename}")
      println(f"       L1_name=${c.name}  L2_mfn=${c.methodFullName}")
      println(f"       L3_callee=[${callees.map(m=>s"${m.id}:${m.fullName}").mkString(" , ")}]  n=${callees.size}")
      println(f"       RECV id=$rid type=$rty hints=[$rh]  dispatch=${c.dispatchType}")
      println(f"       ARGS=${c.argument.l.sortBy(_.argumentIndex).map(a=>a match {
        case m: io.shiftleft.codepropertygraph.generated.nodes.MethodRef => s"${a.argumentIndex}:MREF(${m.methodFullName})"
        case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => s"${a.argumentIndex}:ID(${i.name}:${i.typeFullName})"
        case l: io.shiftleft.codepropertygraph.generated.nodes.Literal => s"${a.argumentIndex}:LIT(${l.code})"
        case o => s"${a.argumentIndex}:${o.label}"}).mkString(" ")}")
    }
  }
}
