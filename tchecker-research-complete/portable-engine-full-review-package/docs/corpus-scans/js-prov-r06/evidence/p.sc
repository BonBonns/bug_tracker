@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("=== PART C: registration-call discriminator vs declared-interface lookalike ===")
  cpg.call.nameExact("post").l.foreach{c=>
    val recv = c.argument.l.headOption.map{case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier=>s"${i.name}:${i.typeFullName}"; case o=>o.label}.getOrElse("?")
    println(f"  post mfn=${c.methodFullName}%-56s recv=$recv")
  }
  println("=== D: structural identity routes for the receivers ===")
  List("app","notFramework","nf2").foreach{n=>
    cpg.identifier.nameExact(n).l.take(1).foreach{i=>
      val decls = cpg.typ.fullNameExact(i.typeFullName).l.flatMap(_.referencedTypeDecl.l).map(d=>s"${d.id}:${d.fullName}:ext=${d.isExternal}")
      println(f"  $n%-14s type=${i.typeFullName}%-42s -> TYPE_DECL[${decls.mkString(" , ")}]")
    }
  }
}
