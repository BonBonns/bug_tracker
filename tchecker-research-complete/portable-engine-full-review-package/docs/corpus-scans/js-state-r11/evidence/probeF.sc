@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("=== caseF: index-access base evidence ===")
  cpg.call.nameExact("<operator>.indexAccess").l.filter(_.code.contains("users")).foreach { ia =>
    println(s"indexAccess code=${ia.code} typeFullName=${ia.typeFullName}")
    ia.argument.l.sortBy(_.argumentIndex).foreach { a =>
      val t = a match {
        case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => s"${i.typeFullName} hints=[${i.dynamicTypeHintFullName.l.mkString("|")}]"
        case _ => a.label
      }
      println(s"    base/idx arg${a.argumentIndex} code=${a.code} -> $t")
    }
  }
  println("=== 'users' LOCAL declaration + its assignment ===")
  cpg.local.nameExact("users").l.foreach { l =>
    println(s"LOCAL users typeFullName=${l.typeFullName} code=${l.code}")
  }
  cpg.assignment.l.filter(_.code.contains("users =")).foreach { a =>
    println(s"ASSIGN ${a.code.replace("\n","\\n")}")
  }
  println("=== TYPE_DECL for Record/users ===")
  cpg.typeDecl.l.filter(t => t.name.contains("Record") || t.fullName.contains("Record")).foreach { t =>
    println(s"TYPEDECL name=${t.name} full=${t.fullName} external=${t.isExternal}")
  }
  println("=== members of any object-literal type backing users ===")
  cpg.member.l.foreach { m => println(s"MEMBER ${m.name} : ${m.typeFullName} (owner=${m.typeDecl.fullName})") }
}
