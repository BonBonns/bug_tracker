// JS-PROV-R14 — raw facts for module specifier resolution.
//  (a) require() bindings: specifier literal + the local it is assigned to
//  (b) export assignments: file + member name + RHS method identity
//  (c) call sites whose receiver is a require-bound local
@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s:String)=Option(s).getOrElse("").replace("\n"," ").replace("\t"," ").take(90)
  val rq=new java.io.PrintWriter(new java.io.File(s"$outDir/require_bindings.tsv"),"UTF-8")
  try cpg.call.nameExact("require").l.foreach{ c =>
    val spec = c.argument.l.collectFirst{case l: io.shiftleft.codepropertygraph.generated.nodes.Literal => l.code.replaceAll("^['\"]|['\"]$","")}
    val local = c.inAssignment.l.flatMap(_.argument.l.filter(_.argumentIndex==1))
      .collectFirst{case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => i.name}
    spec.foreach{ s => rq.println(Seq(cl(c.method.filename), cl(s), cl(local.getOrElse("")), c.id).mkString("\t")) }
  } finally rq.close()

  // JS-PROV-R33 (SOUNDNESS): `const x = require(spec).member` selects a MEMBER
  // of the module, not the module object. `require_bindings.tsv` records only
  // `x -> spec`, which is not incomplete but FALSE: a consumer then looks
  // members up in the WRONG module and, where names overlap, fabricates an
  // identity.
  //
  // Emitted as a SEPARATE FILE, not a new column on require_bindings.tsv --
  // that file is parsed by three independent consumers, so a column change is a
  // cross-cutting schema edit (this is what broke the first R33 attempt).
  // Existing readers are untouched; a consumer opts in by reading this file.
  val ms=new java.io.PrintWriter(new java.io.File(s"$outDir/require_member_selection.tsv"),"UTF-8")
  try cpg.call.nameExact("require").l.foreach{ c =>
    val spec = c.argument.l.collectFirst{
      case l: io.shiftleft.codepropertygraph.generated.nodes.Literal => l.code.replaceAll("^['\"]|['\"]$","")}
    val fa = c.astParent match {
      case p: io.shiftleft.codepropertygraph.generated.nodes.Call if p.name=="<operator>.fieldAccess" => Some(p)
      case _ => None
    }
    fa.foreach{ f =>
      val sel = f.argument.l.sortBy(_.argumentIndex).lift(1).map(_.code).getOrElse("")
      val loc = f.inCall.nameExact("<operator>.assignment").l.headOption
        .flatMap(_.argument.l.filter(_.argumentIndex==1)
          .collectFirst{case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => i.name})
      spec.foreach{ sp =>
        if (sel.nonEmpty && loc.nonEmpty)
          ms.println(Seq(cl(c.method.filename), cl(loc.get), cl(sp), cl(sel), c.id).mkString("\t"))
      }
    }
  } finally ms.close()

  val ex=new java.io.PrintWriter(new java.io.File(s"$outDir/module_exports.tsv"),"UTF-8")
  try cpg.assignment.l.filter(a=>a.code.contains("exports")).foreach{ a =>
    val args=a.argument.l.sortBy(_.argumentIndex)
    val lhs=args.headOption.map(x=>cl(x.code)).getOrElse("")
    // member name: `exports.X` / `module.exports.X` -> X ; `module.exports` -> "" (default)
    val member = { val t=lhs.trim
      if (t=="module.exports"||t=="exports") "" else t.split('.').lastOption.getOrElse("") }
    val rhs=args.lift(1)
    val rhsMethod = rhs.map{
      case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => i.typeFullName
      case m: io.shiftleft.codepropertygraph.generated.nodes.MethodRef => m.methodFullName
      case o => "" }.getOrElse("")
    val rhsKind = rhs.map(_.label).getOrElse("")
    // JS-PROV-R26: for a RE-EXPORT the RHS is a field access on an imported
    // module object (`exports.f = _lib.f`). Record the BASE LOCAL and MEMBER
    // structurally so the chain can be followed, rather than parsing the code
    // string (JS-PROV-R13: code strings are not identities).
    val (reBase, reMember) = rhs match {
      case Some(c: io.shiftleft.codepropertygraph.generated.nodes.Call) if c.name=="<operator>.fieldAccess" =>
        val fa = c.argument.l.sortBy(_.argumentIndex)
        (fa.headOption.collect{case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier=>i.name}.getOrElse(""),
         fa.lift(1).map(_.code).getOrElse(""))
      case _ => ("","")
    }
    ex.println(Seq(cl(a.method.filename), member, cl(rhsMethod), rhsKind, cl(a.code),
                   cl(reBase), cl(reMember)).mkString("\t"))

    // JS-PROV-R31: `module.exports = { a, b }` lowers to a BLOCK whose member
    // assignments are individually present (`_tmp_0.a = a`). Emit each
    // STATICALLY NAMED member as its own export row.
    //   fieldAccess LHS -> static key   -> emitted
    //   indexAccess LHS -> computed key -> NOT emitted (abstains)
    //   spread child    -> no name      -> NOT emitted (abstains)
    // A static key alone is NOT sufficient: downstream still requires the RHS
    // to carry a declaration identity, via the same rhs/kind columns used by
    // every other export row.
    rhs.foreach { r0 =>
      if (r0.label == "BLOCK") {
        r0.astChildren.l.foreach {
          case mc: io.shiftleft.codepropertygraph.generated.nodes.Call if mc.name=="<operator>.assignment" =>
            val ma = mc.argument.l.sortBy(_.argumentIndex)
            val lhsFA = ma.headOption.collect{
              case fa: io.shiftleft.codepropertygraph.generated.nodes.Call if fa.name=="<operator>.fieldAccess" => fa }
            lhsFA.foreach { fa =>
              val mname = fa.argument.l.sortBy(_.argumentIndex).lift(1).map(_.code).getOrElse("")
              val mrhs = ma.lift(1)
              val mMethod = mrhs.map{
                case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => i.typeFullName
                case mr: io.shiftleft.codepropertygraph.generated.nodes.MethodRef => mr.methodFullName
                case _ => "" }.getOrElse("")
              val mKind = mrhs.map(_.label).getOrElse("")
              val (mB, mM) = mrhs match {
                case Some(c2: io.shiftleft.codepropertygraph.generated.nodes.Call) if c2.name=="<operator>.fieldAccess" =>
                  val f2 = c2.argument.l.sortBy(_.argumentIndex)
                  (f2.headOption.collect{case i2: io.shiftleft.codepropertygraph.generated.nodes.Identifier=>i2.name}.getOrElse(""),
                   f2.lift(1).map(_.code).getOrElse(""))
                case _ => ("","") }
              if (mname.nonEmpty)
                ex.println(Seq(cl(a.method.filename), mname, cl(mMethod), mKind,
                               cl(mc.code), cl(mB), cl(mM)).mkString("\t"))
            }
          case _ =>
        }
      }
    }
  } finally ex.close()

  val ic=new java.io.PrintWriter(new java.io.File(s"$outDir/import_calls.tsv"),"UTF-8")
  try cpg.call.l.foreach{ c =>
    val recv=c.argument.l.find(_.argumentIndex==0)
    // direct: m1(1)  -> callee name is the local itself
    // member: m2.validate(1) -> receiver is fieldAccess(local, member)
    recv.foreach{
      case fa: io.shiftleft.codepropertygraph.generated.nodes.Call if fa.name=="<operator>.fieldAccess" =>
        val fargs=fa.argument.l.sortBy(_.argumentIndex)
        val base=fargs.headOption.collect{case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier=>i.name}
        val mem=fargs.lift(1).map(_.code)
        base.foreach{b=> ic.println(Seq(c.id, cl(c.method.filename), b, mem.getOrElse(""), cl(c.name), cl(c.code)).mkString("\t"))}
      case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier =>
        ic.println(Seq(c.id, cl(c.method.filename), i.name, "", cl(c.name), cl(c.code)).mkString("\t"))
      case _ =>
    }
  } finally ic.close()
}
