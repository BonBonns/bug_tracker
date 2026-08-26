// JS-PROV-R17 — per-method local definition chains, enough to walk a write's
// RHS back to its origins WITHOUT modelling any third-party semantics.
// Emits, for `X = RHS`: the RHS kind, its callee resolvability, its spread
// SOURCE operands (accumulator temp excluded), member base/name, and call args.
@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s:String)=Option(s).getOrElse("").replace("\n"," ").replace("\t"," ").take(70)
  val w=new java.io.PrintWriter(new java.io.File(s"$outDir/local_defs.tsv"),"UTF-8")
  try cpg.method.l.foreach{ m =>
    m.ast.isCall.nameExact("<operator>.assignment").l.foreach{ a =>
      val args=a.argument.l.sortBy(_.argumentIndex)
      val lhs=args.headOption; val rhs=args.lift(1)
      val lhsName = lhs.collect{case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier=>i.name}
      rhs.foreach{ r =>
        // Unwrap `await X` so the INNER call's identity/args are recorded:
        // otherwise a transform boundary hidden behind `await` is invisible.
        val rEff = r match {
          case c: io.shiftleft.codepropertygraph.generated.nodes.Call if c.name=="<operator>.await" =>
            c.argument.l.filter(_.argumentIndex>0).headOption.getOrElse(r)
          case _ => r
        }
        // spread SOURCES: skip argumentIndex 1 (the accumulating temp)
        val spreads = rEff.ast.isCall.nameExact("<operator>.spread").l
          .flatMap(_.argument.l.filter(_.argumentIndex>1)).map(x=>cl(x.code)).distinct
        val (rk, callee, nCallee, cargs) = rEff match {
          case c: io.shiftleft.codepropertygraph.generated.nodes.Call =>
            (c.name, c.methodFullName, c.callee.l.size,
             c.argument.l.filter(_.argumentIndex>0).map{
               case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => "LOCAL:"+i.name
               case x => "EXPRESSION_NODE:"+x.id
             }.mkString("|"))
          case o => (o.label, "", -1, "")
        }
        lhsName.foreach{ n =>
          w.println(Seq(cl(m.fullName), n, r.label, cl(rk), cl(callee), nCallee,
                        spreads.mkString("|"), cargs, cl(rEff.code)).mkString("\t")) }
      }
    }
  } finally w.close()

  // JS-PROV-R18 — ArgumentValueRef targets. For an expression used as a call
  // argument, record the spread SOURCES that belong to THAT node's own object
  // literal. Only direct AST children are inspected: a spread buried inside an
  // unrelated NESTED CALL must never be harvested as this argument's content
  // (the JS-PROV-R17 unsafe-direction bug).
  val e=new java.io.PrintWriter(new java.io.File(s"$outDir/expr_nodes.tsv"),"UTF-8")
  try cpg.call.l.foreach{ c =>
    c.argument.l.filter(_.argumentIndex>0).foreach{ a =>
      a match {
        case _: io.shiftleft.codepropertygraph.generated.nodes.Identifier =>
        // ONLY an argument that IS ITSELF an object literal contributes spread
        // sources. If the argument is a CALL, it is a NESTED TRANSFORM: its own
        // arguments' spreads belong to that inner call, not to the outer one.
        // Harvesting them would attribute an inner transform's inputs to the
        // outer transform -- the same unsafe direction as the JS-PROV-R17 bug.
        case node if node.label != "BLOCK" =>
          e.println(Seq(node.id, node.label, "", cl(node.code)).mkString("\t"))
        case node =>
          val direct = node.astChildren.l.flatMap{ ch =>
            ch match {
              case sp: io.shiftleft.codepropertygraph.generated.nodes.Call if sp.name=="<operator>.spread" => List(sp)
              case blk => blk.astChildren.l.collect{
                case sp2: io.shiftleft.codepropertygraph.generated.nodes.Call if sp2.name=="<operator>.spread" => sp2 }
            }
          }
          val srcs = direct.flatMap(_.argument.l.filter(_.argumentIndex>1)).map(x=>cl(x.code)).distinct
          e.println(Seq(node.id, node.label, srcs.mkString("|"), cl(node.code)).mkString("\t"))
      }
    }
  } finally e.close()
}
