// transform_presence.sc — SERIALIZE-DOS-R01, size/structure-bound axis, fact producer.
//
// NEW, property-local, deterministic-only fact table. Does NOT reimplement the
// tchecker-property-adjudicator taint engine's interprocedural transform-chain /
// trace-identity machinery (see ../RECONCILIATION.md and ../serialize_dos_r01.py for the
// explicit, disclosed scope reduction this represents). This producer answers a much
// narrower, single-hop, intraprocedural structural question, for the SAME real serializer
// call sites export_serialize_facts.sc already finds (same method scan, same
// isSerializer/name predicate, same per-line dedup -- so the two fact sets align 1:1 by
// (file, method, line)):
//
//   Is the value passed to JSON.stringify/util.inspect used AS-IS from an attacker source
//   (no transform_present), or was it most recently assigned from the return value of some
//   OTHER call (transform_present=true, callee name recorded when statically resolvable)?
//
// This is a conservative, structural approximation only: it does not follow the transform
// into its own body, does not determine whether the transform actually bounds size, and
// does not cross method boundaries (an attacker value laundered through an intervening
// helper's PARAMETER, rather than assigned locally in this method, is not modeled -- the
// same intraprocedural scope the crash-DoS fact producer already discloses).
//
// transform_presence.tsv (6 cols): file, method, line, arg_code, transform_present,
//                                   transform_callee (empty when transform_present=false
//                                   or the callee name is not statically resolvable)
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s: String) = Option(s).getOrElse("").replace("\n", " ").replace("\t", " ").take(200)
  def w(n: String) = new java.io.PrintWriter(new java.io.File(s"$outDir/$n"), "UTF-8")

  def isSerializer(c: nodes.Call): Boolean = {
    val code = Option(c.code).getOrElse("")
    code.matches("""(?s).*\bJSON\.stringify\s*\(.*""") ||
    code.matches("""(?s).*\butil\.inspect\s*\(.*""") ||
    (c.name == "stringify" && code.contains("JSON"))
  }

  val tp = w("transform_presence.tsv")
  try cpg.method.isExternal(false).l.foreach { m =>
    // Same per-method local-assignment index the crash-DoS producer builds: identifier ->
    // the RHS Expression node of its most recent assignment in this method (last write wins,
    // matching the existing producer's intraprocedural, order-insensitive scope).
    val lastAssignRhs = scala.collection.mutable.Map[String, nodes.Expression]()
    m.assignment.l.foreach { a =>
      val rhsOpt = a.argument.l.find(_.argumentIndex == 2)
      val lhsName = a.argument.l.find(_.argumentIndex == 1).collect { case i: nodes.Identifier => i.name }
      (lhsName, rhsOpt) match {
        case (Some(name), Some(rhs)) => lastAssignRhs(name) = rhs
        case _ => ()
      }
    }

    val seen = scala.collection.mutable.Set[Int]()
    m.call.l.filter(isSerializer).foreach { c =>
      val line = c.lineNumber.map(_.toInt).getOrElse(-1)
      if ((c.name == "stringify" || c.name == "inspect") && seen.add(line)) {
        // ONLY the value argument (argumentIndex == 1) -- JSON.stringify's optional
        // replacer/space arguments (index 2, 3) are a different concern entirely and
        // must never overwrite the value argument's own row for this (file, method,
        // line) key in transform_presence.tsv, which is looked up by site alone.
        c.argument.l.filter(_.argumentIndex == 1).foreach { arg =>
          val argCode = Option(arg.code).getOrElse("")
          // Resolve the RHS to inspect: if the argument is itself a bare identifier that was
          // locally assigned, follow to that assignment's RHS; otherwise inspect the argument
          // expression directly (covers an inline call passed straight to the sink).
          val toInspect: Option[nodes.Expression] = arg match {
            case i: nodes.Identifier => lastAssignRhs.get(i.name).orElse(Some(arg))
            case other => Some(other)
          }
          val (transformPresent, calleeName) = toInspect match {
            // A synthetic desugared operator call (Joern lowers `req.body`, `a[b]`, `a=b`,
            // etc. to `<operator>.fieldAccess` / `<operator>.indexAccess` / ... Call nodes)
            // is source ACCESS, not a transform -- excluded explicitly, the same way the
            // crash-DoS producer and setup_candidate.sc each exclude their own non-transform
            // call categories (a plain builtin-name set there; a name-prefix check here,
            // since Joern's own synthetic-operator naming convention is name-agnostic by
            // construction, not a per-property vocabulary).
            case Some(callNode: nodes.Call) if !Option(callNode.name).getOrElse("").startsWith("<operator>") =>
              (true, Option(callNode.name).getOrElse(""))
            case _ => (false, "")
          }
          tp.println(Seq(cl(m.filename), cl(m.fullName), line.toString, cl(argCode),
            transformPresent.toString, cl(calleeName)).mkString("\t"))
        }
      }
    }
  } finally tp.close()

  println(s"TRANSFORM_PRESENCE_COMPLETE: $outDir")
}
