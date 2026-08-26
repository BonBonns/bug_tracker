// FAIL-OPEN-R01 — candidate characterization for permissive-on-error security controls.
//
// This is deliberately NOT a vulnerability verdict and NOT a taint producer. It recognizes the
// high-signal Promise shape `.then(handler, handler)` only when the enclosing method also looks
// like a security decision. The identical-handler comparison is syntactic and local to the exact
// call; it is never presented as resolved function identity. Every inspected `.then` call is
// recorded in the audit table so exclusions and abstentions remain measurable.
//
// fail_open_candidates.tsv (18 columns):
//   candidate_id, file, line, then_call_id, fulfilled_handler_id, fulfilled_handler_code,
//   rejected_handler_id, rejected_handler_code, enclosing_method, enclosing_method_full_name,
//   then_expression, method_code, handler_definition_id, handler_definition_full_name,
//   handler_definition_body, handler_definition_status, candidate_class, deterministic_status
//
// fail_open_audit.tsv (8 columns):
//   file, line, then_call_id, enclosing_method, fulfilled_handler_code,
//   rejected_handler_code, disposition, reason
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile)
  new java.io.File(outDir).mkdirs()
  def cl(s: String) = Option(s).getOrElse("").replace("\t", " ").replace("\n", " ").take(1200)
  def securityName(s: String): Boolean =
    Option(s).getOrElse("").toLowerCase.matches(".*(allow|access|auth|permission|permit|rate|quota|limit|over|deny|block|verify|validat).*" )
  def securityBody(s: String): Boolean = {
    val x = Option(s).getOrElse("").toLowerCase
    x.matches("(?s).*(isallowed|authorize|permission|ratelimit|rate_limit|quota|deny|block|forbidden|unauthorized).*" ) ||
    x.matches("(?s).*(length|count|size)\\s*(===|==|>|>=|<|<=)\\s*[0-9]+.*")
  }
  // R02: a .then whose result is discarded (terminal continuation, e.g. `.then(next, next)`)
  // cannot default a value into a downstream decision. Value is "used" iff the call is an
  // argument/receiver of another call (await, an outer .then, etc.) or is returned.
  def discardedResult(c: nodes.Call): Boolean = c.astParent match {
    case _: nodes.Call   => false
    case _: nodes.Return => false
    case _               => true
  }

  // Resolve only by CPG identity. A direct METHOD_REF uses referencedMethod. An identifier must
  // REF exactly one LOCAL, and that exact local must have exactly one assignment whose RHS is a
  // METHOD_REF. No same-name or same-file fallback is permitted.
  def exactHandlerDefinition(n: nodes.AstNode): Option[nodes.Method] = n match {
    case mr: nodes.MethodRef => scala.util.Try(mr.referencedMethod).toOption
    case i: nodes.Identifier =>
      val locals = i.refsTo.collectAll[nodes.Local].l.distinctBy(_.id)
      if (locals.size != 1) None
      else {
        // A top-level function referenced inside another function is represented through a
        // materialized closure LOCAL. Follow its closureBindingId to the exact outer LOCAL before
        // looking for the METHOD_REF assignment (the frontend's explicit capture identity seam).
        val direct = locals.head
        val capturedOuter = direct.closureBindingId.toList.flatMap { cbid =>
          cpg.all.collectAll[nodes.ClosureBinding].l
            .filter(_.closureBindingId.contains(cbid))
            .flatMap(_._refOut.collect { case l: nodes.Local => l }.l)
        }
        val localIds = (direct :: capturedOuter).map(_.id).distinct.toSet
        val methods = cpg.assignment.l.flatMap { a =>
          val lhsMatches = a.argument.l.find(_.argumentIndex == 1).exists {
            case li: nodes.Identifier => li.refsTo.id.l.exists(localIds.contains)
            case _ => false
          }
          if (!lhsMatches) Nil
          else a.argument.l.find(_.argumentIndex == 2).collect {
            case rhs: nodes.MethodRef => scala.util.Try(rhs.referencedMethod).toOption
          }.flatten.toList
        }.distinctBy(_.id)
        if (methods.size == 1) methods.headOption else None
      }
    case _ => None
  }

  val candidates = new java.io.PrintWriter(new java.io.File(s"$outDir/fail_open_candidates.tsv"), "UTF-8")
  val audit = new java.io.PrintWriter(new java.io.File(s"$outDir/fail_open_audit.tsv"), "UTF-8")
  var ordinal = 0
  // R03: relocate the security signal from the ENCLOSING METHOD to the CONSUMER of the
  // defaulted value. A fail-open matters when the error-defaulted value can reach a security
  // decision; that is an interprocedural fact, not a property of the method holding the .then.
  // MEASURED: on fxa-customs-server the records.js `.then(parser,parser)` result reaches
  // isRateLimited/isBlocked/update via Joern's interprocedural dataflow.
  val securityDecisionCalls =
    cpg.call.name("update|isOver.*|isBlocked|isRateLimited|shouldBlock|isAllowed|canUnblock").l
  def reachesSecurityDecision(c: nodes.Call): Boolean =
    securityDecisionCalls.exists(sink => sink.reachableBy(Iterator.single(c)).nonEmpty)

  try cpg.call.nameExact("then").l.sortBy(_.id).foreach { c =>
    val args = c.argument.l.filter(_.argumentIndex >= 1).sortBy(_.argumentIndex)
    val fulfill = args.find(_.argumentIndex == 1)
    val reject = args.find(_.argumentIndex == 2)
    val method = c.method
    val file = cl(method.filename)
    val line = c.lineNumber.map(_.toInt).getOrElse(-1)
    val fcode = fulfill.map(x => cl(x.code)).getOrElse("")
    val rcode = reject.map(x => cl(x.code)).getOrElse("")
    val sameSyntax = fulfill.nonEmpty && reject.nonEmpty && fcode.nonEmpty && fcode == rcode
    val secHeuristic = securityName(method.name) || securityName(method.fullName) || securityBody(method.code)
    val secContext = secHeuristic || (fulfill.nonEmpty && reject.nonEmpty && fcode == rcode && reachesSecurityDecision(c))
    val (disp, reason) =
      if (reject.isEmpty) ("EXCLUDED_NO_REJECTION_HANDLER", "call has no explicit rejection continuation")
      else if (!sameSyntax) ("EXCLUDED_DISTINCT_HANDLER", "fulfillment and rejection handler syntax differs")
      else if (!secContext) ("EXCLUDED_NON_SECURITY_CONTEXT", "no bounded security-decision context was recognized")
      else if (discardedResult(c)) ("EXCLUDED_DISCARDED_CONTINUATION", "the .then result is discarded (terminal continuation such as .then(next, next)); no value defaults into a downstream decision")
      else ("CANDIDATE_OPEN", "same handler syntax serves fulfillment and rejection in a security-decision context")
    audit.println(Seq(file, line, c.id, cl(method.name), fcode, rcode, disp, reason).mkString("\t"))
    if (disp == "CANDIDATE_OPEN") {
      ordinal += 1
      val handlerDef = reject.flatMap(exactHandlerDefinition)
      candidates.println(Seq(
        s"fail-open-$ordinal", file, line, c.id,
        fulfill.map(_.id).getOrElse(-1L), fcode,
        reject.map(_.id).getOrElse(-1L), rcode,
        cl(method.name), cl(method.fullName), cl(c.code), cl(method.code),
        handlerDef.map(_.id).getOrElse(-1L), handlerDef.map(x => cl(x.fullName)).getOrElse(""),
        handlerDef.map(x => cl(x.code)).getOrElse(""),
        if (handlerDef.nonEmpty) "ESTABLISHED_BY_EXACT_REF" else "UNKNOWN",
        "FAIL_OPEN_SECURITY_CONTROL", "UNKNOWN"
      ).mkString("\t"))
    }
  } finally { candidates.close(); audit.close() }
  println(s"FAIL_OPEN_CANDIDATES_COMPLETE: $outDir ($ordinal candidates)")
}
