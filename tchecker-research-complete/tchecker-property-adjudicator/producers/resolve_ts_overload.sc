// TS-OVERLOAD-R01: resolves a call that lands on a body-less TypeScript overload SIGNATURE
// declaration to its single concrete implementation, using ONLY structural signals:
//   - same source file
//   - same overload family (grouped by jssrc2cpg's own base-name-plus-optional-numeric-suffix
//     naming convention -- this grouping step is NOT the part under scrutiny; jssrc2cpg itself
//     uses this convention to disambiguate colliding declarations, so it is a legitimate way to
//     find CANDIDATE family members, not a guess about which one is real)
//   - signature compatibility proxy: same parameter count (excluding `this`)
//   - exactly one family member has a non-empty body (bodyChildCount > 0)
// If zero or more than one candidate has a body, or the family-grouping is ambiguous, the resolver
// ABSTAINS (returns None) -- it never guesses which numbered sibling is "probably" the real one,
// and never assumes the unsuffixed or highest-suffixed name is privileged (confirmed necessary:
// the fixture and the real RocketChat case have OPPOSITE assignments of which name is real).
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes

def bodyChildCount(m: nodes.Method): Int =
  m.block.astChildren.filterNot(_.isInstanceOf[nodes.MethodParameterIn]).size

def stripTrailingDigits(name: String): String = name.reverse.dropWhile(_.isDigit).reverse

def resolveOverloadImplementation(callSite: nodes.Call): Either[String, nodes.Method] = {
  val calleeOpt = callSite.callee.headOption
  calleeOpt match {
    case None => Left("no resolved callee at all")
    case Some(callee) =>
      if (bodyChildCount(callee) > 0) {
        Right(callee)  // already resolves to a real implementation -- no redirect needed
      } else {
        val baseName = stripTrailingDigits(callee.name)
        val paramCount = callee.parameter.filterNot(_.name == "this").size
        val candidates = cpg.method.filter { m =>
          m.filename == callee.filename &&
          stripTrailingDigits(m.name) == baseName &&
          m.parameter.filterNot(_.name == "this").size == paramCount
        }.l
        val withBody = candidates.filter(bodyChildCount(_) > 0)
        if (withBody.size == 1) Right(withBody.head)
        else if (withBody.isEmpty) Left(s"resolved callee '${callee.name}' has no body, and no same-family " +
          s"sibling (same file, base name '$baseName', $paramCount params) has one either -- abstain")
        else Left(s"resolved callee '${callee.name}' has no body, and ${withBody.size} same-family siblings " +
          s"have bodies (ambiguous, multiple concrete implementations) -- abstain, do not guess")
      }
  }
}

@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  println("=== every call site in the file, resolution result ===")
  cpg.call.filter(c => c.callee.nonEmpty).l.foreach { c =>
    resolveOverloadImplementation(c) match {
      case Right(m) => println(s"line=${c.lineNumber.getOrElse(-1)} call=${c.code.take(40)} -> RESOLVED to ${m.name} (line ${m.lineNumber.getOrElse(-1)}, body=${bodyChildCount(m)} stmts)")
      case Left(reason) => println(s"line=${c.lineNumber.getOrElse(-1)} call=${c.code.take(40)} -> ABSTAIN: $reason")
    }
  }
}
