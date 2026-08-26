// REDOS-PROP-R01 (Stage 2): complexity/danger classification. Heuristic, pattern-text-based
// analysis -- NOT a full formal regex-safety proof (matching how real ReDoS-detection tooling
// like safe-regex/recheck/eslint-plugin-redos operates: structural heuristics, not exhaustive
// ambiguity proof, since full ReDoS detection is a hard, undecidable-in-general problem). Verified
// against real, empirically-timed ground truth -- not just theoretical pattern-shape reasoning.
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes

val REGEXP_RECEIVER_METHODS = Set("test", "exec")
val STRING_RECEIVER_METHODS = Set("match", "matchAll", "search", "replace", "replaceAll")

// --- classification heuristic ---
// 1. Nested quantifier: a parenthesized group containing its own +/* is itself quantified with
//    +/* -- the classic exponential-blowup shape, e.g. (a+)+
val NESTED_QUANTIFIER = """\([^()]*[+*][^()]*\)[+*]""".r

// 2. Splits the pattern body on TOP-LEVEL '|' (not inside a character class or group) to inspect
//    each alternation branch independently.
def splitTopLevelAlternation(body: String): List[String] = {
  val branches = scala.collection.mutable.ListBuffer[String]()
  val current = new StringBuilder
  var depth = 0
  var inClass = false
  var i = 0
  while (i < body.length) {
    val ch = body(i)
    if (ch == '\\' && i + 1 < body.length) {
      // an escaped character (\|, \(, \), \[, \]) is a LITERAL, never a metacharacter -- confirmed
      // as a real false-positive source against RocketChat's SlackImporter.ts
      // (/<(http[s]?:[^|]*)\|([^>]*)>/g -- the \| was being mis-treated as an alternation
      // operator, splitting the pattern incorrectly and producing a false DANGEROUS flag).
      current += ch; current += body(i + 1); i += 2
    } else {
      if (ch == '[' && !inClass) inClass = true
      else if (ch == ']' && inClass) inClass = false
      else if (ch == '(' && !inClass) depth += 1
      else if (ch == ')' && !inClass) depth -= 1
      if (ch == '|' && depth == 0 && !inClass) { branches += current.toString; current.clear() }
      else current += ch
      i += 1
    }
  }
  branches += current.toString
  branches.toList
}

// a negated character class [^X...] immediately followed by a literal that IS one of the excluded
// characters X cannot consume that literal -- there is no ambiguity in where the quantified
// portion stops, so "quantifier followed by more content" is NOT dangerous in this specific shape.
// Confirmed as a real false-positive source against RocketChat's parseMessageSearchQuery.ts
// ([^"]+" -- the quantified negated class excludes '"', which is exactly what follows it, so the
// match is unambiguous and empirically confirmed safe, not the quadratic blowup the naive rule
// below would suggest).
val NEGATED_CLASS_THEN_EXCLUDED_LITERAL = """\[\^([^\]]+)\][+*](.)""".r
val NEGATED_CLASS_THEN_NEGATED_CLASS = """\[\^[^\]]+\][+*]\[\^[^\]]+\][?+*]?""".r
def isSafeNegatedClassShape(branch: String): Boolean = {
  val literalCase = NEGATED_CLASS_THEN_EXCLUDED_LITERAL.findFirstIn(branch).isDefined &&
    NEGATED_CLASS_THEN_EXCLUDED_LITERAL.findAllMatchIn(branch).forall { m =>
      val excluded = m.group(1)
      val following = m.group(2)
      excluded.contains(following)
    }
  // two consecutive negated classes (e.g. [^\s"]+[^"]?): each independently bounds its own
  // extent by what it excludes -- confirmed as a real false-positive source against RocketChat's
  // parseMessageSearchQuery.ts.
  val consecutiveClassCase = NEGATED_CLASS_THEN_NEGATED_CLASS.findFirstIn(branch).isDefined
  literalCase || consecutiveClassCase

}

// a nested quantifier (a+)+-shaped group is genuinely ambiguous/dangerous ONLY when the quantified
// inner content could itself "absorb" what makes repetitions distinguishable. When the group
// starts with an ESCAPED LITERAL character acting as an unambiguous per-repetition delimiter
// (e.g. \.), and the rest of the group's own quantified portion matches a DIFFERENT character
// class that cannot itself produce that delimiter, repetitions are unambiguous -- confirmed as a
// real false-positive source against RocketChat's UAParserCustom.js
// ((\.\d+)+ -- each repetition is unambiguously delimited by the literal dot, \d+ cannot itself
// produce a dot, so there is exactly one way to parse "1.2.3", not exponentially many; empirically
// confirmed safe even at 100,000 characters).
val DELIMITED_NESTED_GROUP = """\(\\(.)([^()]*)\)[+*]""".r
def isSafePrefixDelimitedNestedQuantifier(text: String): Boolean = {
  DELIMITED_NESTED_GROUP.findAllMatchIn(text).nonEmpty &&
  DELIMITED_NESTED_GROUP.findAllMatchIn(text).forall { m =>
    val delimiterChar = m.group(1)
    val restOfGroup = m.group(2)
    !restOfGroup.contains(delimiterChar)
  }
}
// SUFFIX-delimiter variant: a quantified character class followed by a literal that the class
// itself excludes, e.g. ([A-Z0-9-]+\.)+ -- the literal '.' unambiguously marks where each
// repetition ends, and the character class [A-Z0-9-] cannot itself produce a '.', so there is
// exactly one way to partition a matching string. Structurally the mirror image of the
// prefix-delimiter case above (same safety reasoning, delimiter position flipped). Confirmed
// against RocketChat's real email-validation regex
// (/\b[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,4}\b/i) -- empirically measured as essentially
// linear (0.56ms/0.57ms/1.17ms at 10000/50000/100000 adversarial chars), which the prefix-only
// check incorrectly flagged DANGEROUS since it doesn't match that shape at all.
val SUFFIX_DELIMITED_GROUP = """\(\??:?\[([^\]]+)\][+*]\\(.)\)[+*]""".r
def isSafeSuffixDelimitedNestedQuantifier(text: String): Boolean = {
  SUFFIX_DELIMITED_GROUP.findAllMatchIn(text).nonEmpty &&
  SUFFIX_DELIMITED_GROUP.findAllMatchIn(text).forall { m =>
    val classChars = m.group(1)
    val delimiterChar = m.group(2)
    !classChars.contains(delimiterChar)
  }
}
def isSafeDelimitedNestedQuantifier(text: String): Boolean = {
  isSafePrefixDelimitedNestedQuantifier(text) || isSafeSuffixDelimitedNestedQuantifier(text)
}

// 3. Within a branch, does a quantified portion (+/* on a class or group) have MORE PATTERN
//    CONTENT after it within the same branch (a literal, another construct -- not just an anchor
//    or end-of-branch)? That "quantified-then-more-content" shape is what forces backtracking
//    through every possible quantifier length when the trailing content fails to match --
//    confirmed empirically as the actual mechanism in both real dangerous cases found this session.
//    EXCEPT when the quantified portion is a negated class that excludes what follows it (see
//    isSafeNegatedClassShape above) -- that specific shape is unambiguous and confirmed safe.
def hasQuantifierFollowedByMoreContent(branch: String): Boolean = {
  val quantifierThenContent = """[+*][^$]""".r
  val stripped = branch.stripSuffix("$")
  val hasShape = quantifierThenContent.findFirstIn(stripped).isDefined && !stripped.matches(""".*[+*]$""")
  hasShape && !isSafeNegatedClassShape(stripped)
}

def isFullyAnchoredNoGlobalMultiline(rawLiteral: String): Boolean = {
  val lastSlash = rawLiteral.lastIndexOf('/')
  val flags = if (lastSlash >= 0) rawLiteral.substring(lastSlash + 1) else ""
  val body = rawLiteral.stripPrefix("/").take(math.max(0, lastSlash - 1))
  val noGM = !flags.contains("g") && !flags.contains("m")
  val anchored = body.startsWith("^") && body.endsWith("$")
  noGM && anchored
}

def classifyPattern(rawLiteralOrDynamic: String, isResolved: Boolean): (String, String) = {
  if (!isResolved) return ("UNKNOWN", "pattern not statically resolved -- cannot be analyzed, not guessed")
  val lastSlash = rawLiteralOrDynamic.lastIndexOf('/')
  if (!rawLiteralOrDynamic.startsWith("/") || lastSlash <= 0) {
    return ("UNKNOWN", "pattern text not in recognizable /pattern/flags form")
  }
  val body = rawLiteralOrDynamic.substring(1, lastSlash)
  if (NESTED_QUANTIFIER.findFirstIn(body).isDefined && !isSafeDelimitedNestedQuantifier(body)) {
    return ("DANGEROUS", s"nested quantifier detected (classic exponential-blowup shape): $body")
  }
  val branches = splitTopLevelAlternation(body)
  if (branches.size > 1) {
    val riskyBranches = branches.filter(hasQuantifierFollowedByMoreContent)
    if (riskyBranches.nonEmpty) {
      return ("DANGEROUS", s"alternation branch has a quantifier followed by more content " +
              s"(forces backtracking through every quantifier length on failure): ${riskyBranches.mkString("; ")}")
    }
  }
  if (isFullyAnchoredNoGlobalMultiline(rawLiteralOrDynamic)) {
    return ("SAFE", "fully anchored (^...$), no g/m flags, no nested quantifier, no risky alternation branch")
  }
  ("UNKNOWN", "does not match a recognized SAFE or DANGEROUS shape -- not guessed either way")
}

def resolvePattern(operand: nodes.Expression, method: nodes.Method): (String, String) = operand match {
  case lit: nodes.Literal if lit.code.trim.startsWith("/") => ("DIRECT_LITERAL", lit.code)
  case id: nodes.Identifier =>
    val assigns = method.ast.isCall.name("<operator>.assignment").l.filter { a =>
      a.argument.l.find(_.argumentIndex == 1).exists(_.code.trim == id.code.trim)
    }
    val resolved = assigns.flatMap { a =>
      a.argument.l.find(_.argumentIndex == 2).flatMap {
        case lit: nodes.Literal if lit.code.trim.startsWith("/") => Some(("VARIABLE_TO_LITERAL", lit.code))
        case block if block.code.trim.startsWith("new RegExp(") =>
          val newCall = block.ast.isCall.name("<operator>.new").headOption
          newCall.flatMap(_.argument.l.find(_.argumentIndex == 1)) match {
            case Some(patLit: nodes.Literal) =>
              val inner = patLit.code.stripPrefix("'").stripPrefix("\"").stripSuffix("'").stripSuffix("\"")
              Some(("VARIABLE_TO_NEW_REGEXP_LITERAL", s"/$inner/"))
            case Some(patDynamic) => Some(("VARIABLE_TO_NEW_REGEXP_DYNAMIC", patDynamic.code))
            case None => None
          }
        case _ => None
      }
    }
    resolved.headOption.getOrElse(("UNRESOLVED_IDENTIFIER", id.code))
  case other => ("UNRESOLVED_OTHER", other.code)
}

@main def exec(cpgFile: String, outFile: String) = {
  importCpg(cpgFile)
  case class Row(fn: String, callShape: String, line: Int, patternResolution: String,
                  patternText: String, classification: String, note: String)
  val rows = scala.collection.mutable.ListBuffer[Row]()

  val cases = Seq(
    "knownDangerous_parseMessage", "knownDangerous_autotranslate", "knownSafe_cors",
    "textbookNestedQuantifier", "simpleAnchoredAllowlist", "quantifierAtEndFullyAnchored",
    "unresolvedDynamic", "suffixDelimitedNestedQuantifier"
  )

  cases.foreach { fnName =>
    val m = cpg.method.name(fnName).headOption
    m match {
      case None => rows += Row(fnName, "?", -1, "?", "?", "NO_METHOD_FOUND", "")
      case Some(method) =>
        val call = method.ast.isCall.filter(c => REGEXP_RECEIVER_METHODS.contains(c.name) || STRING_RECEIVER_METHODS.contains(c.name)).headOption
        call match {
          case None => rows += Row(fnName, "?", -1, "?", "?", "NO_CALL_FOUND", "")
          case Some(c) =>
            val patternArg =
              if (REGEXP_RECEIVER_METHODS.contains(c.name)) c.argument.l.find(_.argumentIndex == 0)
              else c.argument.l.find(_.argumentIndex == 1)
            patternArg match {
              case None => rows += Row(fnName, c.name, c.lineNumber.getOrElse(-1), "?", "?", "NO_PATTERN_ARG", "")
              case Some(pat) =>
                val (resKind, resText) = resolvePattern(pat, method)
                val isResolved = resKind != "UNRESOLVED_IDENTIFIER" && resKind != "UNRESOLVED_OTHER" &&
                                  resKind != "VARIABLE_TO_NEW_REGEXP_DYNAMIC"
                val (classification, note) = classifyPattern(resText, isResolved)
                rows += Row(fnName, c.name, c.lineNumber.getOrElse(-1), resKind, resText, classification, note)
            }
        }
    }
  }

  val w = new java.io.PrintWriter(outFile)
  w.println(Seq("function","call_shape","line","pattern_resolution","pattern_text","classification","note").mkString("\t"))
  rows.foreach(r => w.println(Seq(r.fn, r.callShape, r.line, r.patternResolution, r.patternText, r.classification, r.note).mkString("\t")))
  w.close()
  println(s"REDOS_STAGE2_COMPLETE rows=${rows.size}")
}
