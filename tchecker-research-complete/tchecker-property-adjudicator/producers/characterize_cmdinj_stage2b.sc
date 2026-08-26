// CMDINJ-STAGE2B: ad-hoc character-filter characterization. Deliberately lower-trust than Stage
// 2A -- this is a characterization EXPERIMENT, not trusted sanitizer semantics. The asymmetric
// rule is the whole point: positive allowlisting is easier to prove safe than blacklist
// completeness, so only demonstrated, narrow, fully-anchored allowlists (or genuine finite enums)
// can BREAKS. No blacklist -- however large, however many characters it appears to cover -- is
// ever auto-promoted to BREAKS. "Removed some characters" must never collapse to "safe."
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes

val SAFE_ALLOWLIST_CLASS = """^\^\[([A-Za-z0-9\\_\-]+)\]\+\$$""".r  // ^[...]+$ with only safe chars

def isSafeCharacterClass(innerChars: String): Boolean = {
  // only alphanumeric ranges, underscore, hyphen -- explicitly excludes anything that could admit
  // a shell metacharacter
  innerChars.matches("^[A-Za-z0-9\\\\_\\-]*$")
}
def isFullyAnchoredAllowlist(rawLiteral: String): Boolean = {
  // strip JS regex literal delimiters: /pattern/flags -> pattern
  val stripped = rawLiteral.trim.stripPrefix("/").reverse.dropWhile(_ != '/').drop(1).reverse
  val m = """^\^\[([^\]]*)\]\+\$$""".r.findFirstMatchIn(stripped)
  m.exists(mm => isSafeCharacterClass(mm.group(1)))
}

def extractRegexLiteral(testCall: nodes.Call, method: nodes.Method): Option[String] = {
  val receiver = testCall.argument.l.find(_.argumentIndex == 0)
  receiver.flatMap {
    case id: nodes.Identifier =>
      // receiver is a bare temp identifier (_tmp_0) -- trace back to its defining assignment
      // (_tmp_0 = /regex/) within the same method.
      val assigns = method.ast.isCall.name("<operator>.assignment").l.filter { a =>
        a.argument.l.find(_.argumentIndex == 1).exists(_.code.trim == id.code.trim)
      }
      assigns.flatMap(_.argument.l.find(_.argumentIndex == 2))
        .collectFirst { case lit: nodes.Literal => lit.code }
    case fld: nodes.Call if fld.name == "<operator>.fieldAccess" =>
      val tempAssigns = fld.ast.isCall.name("<operator>.assignment").l
      tempAssigns.flatMap(_.argument.l.find(_.argumentIndex == 2))
        .collectFirst { case lit: nodes.Literal => lit.code }
    case _ => None
  }
}

@main def exec(cpgFile: String, outFile: String) = {
  importCpg(cpgFile)

  case class Row(function: String, classification: String, mechanism: String, note: String)
  val rows = scala.collection.mutable.ListBuffer[Row]()

  def enclosingCall(n: nodes.AstNode): Option[nodes.Call] = {
    var cur: nodes.AstNode = n; var hops = 0
    while (hops < 8) {
      val p = scala.util.Try(cur.astParent).toOption
      p match { case Some(c: nodes.Call) => return Some(c); case Some(null) => return None
                case Some(pp) => cur = pp; hops += 1; case None => return None }
    }
    None
  }

  // resolves a guard condition to its underlying .test() call(s), tracing through an intermediate
  // boolean variable if the condition is a bare identifier (e.g. `const isSafe = re.test(x); if
  // (isSafe) {...}`).
  def resolveTestCalls(cond: nodes.Expression, method: nodes.Method): List[(nodes.Call, Boolean)] = {
    // Boolean = isNegated
    cond match {
      case c: nodes.Call if c.name == "<operator>.logicalNot" =>
        val inner = c.argument.l.find(_.argumentIndex == 1)
        inner.toList.flatMap(i => resolveTestCalls(i.asInstanceOf[nodes.Expression], method).map { case (t, n) => (t, !n) })
      case c: nodes.Call if c.name == "test" => List((c, false))
      case id: nodes.Identifier =>
        val assigns = method.ast.isCall.name("<operator>.assignment").l.filter { a =>
          a.argument.l.find(_.argumentIndex == 1).exists(_.code.trim == id.code.trim)
        }
        assigns.flatMap { a =>
          a.argument.l.find(_.argumentIndex == 2).toList.flatMap(r => resolveTestCalls(r.asInstanceOf[nodes.Expression], method))
        }
      case _ => Nil
    }
  }

  def isFixedEnumChain(cond: nodes.Expression, trackedCode: String): Boolean = cond match {
    case c: nodes.Call if c.name == "<operator>.logicalOr" =>
      val operands = c.argument.l
      operands.forall {
        case eq: nodes.Call if eq.name == "<operator>.equals" =>
          eq.argument.l.exists(_.code.trim == trackedCode) &&
          eq.argument.l.exists(_.isInstanceOf[nodes.Literal])
        case nested: nodes.Call if nested.name == "<operator>.logicalOr" =>
          isFixedEnumChain(nested, trackedCode)
        case _ => false
      }
    case _ => false
  }

  val cases = Seq(
    ("strongAllowlist_anchoredAlnum", "x", "BREAKS"),
    ("strongAllowlist_numericOnly", "x", "BREAKS"),
    ("strongAllowlist_fixedEnum", "x", "BREAKS"),
    ("claimedComprehensiveBlacklist", "x", "UNKNOWN"),
    ("removeSemicolonOnly", "x", "PRESERVES"),
    ("removeAmpersandOnly", "x", "PRESERVES"),
    ("removeThreeMetachars", "x", "PRESERVES"),
    ("singleReplaceNonGlobal", "x", "PRESERVES"),
    ("endsWithCheckOnly", "x", "PRESERVES"),
    ("lengthBoundOnly", "x", "PRESERVES"),
    ("trimAndLowercase", "x", "PRESERVES"),
    ("blacklistDoesNotDominate", "x", "PRESERVES"),
    ("allowlistDominatesSink", "x", "BREAKS")
  )

  cases.foreach { case (fnName, trackedCode, expected) =>
    val m = cpg.method.name(fnName).headOption
    m match {
      case None => rows += Row(fnName, "NO_METHOD_FOUND", "", expected)
      case Some(method) =>
        val ifNodeOpt = method.ast.isControlStructure.filter(_.controlStructureType == "IF").headOption
        val hasReplace = method.ast.isCall.name("replace").nonEmpty
        val hasEndsWithOrLength = method.ast.isCall.name("endsWith").nonEmpty ||
          method.ast.isCall.filter(_.code.contains(".length")).nonEmpty
        val hasTrimOrLower = method.ast.isCall.filter(c => Set("trim","toLowerCase").contains(c.name)).nonEmpty

        ifNodeOpt match {
          case Some(ifNode) =>
            val sinkCall = method.ast.isCall.name("exec").headOption
            val thenBlock = ifNode.astChildren.l.drop(1).headOption
            val sinkInThen = sinkCall.exists(s => thenBlock.exists(_.ast.contains(s)))
            val cond = ifNode.condition.l.headOption
            if (!sinkInThen) {
              rows += Row(fnName, "PRESERVES", "guard-does-not-dominate", expected)
            } else {
              val testCalls = cond.toList.flatMap(c => resolveTestCalls(c, method))
              val fixedEnum = cond.exists(c => isFixedEnumChain(c, trackedCode))
              if (fixedEnum) {
                rows += Row(fnName, "BREAKS", "fixed-enum-comparison-chain", expected)
              } else if (testCalls.nonEmpty) {
                val (testCall, isNegated) = testCalls.head
                val pattern = extractRegexLiteral(testCall, method)
                if (!isNegated) {
                  // allowlist shape: value must MATCH the regex to pass
                  val strong = pattern.exists(isFullyAnchoredAllowlist)
                  if (strong) rows += Row(fnName, "BREAKS", s"anchored-safe-allowlist-regex($pattern)", expected)
                  else rows += Row(fnName, "UNKNOWN", s"allowlist-regex-not-confirmed-restrictive($pattern)", expected)
                } else {
                  // blacklist shape: value must NOT match to pass -- NEVER auto-BREAKS, regardless
                  // of apparent size/effort, per the asymmetric rule
                  rows += Row(fnName, "UNKNOWN", s"blacklist-regex-completeness-not-established($pattern)", expected)
                }
              } else if (hasEndsWithOrLength) {
                rows += Row(fnName, "PRESERVES", "format-or-length-check-not-a-syntax-guard", expected)
              } else {
                rows += Row(fnName, "UNKNOWN", "unrecognized-guard-shape", expected)
              }
            }
          case None =>
            // no IF at all -- classify based on value-transform calls present (replace/trim/etc.)
            val hasIncludesOrTest = method.ast.isCall.filter(c => Set("includes","test").contains(c.name)).nonEmpty
            if (hasReplace) rows += Row(fnName, "PRESERVES", "blacklist-character-removal-known-incomplete", expected)
            else if (hasTrimOrLower) rows += Row(fnName, "PRESERVES", "normalization-only", expected)
            else if (hasIncludesOrTest) rows += Row(fnName, "PRESERVES", "check-present-but-does-not-dominate-sink", expected)
            else rows += Row(fnName, "UNKNOWN", "unrecognized-transform", expected)
        }
    }
  }

  val w = new java.io.PrintWriter(outFile)
  w.println(Seq("function","classification","mechanism","expected").mkString("\t"))
  rows.foreach(r => w.println(Seq(r.function, r.classification, r.mechanism, r.note).mkString("\t")))
  w.close()
  println(s"STAGE2B_COMPLETE rows=${rows.size}")
}
