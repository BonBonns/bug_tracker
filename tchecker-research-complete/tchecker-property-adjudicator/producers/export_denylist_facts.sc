// JS-PROV-DP1 — denylist / pattern matcher-kind mismatch fact producer.
//
// Models the root cause of the Forminator forminator_allowed_mime_types() +
// wp_check_filetype() bypass in JS/TS: a security DENYLIST removes dangerous
// tokens by EXACT match, but the surviving tokens are later used as PATTERNS
// (regex alternation), so a token pattern-equivalent to a forbidden one but not
// string-equal (`ph(p)` vs `php`) slips through.
//
// Fact files (separate, opt-in -- R33 rule):
//   denylist_guards.tsv  file, method, line, match_kind, denylist_code,
//                        normalizes_key
//       match_kind in {EXACT, NORMALIZED}. EXACT = includes/has/===/indexOf on
//       the raw key. NORMALIZED = the key is passed through a metachar-stripping
//       transform before the membership test.
//   pattern_consumers.tsv  file, method, line, token_code, escaped
//       a RegExp built from (or a .test/.match using) a per-key token. escaped
//       is true iff the token is wrapped in an escape/normalize call inside the
//       pattern.
//   collection_flow.tsv  file, caller_method, filter_callee, consumer_callee
//       a function that calls a denylist-filter and passes its result into a
//       pattern-consumer (structural link between the two halves).
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s: String) = Option(s).getOrElse("").replace("\n", " ").replace("\t", " ").take(180)
  def w(n: String) = new java.io.PrintWriter(new java.io.File(s"$outDir/$n"), "UTF-8")

  // metachar-stripping / normalization transforms
  val normNames = Set("stripMeta", "normalize", "sanitize")
  def isEscaper(name: String): Boolean =
    name.toLowerCase.contains("escape") || normNames.contains(name)
  // A replace(...) that targets regex metacharacters is a normalizer too.
  def isMetaReplace(c: nodes.Call): Boolean =
    c.name == "replace" && Option(c.code).getOrElse("").matches("""(?s).*\[[^\]]*[()|*?].*""")

  // ---- denylist_guards.tsv -------------------------------------------------
  // Exact-membership tests against a token list used to remove/skip entries.
  val dg = w("denylist_guards.tsv")
  try cpg.method.isExternal(false).l.foreach { m =>
    m.call.l.foreach { c =>
      val exactMember = (c.name == "includes" || c.name == "has" || c.name == "indexOf")
      if (exactMember) {
        val code = Option(c.code).getOrElse("")
        // receiver looks like a denylist (UPPER_SNAKE const or *deny*/*danger*/*black*/*filters*)
        val recv = c.argument.l.find(_.argumentIndex == 0).map(a => Option(a.code).getOrElse("")).getOrElse("")
        val looksDeny = recv.matches("""[A-Z_][A-Z0-9_]*""") ||
          recv.toLowerCase.matches(""".*(deny|danger|block|forbidden|filter|banned).*""")
        // the KEY being tested: the call's first real argument
        val keyArg = c.argument.l.find(_.argumentIndex == 1)
        val keyCode = keyArg.map(a => Option(a.code).getOrElse("")).getOrElse("")
        // NORMALIZED if the key passes through an escaper/metachar-replace
        val keyNormalized =
          keyArg.exists {
            case call: nodes.Call => isEscaper(call.name) || isMetaReplace(call) ||
              call.ast.isCall.l.exists(cc => isEscaper(cc.name) || isMetaReplace(cc))
            case _ => false
          }
        if (looksDeny) {
          val kind = if (keyNormalized) "NORMALIZED" else "EXACT"
          dg.println(Seq(cl(m.filename), cl(m.fullName),
            c.lineNumber.map(_.toString).getOrElse(""), kind, cl(code),
            keyNormalized.toString).mkString("\t"))
        }
      }
    }
  } finally dg.close()

  // ---- pattern_consumers.tsv ----------------------------------------------
  // RegExp(...) built from a per-key token, or .test/.match with such a regex.
  val pc = w("pattern_consumers.tsv")
  try cpg.method.isExternal(false).l.foreach { m =>
    // locals in this method assigned from an escaper / metachar-replace, so an
    // interpolated `${esc}` counts as escaped even when normalized a line above.
    val normalizedLocals: Set[String] =
      m.assignment.l.flatMap { a =>
        val lhs = a.argument.l.find(_.argumentIndex == 1).collect {
          case i: nodes.Identifier => i.name
        }
        val rhsNorm = a.argument.l.find(_.argumentIndex == 2).exists {
          case call: nodes.Call => isEscaper(call.name) || isMetaReplace(call) ||
            call.ast.isCall.l.exists(cc => isEscaper(cc.name) || isMetaReplace(cc))
          case _ => false
        }
        if (rhsNorm) lhs else None
      }.toSet
    m.call.l.foreach { c =>
      val code = Option(c.code).getOrElse("")
      val isRegexBuild = code.contains("new RegExp") || c.name == "RegExp"
      if (isRegexBuild) {
        val inlineEsc = c.ast.isCall.l.exists(cc => isEscaper(cc.name) || isMetaReplace(cc)) ||
          code.matches("""(?s).*escape\w*\(.*""") || code.matches("""(?s).*\bstripMeta\(.*""")
        // interpolated identifier that is a normalized local?
        val interpEsc = normalizedLocals.exists(n =>
          code.matches(s"""(?s).*\\$$\\{\\s*${java.util.regex.Pattern.quote(n)}\\s*\\}.*"""))
        val escaped = inlineEsc || interpEsc
        pc.println(Seq(cl(m.filename), cl(m.fullName),
          c.lineNumber.map(_.toString).getOrElse(""), cl(code), escaped.toString).mkString("\t"))
      }
    }
  } finally pc.close()

  // ---- collection_flow.tsv -------------------------------------------------
  // A method that calls a filter (returns a collection) and passes it into a
  // consumer. We record (caller, filter_callee, consumer_callee) when a call's
  // argument is itself a call -- `consumer(filter(...))` -- or when a local
  // assigned from the filter is later passed to the consumer.
  val cf = w("collection_flow.tsv")
  def calleeName(c: nodes.Call): String = {
    val n = c.name
    if (n.startsWith("<operator>")) "" else n
  }
  try cpg.method.isExternal(false).l.foreach { m =>
    val calls = m.call.l.filter(c => !c.name.startsWith("<operator>"))
    // direct nesting: consumer(filter(...))
    calls.foreach { outer =>
      outer.argument.l.collect { case inner: nodes.Call if !inner.name.startsWith("<operator>") => inner }
        .foreach { inner =>
          cf.println(Seq(cl(m.filename), cl(m.fullName), cl(calleeName(inner)),
            cl(calleeName(outer)), "NESTED").mkString("\t"))
        }
    }
    // local-mediated: `x = filter(...); consumer(x)` -- link filter and any
    // consumer in the same method (over-approx; the verdict tightens by name).
    val filterCallees = calls.filter(c => c.name.toLowerCase.matches(""".*(allow|filter|mime|sanitiz).*""")).map(calleeName).distinct
    val consumerCallees = calls.filter(c => c.name.toLowerCase.matches(""".*(check|valid|match|test).*""")).map(calleeName).distinct
    for (fc <- filterCallees; cc <- consumerCallees if fc.nonEmpty && cc.nonEmpty && fc != cc) {
      cf.println(Seq(cl(m.filename), cl(m.fullName), cl(fc), cl(cc), "SAME_METHOD").mkString("\t"))
    }
  } finally cf.close()

  println(s"DP1_FACTS_COMPLETE: $outDir")
}
