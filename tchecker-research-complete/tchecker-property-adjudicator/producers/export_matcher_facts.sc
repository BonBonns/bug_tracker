// JS-PROV-DP2 — matcher/predicate semantics for denylist-bypass (domain coverage).
// The security property is set/domain containment, not matcher_kind difference. This
// producer establishes the STRUCTURAL/SEMANTIC attributes the containment judgement
// needs, per check and per consumer, joined by the value they operate on.
//
// matcher_facts.tsv:
//   file, method, role(CHECK|CONSUMER), node, line, matcher_kind, value_code,
//   pattern_code, regex_breadth(ANCHORED_FINITE|BROAD|UNKNOWN|NA),
//   escaped_resolution(INLINE|PRIOR_LOCAL|NONE|NA), normalized_from(src|'')
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s: String) = Option(s).getOrElse("").replace("\n", " ").replace("\t", " ").take(80)
  val w = new java.io.PrintWriter(new java.io.File(s"$outDir/matcher_facts.tsv"), "UTF-8")

  def isEscaper(name: String) = name.matches("(?i).*esc.*|.*escapeRegExp.*|.*quote.*")
  def isNormalizer(name: String) = name.matches("(?i).*norm.*|toLowerCase|toUpperCase|trim")

  // resolve an identifier (Joern lowers /re/ to `_tmp = /re/`) to its assignment RHS
  def resolvePattern(code: String, m: nodes.Method): String = {
    val c = code.trim
    if (c.startsWith("/") || c.contains("RegExp(")) return c
    var rhs = c
    m.ast.isCall.name("<operator>.assignment").foreach { a =>
      val lhs = a.argument.headOption.map(x => Option(x.code).getOrElse("")).getOrElse("").trim
      val r = a.argument.l.lift(1).map(x => Option(x.code).getOrElse("")).getOrElse("")
      if (lhs == c) rhs = r
    }
    rhs
  }
  // regex breadth from a pattern (regex literal /.../ or RegExp("...") string)
  def innerPat(pat: String): String = {
    val p = pat.trim
    if (p.startsWith("/")) p.replaceAll("^/", "").replaceAll("/[a-z]*$", "")
    else if (p.contains("RegExp(")) {
      val m = """RegExp\(\s*"([^"]*)"""".r.findFirstMatchIn(p)
      m.map(_.group(1)).getOrElse("")   // empty when the arg is dynamic (concat/var)
    } else ""
  }
  def breadth(pat: String): String = {
    val inner = innerPat(pat)
    if (inner.isEmpty) return "UNKNOWN"
    if (inner.matches("""\^\(?[A-Za-z0-9|]+\)?\$""")) "ANCHORED_FINITE"  // ^(a|b)$ of literals
    else "BROAD"                                                         // unanchored / metachars
  }
  // value V defined as `V = <normalizer>(SRC)` -> returns SRC, else ""
  def normalizedFrom(value: String, m: nodes.Method): String = {
    var src = ""
    m.ast.isCall.name("<operator>.assignment").foreach { a =>
      val lhs = a.argument.headOption.map(x => Option(x.code).getOrElse("")).getOrElse("").trim
      val rhs = a.argument.l.lift(1).map(x => Option(x.code).getOrElse("")).getOrElse("")
      if (lhs == value.trim && isNormalizer(rhs.replaceAll("\\(.*", ""))) {
        val inner = """\w+\(\s*([A-Za-z0-9_.]+)\s*\)""".r.findFirstMatchIn(rhs)
        src = inner.map(_.group(1)).getOrElse("")
      }
    }
    src
  }
  // does the regex source resolve to an escaper (inline or via a local def)?
  def escapedResolution(pat: String, m: nodes.Method): String = {
    if (pat.matches("""(?s).*\besc\s*\(.*""")) return "INLINE"
    // extract the RegExp(...) argument (quoted string OR identifier)
    val arg = """RegExp\(\s*([^)]*?)\s*\)""".r.findFirstMatchIn(pat).map(_.group(1).trim).getOrElse("")
    val locName = arg.replaceAll("^\"|\"$", "")
    val fromEsc = m.ast.isCall.name("<operator>.assignment").exists { a =>
      val lhs = a.argument.headOption.map(x => Option(x.code).getOrElse("")).getOrElse("").trim
      val rhs = a.argument.l.lift(1).map(x => Option(x.code).getOrElse("")).getOrElse("")
      lhs == locName && rhs.matches("""(?s).*\besc\s*\(.*""")
    }
    if (fromEsc) "PRIOR_LOCAL" else "NONE"
  }

  try {
    cpg.method.isExternal(false).l.foreach { m =>
      // ---- includes/has/indexOf: CHECK iff denylist receiver guarding a reject,
      //      else CONSUMER (mutually exclusive; no double-emit).
      m.ast.isCall.name("includes", "has", "indexOf").l.foreach { c =>
        val recv = c.argument.argumentIndex(0).headOption.map(x => cl(x.code)).getOrElse("")
        val value = c.argument.argumentIndex(1).headOption.map(x => cl(x.code)).getOrElse("")
        val looksDenylist = recv.matches("""[A-Z_]{2,}|.*(bad|deny|danger|black|forbid|BAD).*""")
        val enclIf = c.inAst.collectAll[nodes.ControlStructure].filter(_.controlStructureType == "IF").l.headOption
        val guardsReject = enclIf.exists(ifn =>
          ifn.ast.isReturn.exists(r => Option(r.code).getOrElse("").matches("""return\s*(false|;|$).*""")))
        val role = if (looksDenylist && guardsReject) "CHECK" else "CONSUMER"
        w.println(Seq(cl(m.filename), cl(m.fullName), role, c.id.toString,
          c.lineNumber.map(_.toString).getOrElse(""), "EXACT_KEY", value, recv, "NA", "NA",
          normalizedFrom(value, m)).mkString("\t"))
      }
      m.ast.isCall.name("test", "match").l.foreach { c =>
        val value = c.argument.argumentIndex(1).headOption.orElse(c.argument.argumentIndex(0).headOption)
          .map(x => cl(x.code)).getOrElse("")
        val regexNode = c.argument.argumentIndex(0).headOption
        val patRaw = regexNode.map(x => Option(x.code).getOrElse("")).getOrElse("")
        val pat = resolvePattern(patRaw, m)
        val enclIf = c.inAst.collectAll[nodes.ControlStructure].filter(_.controlStructureType == "IF").l.headOption
        val guardsReject = enclIf.exists { ifn =>
          ifn.ast.isReturn.exists(r => Option(r.code).getOrElse("").matches("""return\s*(false|;|$).*"""))
        }
        val inReturnValue = c.inAst.isReturn.nonEmpty
        val role = if (guardsReject && !inReturnValue) "CHECK" else "CONSUMER"
        val esc = escapedResolution(pat, m)
        w.println(Seq(cl(m.filename), cl(m.fullName), role, c.id.toString,
          c.lineNumber.map(_.toString).getOrElse(""), "REGEX", value, cl(pat),
          breadth(pat), esc, normalizedFrom(value, m)).mkString("\t"))
      }
      // ---- UNKNOWN external matcher: a returned call to a non-builtin callee taking
      //      the checked value -> accepted domain unresolved -> SEMANTICALLY_OPEN.
      m.ast.isReturn.l.foreach { r =>
        r.astChildren.isCall.l.filter { c =>
          !c.name.startsWith("<operator>") &&
          !Set("includes", "has", "indexOf", "test", "match").contains(c.name)
        }.foreach { c =>
          val value = c.argument.argumentIndex(1).headOption.orElse(c.argument.argumentIndex(0).headOption)
            .map(x => cl(x.code)).getOrElse("")
          w.println(Seq(cl(m.filename), cl(m.fullName), "CONSUMER", c.id.toString,
            c.lineNumber.map(_.toString).getOrElse(""), "UNKNOWN", value, cl(c.name),
            "UNKNOWN", "NA", normalizedFrom(value, m)).mkString("\t"))
        }
      }
    }
  } finally w.close()
  println(s"MATCHER_FACTS_COMPLETE: $outDir")
}
