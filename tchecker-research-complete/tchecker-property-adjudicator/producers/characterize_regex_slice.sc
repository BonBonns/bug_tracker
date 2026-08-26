// PATH-PROV-R01: regex-capture-plus-slice characterization for
// ATTACKER_CONTROL_OF_FILESYSTEM_LOCATION. The regex's ACTUAL ACCEPTED LANGUAGE determines whether
// location-control survives extraction -- regex extraction is not automatically sanitization.
// Classification is based on parsing the regex pattern's LITERAL TEXT for well-defined character-
// class shapes (not full regex-engine semantics, but not a guess either -- verified against
// controlled fixtures, including the exact real RocketChat pattern, before any real-code use).
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

// Character-class classification, based on the pattern's literal text:
//   RESTRICTED_SAFE          -- capture class is tightly bounded to alphanumeric/-/_ only,
//                                no '/', '.', or '\' possible -> BREAKS
//   EXCLUDES_SLASH_ALLOWS_DOT -- capture class explicitly excludes '/' (e.g. [^/?]) but does not
//                                exclude '.' -> genuine middle case, multi-segment traversal
//                                blocked but a single ".." segment can still escape one level ->
//                                UNKNOWN (neither extreme accurately describes the real risk)
//   UNRESTRICTED              -- capture class allows '/' or is unbounded (.+, .*, [^?]+ etc.)
//                                -> PRESERVES
//   INDETERMINATE              -- pattern is not a literal (computed at runtime) -> UNKNOWN
def classifyRegexCapture(patternText: String): String = {
  val restrictedSafe = """\[A-Za-z0-9_\-\]""".r
  val excludesSlashClass = """\[\^[^\]]*/[^\]]*\]""".r  // a negated class [^...] that includes '/' among the excluded chars
  if (restrictedSafe.findFirstIn(patternText).isDefined) {
    "RESTRICTED_SAFE"
  } else if (excludesSlashClass.findFirstIn(patternText).isDefined) {
    // excludes '/' -- but does the SAME negated class also exclude '.'? If the excluded-chars
    // list (inside [^...]) contains a literal '.', dot is ALSO blocked -> effectively restricted
    // further. Otherwise '.' survives -> the genuine middle case.
    val negClassContent = excludesSlashClass.findFirstIn(patternText).get
    if (negClassContent.contains("\\.") || negClassContent.replace("[^","").replace("]","").contains(".")) {
      // dot also excluded from the negated class -- still allows most other chars, but without
      // '/' AND without '.', a ".." escape cannot be formed at all -> effectively safe for
      // traversal-syntax purposes specifically (BREAKS), even though other characters remain free.
      "RESTRICTED_SAFE"
    } else {
      "EXCLUDES_SLASH_ALLOWS_DOT"
    }
  } else {
    "UNRESTRICTED"
  }
}

@main def exec(cpgFile: String, outFile: String) = {
  importCpg(cpgFile)
  implicit val ec: EngineContext = EngineContext()

  case class Row(function: String, effect: String, note: String)
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

  val cases = Seq(
    ("extensionStripOnly", "PRESERVES expected (underlying regex is unrestricted .+ ; extension-strip does not restrict the prefix)"),
    ("restrictedAlnumCapture", "BREAKS expected ([A-Za-z0-9_-]+ -- no traversal chars possible)"),
    ("unrestrictedCapture", "PRESERVES expected (.+ allows everything including '/')"),
    ("excludesSlashAllowsDot", "UNKNOWN expected (REAL RocketChat regex: [^/?]+ -- excludes '/' but allows '.', a genuine bounded-but-real middle case)"),
    ("truncatedToFixedShortLength", "PRESERVES expected (regex unrestricted; truncating to 2 chars still permits '..' exactly)"),
    ("dynamicRegexPattern", "UNKNOWN expected (pattern is a runtime variable, not a literal -- cannot be established)")
  )

  cases.foreach { case (fnName, expected) =>
    val m = cpg.method.name(fnName).headOption
    m match {
      case None => rows += Row(fnName, "NO_METHOD_FOUND", expected)
      case Some(method) =>
        val newRegexCalls = method.ast.isCall.name("<operator>.new").filter(_.code.startsWith("new RegExp(")).l
        if (newRegexCalls.isEmpty) {
          rows += Row(fnName, "INDETERMINATE (no literal RegExp construction found)", expected)
        } else {
          val patternArg = newRegexCalls.head.argument.l.find(_.argumentIndex == 1)
          patternArg match {
            case Some(lit: nodes.Literal) =>
              val patternText = lit.code
              val classification = classifyRegexCapture(patternText)
              val effect = classification match {
                case "RESTRICTED_SAFE" => "BREAKS"
                case "EXCLUDES_SLASH_ALLOWS_DOT" => "UNKNOWN"
                case "UNRESTRICTED" => "PRESERVES"
                case _ => "UNKNOWN"
              }
              rows += Row(fnName, effect + s" (pattern=$patternText, classification=$classification)", expected)
            case _ =>
              rows += Row(fnName, "UNKNOWN (pattern not a literal -- dynamic/computed)", expected)
          }
        }
    }
  }

  val w = new java.io.PrintWriter(outFile)
  w.println(Seq("function","classified_effect","expected").mkString("\t"))
  rows.foreach(r => w.println(Seq(r.function, r.effect, r.note).mkString("\t")))
  w.close()
  println(s"REGEX_SLICE_CHARACTERIZATION_COMPLETE rows=${rows.size}")
}
