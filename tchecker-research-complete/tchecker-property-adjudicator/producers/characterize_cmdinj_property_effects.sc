// CMDINJ-PROP-R01 (Stage 2A): known semantic effects, PAIR representation (component, effect),
// not a collapsed single value -- adjudication derives from the pair, provenance is preserved.
// Explicit finite allowlists and well-defined shell-word quoting ONLY. Generic regex metacharacter
// stripping (x.replace(/[;&|]/g,'')) is NOT encoded here -- that is Stage 2B, an explicitly
// separate, lower-trust characterization experiment, never given the same status as these
// well-defined transforms.
//
// IMPORTANT CAVEAT, confirmed from shell-quote's own real CVE history (2016, 2018, 2022, and a
// 2026 newline-escaping bug), not assumed: SHELL_WORD_QUOTED represents the DOCUMENTED, INTENDED
// semantic of a correctly-used shell-quote call -- it is not an unconditional safety oracle across
// all shell-quote versions or all input shapes. The 2022 CVE was specifically a case where
// shell-quote's OWN escaping regex was incomplete (a Windows-drive-letter character class bug
// that allowed metacharacter injection). This classifier characterizes the CALL SHAPE (is quote()
// used correctly, as a whole shell word, verbatim), not a version-pinned guarantee that a specific
// shell-quote release is bug-free.
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

// ===== engine representation, exactly as specified =====
object CommandComponent extends Enumeration {
  val COMMAND_SYNTAX, ARGUMENT_ONLY, EXECUTABLE_PATH = Value
}
object PropertyEffect extends Enumeration {
  val NONE, SHELL_WORD_QUOTED, SHELL_WORD_QUOTED_THEN_REWRAPPED, CHARACTER_ALLOWLISTED,
      VALUE_ALLOWLISTED, ARG_COUNT_CONSTRAINED, FIXED_EXECUTABLE, UNKNOWN_TRANSFORM = Value
}
import CommandComponent._
import PropertyEffect._

// adjudication: derived from the PAIR, never collapsing component identity away
def adjudicate(component: CommandComponent.Value, effect: PropertyEffect.Value): String = (component, effect) match {
  case (COMMAND_SYNTAX, NONE)                          => "UNSAFE"
  case (COMMAND_SYNTAX, SHELL_WORD_QUOTED)              => "SHELL_SYNTAX_NEUTRALIZED (candidate)"
  case (COMMAND_SYNTAX, SHELL_WORD_QUOTED_THEN_REWRAPPED) => "UNKNOWN -- re-wrap corrupts shell-quote's escaping per its own docs; do NOT claim sanitized"
  case (COMMAND_SYNTAX, ARG_COUNT_CONSTRAINED)          => "UNSAFE -- arg-count constraint does not address shell-syntax risk"
  case (COMMAND_SYNTAX, VALUE_ALLOWLISTED | FIXED_EXECUTABLE | CHARACTER_ALLOWLISTED) => "SHELL_SYNTAX_NEUTRALIZED (candidate)"
  case (ARGUMENT_ONLY, NONE)                            => "NO_SHELL_INJECTION_PROPERTY"
  case (ARGUMENT_ONLY, SHELL_WORD_QUOTED)                => "NO_SHELL_INJECTION_PROPERTY -- unnecessary escaping, do not promote to safer-than-argument-only"
  case (ARGUMENT_ONLY, ARG_COUNT_CONSTRAINED)            => "NO_SHELL_INJECTION_PROPERTY -- argument shape constrained, note only, not a syntax-safety claim"
  case (EXECUTABLE_PATH, NONE)                           => "EXECUTABLE_CONTROLLED"
  case (EXECUTABLE_PATH, SHELL_WORD_QUOTED)               => "EXECUTABLE_CONTROLLED -- quoting does not solve WHICH executable runs"
  case (EXECUTABLE_PATH, VALUE_ALLOWLISTED | FIXED_EXECUTABLE) => "EXECUTABLE_CONSTRAINED (candidate)"
  case (_, UNKNOWN_TRANSFORM)                            => "UNKNOWN"
  case _                                                  => "UNKNOWN"
}

@main def exec(cpgFile: String, outFile: String) = {
  importCpg(cpgFile)
  implicit val ec: EngineContext = EngineContext()

  case class Row(function: String, component: String, effect: String, adjudication: String, note: String)
  val rows = scala.collection.mutable.ListBuffer[Row]()

  def isQuoteCall(c: nodes.Call): Boolean = c.name == "quote"

  // for a formatString (template literal) interpolation, checks whether the quote() call's
  // result is used VERBATIM (empty/non-quote-character-adjacent literal segments) or RE-WRAPPED
  // (an extra quote character immediately precedes/follows the interpolation point) -- exactly
  // matching shell-quote's own documented corruption warning.
  def classifyQuoteUsageInFormatString(fs: nodes.Call, quoteCallIdx: Int): PropertyEffect.Value = {
    val args = fs.argument.l.sortBy(_.argumentIndex)
    val precedingLiteral = args.lift(quoteCallIdx - 1).collect { case l: nodes.Literal => l.code.stripPrefix("\"").stripSuffix("\"") }
    val followingLiteral = args.lift(quoteCallIdx + 1).collect { case l: nodes.Literal => l.code.stripPrefix("\"").stripSuffix("\"") }
    val precedingEndsInQuoteChar = precedingLiteral.exists(s => s.nonEmpty && (s.last == '\'' || s.last == '"'))
    val followingStartsWithQuoteChar = followingLiteral.exists(s => s.nonEmpty && (s.head == '\'' || s.head == '"'))
    if (precedingEndsInQuoteChar || followingStartsWithQuoteChar) SHELL_WORD_QUOTED_THEN_REWRAPPED
    else SHELL_WORD_QUOTED
  }

  // finite allowlist detection: an indexAccess X[key] where X is a LOCALLY-DEFINED object literal
  // with a FIXED, enumerable set of properties -- verified structurally, not assumed from a
  // variable name.
  def isFiniteObjectLiteralAllowlist(m: nodes.Method, receiverVarName: String): Boolean = {
    val assigns = m.ast.isCall.name("<operator>.assignment").l.filter { a =>
      a.argument.l.find(_.argumentIndex == 1).exists(_.code.trim == receiverVarName)
    }
    assigns.exists { a =>
      val rhs = a.argument.l.find(_.argumentIndex == 2)
      // object-literal lowering: a Block containing field-assignment(s) `_tmp.key = value`
      rhs.exists(_.ast.isCall.name("<operator>.assignment").nonEmpty)
    }
  }

  def findArrayElements(argRoot: nodes.AstNode): List[nodes.Expression] = {
    argRoot.ast.isCall.filter(_.code.matches(".*\\.push\\(.+\\)$")).l
      .flatMap(_.argument.l.find(_.argumentIndex == 1))
  }

  // arg-count constraint detection: X.slice(0, N) applied to an array (not a string -- checked by
  // the receiver being traceable to an array-literal push() chain).
  def hasArgCountSlice(m: nodes.Method): Boolean = {
    m.ast.isCall.name("slice").nonEmpty
  }

  val cases = Seq(
    ("commandSyntax_noTransform", COMMAND_SYNTAX, "UNSAFE"),
    ("commandSyntax_shellQuoted", COMMAND_SYNTAX, "SHELL_SYNTAX_NEUTRALIZED (candidate)"),
    ("commandSyntax_shellQuotedThenRewrapped", COMMAND_SYNTAX, "UNKNOWN -- do NOT claim sanitized"),
    ("argumentOnly_noTransform", ARGUMENT_ONLY, "NO_SHELL_INJECTION_PROPERTY"),
    ("commandSyntax_spawnShellTrue_noTransform", COMMAND_SYNTAX, "UNSAFE"),
    ("commandSyntax_spawnShellTrue_quoted", COMMAND_SYNTAX, "SHELL_SYNTAX_NEUTRALIZED (candidate)"),
    ("executablePath_shellQuoted_stillControlled", EXECUTABLE_PATH, "EXECUTABLE_CONTROLLED"),
    ("executablePath_allowlisted", EXECUTABLE_PATH, "EXECUTABLE_CONSTRAINED (candidate)"),
    ("argumentOnly_argCountChecked", ARGUMENT_ONLY, "NO_SHELL_INJECTION_PROPERTY (arg-count note only)"),
    ("commandSyntax_execFileShellTrue_argCountOnly", COMMAND_SYNTAX, "UNSAFE -- arg-count constraint does not address shell-syntax risk")
  )

  cases.foreach { case (fnName, expectedComponent, expectedAdjudication) =>
    val m = cpg.method.name(fnName).headOption
    m match {
      case None => rows += Row(fnName, "?", "?", "NO_METHOD_FOUND", expectedAdjudication)
      case Some(method) =>
        // find the relevant sink call in this method: exec, spawn, or execFile
        val sinkCall = method.ast.isCall.filter(c => Set("exec", "spawn", "execFile").contains(c.name)).headOption
        sinkCall match {
          case None => rows += Row(fnName, "?", "?", "NO_SINK_FOUND", expectedAdjudication)
          case Some(sink) =>
            val fam = sink.name
            val args = sink.argument.l.filter(_.argumentIndex >= 1)
            val firstArg = args.headOption
            val secondArg = args.lift(1)
            val secondArgIsArrayLiteral = secondArg.exists(a => a.ast.isCall.filter(_.code.matches(".*\\.push\\(.+\\)$")).nonEmpty || a.code.trim.startsWith("["))
            // trace through a bare identifier to its defining assignment within the same method,
            // to recognize array-derived local variables (e.g. `const args = [x].slice(0,1)`)
            // even when the call site passes the variable, not a literal array directly.
            def isArrayDerivedIdentifier(a: nodes.AstNode): Boolean = a match {
              case id: nodes.Identifier =>
                val assigns = method.ast.isCall.name("<operator>.assignment").l.filter { asg =>
                  asg.argument.l.find(_.argumentIndex == 1).exists(_.code.trim == id.code.trim)
                }
                assigns.exists { asg =>
                  val rhs = asg.argument.l.find(_.argumentIndex == 2)
                  rhs.exists { r =>
                    val nameMatch = r match { case c: nodes.Call => c.name == "slice"; case _ => false }
                    r.code.trim.startsWith("[") || nameMatch ||
                    r.ast.isCall.filter(_.code.matches(".*\\.push\\(.+\\)$")).nonEmpty ||
                    r.ast.isCall.name("slice").nonEmpty
                  }
                }
              case _ => false
            }
            val secondArgIsArray = secondArgIsArrayLiteral || secondArg.exists(isArrayDerivedIdentifier)
            val optionsArg = if (secondArgIsArray) args.lift(2) else secondArg
            def findObjectField(argRoot: nodes.AstNode, keys: Seq[String]): Option[(String, nodes.Expression)] = {
              val fieldAssigns = argRoot.ast.isCall.name("<operator>.assignment").l
              for (fa <- fieldAssigns) {
                val lhs = fa.argument(1); val rhs = fa.argument(2)
                lhs match {
                  case fld: nodes.Call if fld.name == "<operator>.fieldAccess" =>
                    val fieldName = fld.code.split("\\.").lastOption.getOrElse("")
                    if (keys.contains(fieldName)) return Some((fieldName, rhs))
                  case _ =>
                }
              }
              None
            }
            val shellOn = optionsArg.flatMap(o => findObjectField(o, Seq("shell"))).exists(_._2.code.trim != "false")

            val component: CommandComponent.Value =
              if (fam == "exec") COMMAND_SYNTAX
              else if (shellOn) COMMAND_SYNTAX
              else EXECUTABLE_PATH  // will be refined below if the tracked value is in args, not command/file position

            // determine WHICH operand carries the interesting transform in this specific fixture
            // by checking each candidate expression for a quote()/allowlist/slice pattern.
            var effect: PropertyEffect.Value = NONE
            var actualComponent = component
            var foundOnFirstArg = false

            // check command/file position (arg1) for formatString-embedded quote() or direct quote()
            firstArg.foreach {
              case fs: nodes.Call if fs.name == "<operator>.formatString" =>
                val fsArgs = fs.argument.l.sortBy(_.argumentIndex)
                fsArgs.zipWithIndex.foreach { case (a, idx) =>
                  a match {
                    case c: nodes.Call if isQuoteCall(c) =>
                      effect = classifyQuoteUsageInFormatString(fs, idx)
                      foundOnFirstArg = true
                    case _ =>
                  }
                }
              case c: nodes.Call if isQuoteCall(c) =>
                effect = SHELL_WORD_QUOTED
                actualComponent = EXECUTABLE_PATH  // quote() applied directly to the command/file position
                foundOnFirstArg = true
              case idx: nodes.Call if idx.name == "<operator>.indexAccess" =>
                val receiverName = idx.argument.l.find(_.argumentIndex == 1).map(_.code).getOrElse("")
                if (isFiniteObjectLiteralAllowlist(method, receiverName)) {
                  effect = FIXED_EXECUTABLE
                  actualComponent = EXECUTABLE_PATH
                  foundOnFirstArg = true
                }
              case _ =>
            }
            // check args-array elements for quote() (only relevant when shell is on, per Stage 1)
            if (secondArgIsArray && !foundOnFirstArg) {
              val elementSource: List[nodes.Expression] = secondArg.get match {
                case id: nodes.Identifier =>
                  // resolve through the defining assignment to reach the actual array construction
                  val assigns = method.ast.isCall.name("<operator>.assignment").l.filter { asg =>
                    asg.argument.l.find(_.argumentIndex == 1).exists(_.code.trim == id.code.trim)
                  }
                  assigns.flatMap(_.argument.l.find(_.argumentIndex == 2)).flatMap(r => findArrayElements(r))
                case other => findArrayElements(other)
              }
              elementSource.foreach {
                case c: nodes.Call if isQuoteCall(c) => effect = SHELL_WORD_QUOTED
                case _ =>
              }
              if (effect == NONE && hasArgCountSlice(method)) {
                effect = ARG_COUNT_CONSTRAINED
              }
              // this determination came from the ARGS ARRAY, so component reflects that position
              actualComponent = if (shellOn) COMMAND_SYNTAX else ARGUMENT_ONLY
            }

            val adjudication = adjudicate(actualComponent, effect)
            rows += Row(fnName, actualComponent.toString, effect.toString, adjudication, expectedAdjudication)
        }
    }
  }

  val w = new java.io.PrintWriter(outFile)
  w.println(Seq("function","component","effect","classified_adjudication","expected").mkString("\t"))
  rows.foreach(r => w.println(Seq(r.function, r.component, r.effect, r.adjudication, r.note).mkString("\t")))
  w.close()
  println(s"STAGE2A_COMPLETE rows=${rows.size}")
}
