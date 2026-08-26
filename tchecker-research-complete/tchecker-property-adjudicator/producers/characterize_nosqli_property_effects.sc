// NOSQLI-PROP-R01 (Stage 2): property-effects classifier for
// ATTACKER_CONTROL_OF_QUERY_OPERATOR_STRUCTURE. Built from the ground up around this property's
// actual defense mechanism (type constraint, not content constraint) -- NOT adapted from any
// prior property's rule set. The one genuine asymmetry-breaker specific to this property: because
// JavaScript's typeof has a CLOSED, finite output set, BOTH `typeof x === 'string'` (positive) and
// `typeof x !== 'object'` (negative, excluding the one dangerous type) are structurally COMPLETE
// guards -- unlike command injection's open-ended shell-metacharacter space, where only positive
// allowlists could be trusted. Explicit key/character blocklists remain untrustworthy regardless
// of apparent thoroughness, grounded in RocketChat's own disclosed bypass (a field-name blocklist
// that never checked the VALUE's type, defeated via $where).
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes

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

  // is this comparison a genuine, COMPLETE typeof-based guard for THIS property specifically --
  // typeof(tracked) === 'string' (positive) or typeof(tracked) !== 'object' (negative, excluding
  // the one dangerous type)? Deliberately narrow: other typeof comparisons (checking for
  // 'number', 'boolean', excluding 'function'/'symbol') are NOT complete guards against
  // object-based operator injection specifically, and must not be credited as BREAKS.
  def isCompleteTypeofGuard(cmp: nodes.Call, trackedCode: String): Boolean = {
    val operands = cmp.argument.l
    val typeofOperand = operands.collectFirst {
      case c: nodes.Call if c.name == "<operator>.instanceOf" => c
    }
    val literalOperand = operands.collectFirst { case l: nodes.Literal => l.code.trim }
    (typeofOperand, literalOperand) match {
      case (Some(t), Some(lit)) =>
        val checksTrackedValue = t.argument.l.exists(_.code.trim == trackedCode)
        val litUnquoted = lit.stripPrefix("'").stripSuffix("'").stripPrefix("\"").stripSuffix("\"")
        val isPositiveString = cmp.name == "<operator>.equals" && litUnquoted == "string"
        val isNegativeObject = cmp.name == "<operator>.notEquals" && litUnquoted == "object"
        checksTrackedValue && (isPositiveString || isNegativeObject)
      case _ => false
    }
  }

  def sinkIsGuardedByTypeCheck(sinkCall: nodes.Call, trackedCode: String): Option[String] = {
    var cur: nodes.AstNode = sinkCall
    var hops = 0
    while (hops < 12) {
      val parentOpt = scala.util.Try(cur.astParent).toOption
      parentOpt match {
        case Some(ifNode: nodes.ControlStructure) if ifNode.controlStructureType == "IF" =>
          val thenBlock = ifNode.astChildren.l.drop(1).headOption
          val isInThen = thenBlock.exists(_.ast.contains(sinkCall))
          if (isInThen) {
            val cond = ifNode.condition.l.headOption
            val genuine = cond.toList.flatMap(_.ast.isCall.filter(c =>
              Set("<operator>.equals", "<operator>.notEquals").contains(c.name)).l)
              .find(isCompleteTypeofGuard(_, trackedCode))
            genuine.foreach(c => return Some(s"typeof guard: ${c.code}"))
          }
          cur = ifNode
        case Some(null) => return None
        case Some(p) => cur = p
        case None => return None
      }
      hops += 1
    }
    None
  }

  // statement-order dominance for Meteor.check(value, String) -- a DIFFERENT mechanism from
  // if-block guard dominance: check() throws synchronously on type mismatch, so its mere presence
  // as an EARLIER statement in the same straight-line method body is sufficient (v1 syntactic
  // approximation: earlier in AST/statement order within the same block, not full CFG dominance --
  // same documented limitation as every guard-dominance check elsewhere in this project).
  def hasMeteorCheckStringBefore(method: nodes.Method, sinkCall: nodes.Call, trackedCode: String): Boolean = {
    val checkCalls = method.ast.isCall.name("check").l.filter { c =>
      val args = c.argument.l.sortBy(_.argumentIndex)
      args.lift(1).exists(_.code.trim == trackedCode) &&
      args.lift(2).exists(_.code.trim == "String")
    }
    checkCalls.exists(_.lineNumber.getOrElse(Int.MaxValue) < sinkCall.lineNumber.getOrElse(0))
  }

  // string coercion: String(x) directly, OR x appears as an interpolated segment of a template
  // literal (formatString) -- both force genuine string conversion regardless of x's original type.
  def hasStringCoercion(method: nodes.Method, valueExpr: nodes.Expression, trackedCode: String): Boolean = {
    valueExpr match {
      case c: nodes.Call if c.name == "String" =>
        c.argument.l.exists(_.code.trim == trackedCode)
      case c: nodes.Call if c.name == "<operator>.formatString" =>
        c.argument.l.exists(_.code.trim == trackedCode)
      case _ => false
    }
  }

  val cases = Seq(
    ("noGuard", "userInput", "PRESERVES"),
    ("typeofStringPositiveDominates", "userInput", "BREAKS"),
    ("typeofStringPositiveDoesNotDominate", "userInput", "PRESERVES"),
    ("typeofObjectNegativeDominates", "userInput", "BREAKS"),
    ("stringCoercion", "userInput", "BREAKS"),
    ("templateLiteralCoercion", "userInput", "BREAKS"),
    ("meteorCheckString", "userInput", "BREAKS"),
    ("incompleteFieldBlocklist", "userInput", "PRESERVES"),
    ("incompleteArrayOnlyCheck", "userInput", "PRESERVES")
  )

  cases.foreach { case (fnName, trackedCode, expected) =>
    val m = cpg.method.name(fnName).headOption
    m match {
      case None => rows += Row(fnName, "NO_METHOD_FOUND", "", expected)
      case Some(method) =>
        val sinkCall = method.ast.isCall.name("findOne").headOption
        sinkCall match {
          case None => rows += Row(fnName, "NO_SINK_FOUND", "", expected)
          case Some(sink) =>
            // find the value operand: the RHS of the field-assignment inside the selector object
            val fieldAssign = sink.argument.l.find(_.argumentIndex == 1).flatMap { selectorArg =>
              selectorArg.ast.isCall.name("<operator>.assignment").l.find { a =>
                a.argument.l.find(_.argumentIndex == 2).exists(_.code.contains(trackedCode))
              }
            }
            val valueExpr = fieldAssign.flatMap(_.argument.l.find(_.argumentIndex == 2))
              .map(_.asInstanceOf[nodes.Expression])

            val typeGuard = sinkIsGuardedByTypeCheck(sink, trackedCode)
            val checkGuard = hasMeteorCheckStringBefore(method, sink, trackedCode)
            val coercion = valueExpr.exists(hasStringCoercion(method, _, trackedCode))

            (typeGuard, checkGuard, coercion) match {
              case (Some(reason), _, _) => rows += Row(fnName, "BREAKS", reason, expected)
              case (_, true, _) => rows += Row(fnName, "BREAKS", "Meteor.check(value, String) precedes sink", expected)
              case (_, _, true) => rows += Row(fnName, "BREAKS", "string coercion (String()/template literal)", expected)
              case (None, false, false) =>
                // check for a guard that exists but doesn't dominate, or a non-type-based
                // blocklist -- both correctly PRESERVE (never guessed as BREAKS)
                val hasIncludesCheck = method.ast.isCall.name("includes").nonEmpty
                val hasArrayCheck = method.ast.isCall.name("isArray").nonEmpty
                val hasTypeofSomewhere = method.ast.isCall.name("<operator>.instanceOf").nonEmpty
                val note = if (hasIncludesCheck) "field/character blocklist present but does not check value type -- not a complete guard"
                           else if (hasArrayCheck) "Array.isArray() check present but does not exclude plain objects -- incomplete type check"
                           else if (hasTypeofSomewhere) "typeof check present but does not dominate the sink"
                           else "no recognized guard"
                rows += Row(fnName, "PRESERVES", note, expected)
            }
        }
    }
  }

  val w = new java.io.PrintWriter(outFile)
  w.println(Seq("function","classification","mechanism","expected").mkString("\t"))
  rows.foreach(r => w.println(Seq(r.function, r.classification, r.mechanism, r.note).mkString("\t")))
  w.close()
  println(s"NOSQLI_STAGE2_COMPLETE rows=${rows.size}")
}
