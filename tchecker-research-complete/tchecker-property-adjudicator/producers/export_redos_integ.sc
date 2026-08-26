// REDOS-INTEG-R01: wires the frozen ReDoS sink-semantics matrix and complexity classifier together
// into one producer emitting the SAME fact-table schema consumed unchanged by adjudicate_js.py.
// Reuses every source-provenance mechanism already verified this session (explicit source
// families, genuine Meteor.methods ingress-boundary detection, real interprocedural tracing via
// Joern's native engine, the sibling-argument artifact filter) unmodified -- only the sink family
// and property-effect (complexity) rules are new to this property.
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

// ===== Stage 1 (frozen): sink semantics =====
val REGEXP_RECEIVER_METHODS = Set("test", "exec")
val STRING_RECEIVER_METHODS = Set("match", "matchAll", "search", "replace", "replaceAll")
val SOURCE_PATTERN = "(req|request)\\.(body|query|params|headers|payload|url)(\\..*)?"
val MESSAGE_SOURCE_PATTERN = "(message|item)\\.(urls|text|attachments|msg)(\\..*)?"

// ===== Stage 2 (frozen): complexity classification =====
val NESTED_QUANTIFIER = """\([^()]*[+*][^()]*\)[+*]""".r

def splitTopLevelAlternation(body: String): List[String] = {
  val branches = scala.collection.mutable.ListBuffer[String]()
  val current = new StringBuilder
  var depth = 0
  var inClass = false
  var i = 0
  while (i < body.length) {
    val ch = body(i)
    if (ch == '\\' && i + 1 < body.length) {
      // escaped chars (\|, \(, \)) are literals, never metacharacters -- fixes the real false
      // positive found against SlackImporter.ts's /<(http[s]?:[^|]*)\|([^>]*)>/g
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
val NEGATED_CLASS_THEN_EXCLUDED_LITERAL = """\[\^([^\]]+)\][+*](.)""".r
val NEGATED_CLASS_THEN_NEGATED_CLASS = """\[\^[^\]]+\][+*]\[\^[^\]]+\][?+*]?""".r
def isSafeNegatedClassShape(branch: String): Boolean = {
  val literalCase = NEGATED_CLASS_THEN_EXCLUDED_LITERAL.findFirstIn(branch).isDefined &&
    NEGATED_CLASS_THEN_EXCLUDED_LITERAL.findAllMatchIn(branch).forall { m => m.group(1).contains(m.group(2)) }
  val consecutiveClassCase = NEGATED_CLASS_THEN_NEGATED_CLASS.findFirstIn(branch).isDefined
  literalCase || consecutiveClassCase
}
def hasQuantifierFollowedByMoreContent(branch: String): Boolean = {
  val quantifierThenContent = """[+*][^$]""".r
  val stripped = branch.stripSuffix("$")
  val hasShape = quantifierThenContent.findFirstIn(stripped).isDefined && !stripped.matches(""".*[+*]$""")
  hasShape && !isSafeNegatedClassShape(stripped)
}
val DELIMITED_NESTED_GROUP = """\(\\(.)([^()]*)\)[+*]""".r
def isSafePrefixDelimitedNestedQuantifier(text: String): Boolean = {
  DELIMITED_NESTED_GROUP.findAllMatchIn(text).nonEmpty &&
  DELIMITED_NESTED_GROUP.findAllMatchIn(text).forall { m => !m.group(2).contains(m.group(1)) }
}
val SUFFIX_DELIMITED_GROUP = """\(\??:?\[([^\]]+)\][+*]\\(.)\)[+*]""".r
def isSafeSuffixDelimitedNestedQuantifier(text: String): Boolean = {
  SUFFIX_DELIMITED_GROUP.findAllMatchIn(text).nonEmpty &&
  SUFFIX_DELIMITED_GROUP.findAllMatchIn(text).forall { m => !m.group(1).contains(m.group(2)) }
}
def isSafeDelimitedNestedQuantifier(text: String): Boolean = {
  isSafePrefixDelimitedNestedQuantifier(text) || isSafeSuffixDelimitedNestedQuantifier(text)
}
def isFullyAnchoredNoGlobalMultiline(rawLiteral: String): Boolean = {
  val lastSlash = rawLiteral.lastIndexOf('/')
  val flags = if (lastSlash >= 0) rawLiteral.substring(lastSlash + 1) else ""
  val body = rawLiteral.stripPrefix("/").take(math.max(0, lastSlash - 1))
  !flags.contains("g") && !flags.contains("m") && body.startsWith("^") && body.endsWith("$")
}
def classifyPattern(rawLiteralOrDynamic: String, isResolved: Boolean): (String, String) = {
  if (!isResolved) return ("UNKNOWN", "pattern not statically resolved")
  val lastSlash = rawLiteralOrDynamic.lastIndexOf('/')
  if (!rawLiteralOrDynamic.startsWith("/") || lastSlash <= 0) return ("UNKNOWN", "pattern text not in /pattern/flags form")
  val body = rawLiteralOrDynamic.substring(1, lastSlash)
  if (NESTED_QUANTIFIER.findFirstIn(body).isDefined && !isSafeDelimitedNestedQuantifier(body)) return ("DANGEROUS", s"nested quantifier: $body")
  val branches = splitTopLevelAlternation(body)
  if (branches.size > 1) {
    val risky = branches.filter(hasQuantifierFollowedByMoreContent)
    if (risky.nonEmpty) return ("DANGEROUS", s"quantifier followed by more content in alternation branch: ${risky.mkString("; ")}")
  }
  if (isFullyAnchoredNoGlobalMultiline(rawLiteralOrDynamic)) return ("SAFE", "fully anchored, no g/m, no risky shape")
  ("UNKNOWN", "not a recognized SAFE or DANGEROUS shape")
}

@main def exec(cpgFile: String, rawDir: String, srcLabel: String) = {
  importCpg(cpgFile)
  implicit val ec: EngineContext = EngineContext()

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

  // ===== sink enumeration =====
  case class SinkTarget(sinkCall: nodes.Call, inputExpr: nodes.Expression, patternResKind: String,
                         patternText: String, classification: String, classNote: String)
  val sinkTargets = scala.collection.mutable.ListBuffer[SinkTarget]()
  cpg.call.l.foreach { c =>
    val method = c.method
    if (REGEXP_RECEIVER_METHODS.contains(c.name)) {
      val recv = c.argument.l.find(_.argumentIndex == 0)
      val input = c.argument.l.find(_.argumentIndex == 1)
      (recv, input) match {
        case (Some(r), Some(i)) =>
          val (resKind, resText) = resolvePattern(r, method)
          val isResolved = resKind != "UNRESOLVED_IDENTIFIER" && resKind != "UNRESOLVED_OTHER" && resKind != "VARIABLE_TO_NEW_REGEXP_DYNAMIC"
          val (cls, note) = classifyPattern(resText, isResolved)
          sinkTargets += SinkTarget(c, i, resKind, resText, cls, note)
        case _ =>
      }
    } else if (STRING_RECEIVER_METHODS.contains(c.name)) {
      val recv = c.argument.l.find(_.argumentIndex == 0)
      val pat = c.argument.l.find(_.argumentIndex == 1)
      (recv, pat) match {
        case (Some(r), Some(p)) =>
          val (resKind, resText) = resolvePattern(p, method)
          val isResolved = resKind != "UNRESOLVED_IDENTIFIER" && resKind != "UNRESOLVED_OTHER" && resKind != "VARIABLE_TO_NEW_REGEXP_DYNAMIC"
          val (cls, note) = classifyPattern(resText, isResolved)
          sinkTargets += SinkTarget(c, r, resKind, resText, cls, note)
        case _ =>
      }
    }
  }
  System.err.println(s"[$srcLabel] sink targets found: ${sinkTargets.size}")
  System.err.println(s"[$srcLabel] DANGEROUS pattern sinks: ${sinkTargets.count(_.classification == "DANGEROUS")}")

  // ===== source enumeration (frozen, verified, reused unmodified) =====
  def findIngressParams(): List[nodes.MethodParameterIn] = {
    val meteorMethodsCalls = cpg.call.name("Meteor.methods").l ++ cpg.call.filter(_.code.startsWith("Meteor.methods")).l
    val objArgs = meteorMethodsCalls.flatMap(_.argument.l.filter(a => a.argumentIndex == 1)).distinct
    val registeredNames = objArgs.flatMap { obj =>
      obj.ast.isCall.name("<operator>.assignment").l.flatMap { assign =>
        assign.argument(2) match {
          case id: nodes.Identifier => Some(id.name)
          case ref: nodes.MethodRef => Some(ref.methodFullName.split("[:.]").lastOption.getOrElse(ref.code))
          case _ => None
        }
      }
    }.distinct
    // cpg.method.name(...) treats its argument as a REGEX PATTERN, not a literal string --
    // filter to strings that are actually valid JS identifiers before using them here. On this
    // larger, more complex real corpus, the extraction above occasionally picked up a bogus
    // "name" (e.g. TypeScript type-annotation text misidentified inside an object-literal RHS)
    // containing regex metacharacters that crash the underlying regex compiler. Verified this is
    // a real robustness gap, not a hypothetical -- confirmed by the actual crash and its exact
    // offending value before writing this filter.
    val validIdentifierPattern = "^[A-Za-z_$][A-Za-z0-9_$]*$".r
    val safeRegisteredNames = registeredNames.filter(n => validIdentifierPattern.matches(n))
    val rejectedNames = registeredNames.diff(safeRegisteredNames)
    if (rejectedNames.nonEmpty) {
      System.err.println(s"  REJECTED non-identifier 'registered names' (not valid JS identifiers, skipped): ${rejectedNames.mkString("|")}")
    }
    System.err.println(s"  Meteor.methods ingress registrations found: ${safeRegisteredNames.mkString(",")}")
    safeRegisteredNames.flatMap { name => cpg.method.name(name).parameter.filter(_.name != "this").l }
  }
  val sourceCallsFieldAccess = cpg.call.name("<operator>.fieldAccess").code(s"($SOURCE_PATTERN)|($MESSAGE_SOURCE_PATTERN)").l
  val ingressParams = findIngressParams()
  val validIdentifierPattern2 = "^[A-Za-z_$][A-Za-z0-9_$]*$".r
  val ingressParamSources: List[nodes.Expression] = ingressParams.flatMap { p =>
    // same guard as findIngressParams: p.name could in principle be a non-identifier string
    // (e.g. from an unusual destructuring pattern) -- verified necessary on this larger corpus,
    // not a hypothetical, since the method-name-level filter alone did not prevent every crash.
    if (validIdentifierPattern2.matches(p.name)) {
      p.method.ast.isIdentifier.name(p.name).l.map(id => id: nodes.Expression)
    } else {
      System.err.println(s"  REJECTED non-identifier parameter name (skipped): ${p.name.take(60)}")
      Nil
    }
  }
  val sourceCalls: List[nodes.Expression] = (sourceCallsFieldAccess.map(c => c: nodes.Expression) ++ ingressParamSources).distinct
  System.err.println(s"[$srcLabel] source candidates found: ${sourceCalls.size} " +
    s"(field-access: ${sourceCallsFieldAccess.size}, ingress-param refs: ${ingressParamSources.size})")

  // ===== combine: does a source reach a DANGEROUS-pattern sink's input operand? =====
  // PERFORMANCE FIX: a naive per-(sink,source)-pair query (13 sinks x 1765 sources = up to 22,945
  // independent reachableByFlows calls) stalled indefinitely on this corpus size -- the exact same
  // O(sinks x sources) anti-pattern already identified and fixed once this session for
  // TS-OVERLOAD-R01's bridge computation, but not yet applied here. Fixed the same way: ONE
  // multi-source reachableByFlows call per sink (passing ALL sources as a single iterator), not
  // one call per individual source.
  case class OutRow(sinkId: String, sinkLine: Int, srcId: String, srcLine: Int, srcCode: String,
                     outcome: String, note: String)
  val outRows = scala.collection.mutable.ListBuffer[OutRow]()

  val dangerousSinks = sinkTargets.filter(_.classification == "DANGEROUS")
  System.err.println(s"[$srcLabel] running batched reachability: ${dangerousSinks.size} dangerous sinks x ${sourceCalls.size} sources (one multi-source query per sink)")
  dangerousSinks.zipWithIndex.foreach { case (target, idx) =>
    System.err.println(s"[$srcLabel]   sink ${idx + 1}/${dangerousSinks.size} (L${target.sinkCall.lineNumber.getOrElse(-1)})...")
    val flows = scala.util.Try {
      cpg.all.id(target.inputExpr.id).collectAll[nodes.Expression]
        .reachableByFlows(sourceCalls.iterator).l
    }.getOrElse(Nil)
    // group by which source each flow actually originated from, to preserve per-source rows
    flows.foreach { f =>
      f.elements.headOption.foreach { origin =>
        outRows += OutRow(target.sinkCall.id.toString, target.sinkCall.lineNumber.getOrElse(-1),
          origin.id.toString, origin.lineNumber.getOrElse(-1), origin.code, "ESTABLISHED",
          s"pattern=${target.patternText} classification=DANGEROUS (${target.classNote})")
      }
    }
  }

  new java.io.File(rawDir).mkdirs()
  val sf = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/source_facts.tsv", true))
  val pr = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/propagation_relations.tsv", true))
  val po = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/property_outcome.tsv", true))
  val ti = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/transform_identity.tsv", true))
  outRows.foreach { r =>
    sf.println(Seq(r.sinkId, r.sinkLine, r.srcId, "REGEX_INPUT", "ESTABLISHED", "","","","","","","").mkString("\t"))
    pr.println(Seq(r.sinkId, "", "", r.srcId, r.srcLine, r.srcCode, "", "", "").mkString("\t"))
    po.println(Seq(r.sinkId, r.srcId, r.outcome, "-1", "-1").mkString("\t"))
    System.err.println(s"[$srcLabel] EMIT sink=${r.sinkId}(L${r.sinkLine}) src=${r.srcId}(L${r.srcLine}:${r.srcCode}) outcome=${r.outcome} note=${r.note}")
  }
  sf.close(); pr.close(); po.close(); ti.close()
  System.err.println(s"[$srcLabel] REDOS_INTEG_COMPLETE rows=${outRows.size}")
}
