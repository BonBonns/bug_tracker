// NPM-INTEG-R01: adds a THIRD source tier -- PACKAGE_API_INPUT_REACHABLE ("does a value from
// this npm package's OWN exported (module.exports/exports/ESM) function parameter reach a
// DANGEROUS-classified regex operation") -- alongside the frozen APPLICATION_INGRESS_REACHABLE
// (Meteor.methods/req.*/message.* -- COPIED VERBATIM from export_redos_integ.sc, UNCHANGED, NOT
// generalized) source model, per direct instruction:
//   "Preserve the RocketChat Meteor.methods/Express model as a separate APPLICATION_INGRESS
//    adapter; don't generalize it into the npm rule."
// The frozen sink-identification (Stage 1) and regex-complexity classification (Stage 2) logic
// below is likewise an UNCHANGED, byte-for-byte copy of export_redos_integ.sc's own -- this
// producer only ADDS a new source-detection pass and runs BOTH source families' reachability
// against the SAME dangerous sinks, tagging each emitted row's own "origin_family" field
// (source_facts.tsv column 4, read as `srcf[0][3]` -> `evidence_final.json`'s own
// `origin.origin_family` by adjudicate_js.py, confirmed by direct inspection -- this field is
// carried through as free text, never interpreted/filtered by adjudicate_js.py itself, so
// repurposing it to distinguish source tiers doesn't change or risk adjudicate_js.py's own
// established behavior) so `redos_verdict.py`'s reducer can classify PACKAGE_API_INPUT_REACHABLE
// vs APPLICATION_INGRESS_REACHABLE independently, reading source_facts.tsv directly (since
// adjudicate_js.py's own evidence_final.json only surfaces the FIRST source row's own
// origin_family per sink -- `srcf[0][3]` -- not every alternative's).
//
// PACKAGE_API_INPUT_REACHABLE's own real, empirically-grounded design (verified against a real
// Joern jssrc2cpg CPG of 7 real fixture files covering every required export shape before this
// code was written -- never guessed):
//   - `module.exports = <MethodRef>` (direct function/arrow/anonymous-function expression --
//     js2cpg resolves this DIRECTLY to a MethodRef, no identifier indirection)
//   - `module.exports = <Identifier>` / `module.exports.NAME = <Identifier>` /
//     `exports.NAME = <Identifier>` -- resolved ONLY when that identifier has EXACTLY ONE prior
//     `identifier = <MethodRef>` assignment in the SAME enclosing scope (a named function
//     declaration or `const foo = () => ...`) -- js2cpg desugars BOTH CommonJS named-function
//     exports (`module.exports.foo = foo`) AND ESM exports (`export function foo(){}` and
//     `export const foo = () => {}` both desugar to `foo = <MethodRef>` + `exports.foo = foo`;
//     `export default function foo(){}` desugars to `foo = <MethodRef>` + `exports["default"] =
//     foo`) into this EXACT SAME shape -- confirmed directly, so no separate ESM-specific code
//     path is needed at all.
//   - `module.exports["NAME"]` / `exports["NAME"]` (indexAccess with a LITERAL string key) --
//     resolved the same as a named fieldAccess export (this is how ESM default exports desugar).
//   - ABSTAINED, never guessed: `module.exports[dynamicExpr]` (indexAccess with a NON-literal
//     key -- confirmed real shape via `module.exports[key] = fn` where `key` is itself a
//     variable); an identifier resolving to a CALL (e.g. `module.exports = require(...)` --
//     confirmed real re-export shape) rather than a MethodRef; an identifier with ZERO or MORE
//     THAN ONE prior MethodRef-assignment (ambiguous); an identifier resolving to a class's own
//     `<init>` (constructor) -- confirmed real shape via `module.exports = SomeClass`, which
//     desugars to `SomeClass = <MethodRef to <init>>` -- the constructor is NOT the class's real
//     public API surface (its other instance methods are), so this shape is explicitly abstained
//     on rather than silently (and wrongly) treating the constructor's own params as the export.
//   - Interprocedural propagation from an exported parameter (through further assignments,
//     argument-passing, returns, and calls into other functions) reuses the SAME real Joern
//     `reachableByFlows` dataflow engine already proven for the frozen APPLICATION_INGRESS
//     source model -- never hand-rolled here. An unresolved/dynamic callee has no real CALL-graph
//     edge for the engine to traverse (confirmed: NaiveCallLinker only creates edges it can
//     actually resolve), so "abstain on ... unproven interprocedural edges" falls out of the
//     engine's own real behavior, not extra code.
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

// ===== Stage 1 (frozen, verbatim copy from export_redos_integ.sc): sink semantics =====
val REGEXP_RECEIVER_METHODS = Set("test", "exec")
val STRING_RECEIVER_METHODS = Set("match", "matchAll", "search", "replace", "replaceAll")
val SOURCE_PATTERN = "(req|request)\\.(body|query|params|headers|payload|url)(\\..*)?"
val MESSAGE_SOURCE_PATTERN = "(message|item)\\.(urls|text|attachments|msg)(\\..*)?"

// ===== Stage 2 (frozen, verbatim copy from export_redos_integ.sc): complexity classification =====
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

  // ===== sink enumeration (frozen, unchanged) =====
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

  // ===== APPLICATION_INGRESS source enumeration (frozen, unchanged from export_redos_integ.sc) =====
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
    if (validIdentifierPattern2.matches(p.name)) {
      p.method.ast.isIdentifier.name(p.name).l.map(id => id: nodes.Expression)
    } else {
      System.err.println(s"  REJECTED non-identifier parameter name (skipped): ${p.name.take(60)}")
      Nil
    }
  }
  val applicationIngressSources: List[nodes.Expression] =
    (sourceCallsFieldAccess.map(c => c: nodes.Expression) ++ ingressParamSources).distinct
  System.err.println(s"[$srcLabel] APPLICATION_INGRESS source candidates: ${applicationIngressSources.size} " +
    s"(field-access: ${sourceCallsFieldAccess.size}, ingress-param refs: ${ingressParamSources.size})")

  // ===== NEW: PACKAGE_API_INPUT source enumeration (npm public-API export surface) =====
  def resolveExportRhs(rhs: nodes.Expression, scopeMethod: nodes.Method): Either[String, nodes.Method] = {
    def methodFromRef(ref: nodes.MethodRef): Either[String, nodes.Method] = {
      cpg.method.fullName(ref.methodFullName).headOption match {
        case Some(m) if m.name == "<init>" => Left("CLASS_CONSTRUCTOR_NOT_PUBLIC_API")
        case Some(m) => Right(m)
        case None => Left("METHODREF_TARGET_NOT_FOUND")
      }
    }
    rhs match {
      case ref: nodes.MethodRef => methodFromRef(ref)
      case id: nodes.Identifier =>
        val candidateAssigns = scopeMethod.ast.isCall.name("<operator>.assignment").l.filter { a =>
          a.argument.l.find(_.argumentIndex == 1).exists {
            case lhsId: nodes.Identifier => lhsId.code.trim == id.code.trim
            case _ => false
          } && a.argument.l.find(_.argumentIndex == 2).exists(_.isInstanceOf[nodes.MethodRef])
        }
        candidateAssigns.size match {
          case 0 => Left("UNRESOLVED_IDENTIFIER_NO_METHODREF_ASSIGNMENT")
          case 1 =>
            candidateAssigns.head.argument.l.find(_.argumentIndex == 2) match {
              case Some(ref: nodes.MethodRef) => methodFromRef(ref)
              case _ => Left("UNRESOLVED_RHS_SHAPE")
            }
          case _ => Left("AMBIGUOUS_IDENTIFIER_MULTIPLE_METHODREF_ASSIGNMENTS")
        }
      case _ => Left("UNRESOLVED_RHS_SHAPE")
    }
  }

  case class ExportedFn(method: nodes.Method, exportName: String)
  val exportedFns = scala.collection.mutable.ListBuffer[ExportedFn]()
  val exportAbstentions = scala.collection.mutable.ListBuffer[(String, String)]()

  val namedExportLhs = "^(module\\.exports|exports)\\.[A-Za-z_$][A-Za-z0-9_$]*$".r
  val exportAssigns = cpg.call.name("<operator>.assignment").l.filter { a =>
    val lhsCode = a.argument.l.find(_.argumentIndex == 1).map(_.code.trim).getOrElse("")
    lhsCode == "module.exports" || namedExportLhs.matches(lhsCode) ||
    a.argument.l.find(_.argumentIndex == 1).exists {
      case c: nodes.Call => c.name == "<operator>.indexAccess" &&
        c.argument.l.find(_.argumentIndex == 1).exists(b => b.code.trim == "module.exports" || b.code.trim == "exports")
      case _ => false
    }
  }
  exportAssigns.foreach { a =>
    val lhsExpr = a.argument.l.find(_.argumentIndex == 1).get
    val rhsExpr = a.argument.l.find(_.argumentIndex == 2).get
    val lhsCode = lhsExpr.code.trim
    val (exportNameOpt, dynamicKey) = lhsExpr match {
      case c: nodes.Call if c.name == "<operator>.indexAccess" =>
        c.argument.l.find(_.argumentIndex == 2) match {
          case Some(lit: nodes.Literal) =>
            val unquoted = lit.code.trim.stripPrefix("\"").stripPrefix("'").stripSuffix("\"").stripSuffix("'")
            (Some(unquoted), false)
          case _ => (None, true)
        }
      case _ if lhsCode == "module.exports" => (Some("module.exports"), false)
      case _ => (Some(lhsCode.split("\\.").last), false)
    }
    if (dynamicKey) {
      exportAbstentions += ((lhsCode, "DYNAMIC_COMPUTED_EXPORT_KEY"))
    } else {
      resolveExportRhs(rhsExpr, a.method) match {
        case Right(m) => exportedFns += ExportedFn(m, exportNameOpt.getOrElse("<unknown>"))
        case Left(reason) => exportAbstentions += ((lhsCode, reason))
      }
    }
  }
  val distinctExportedFns = exportedFns.toList.groupBy(_.method.id).values.map(_.head).toList
  System.err.println(s"[$srcLabel] PACKAGE_API_INPUT exported functions resolved: ${distinctExportedFns.size} " +
    s"(${distinctExportedFns.map(e => s"${e.exportName}@${e.method.name}").mkString(",")})")
  if (exportAbstentions.nonEmpty) {
    System.err.println(s"[$srcLabel] PACKAGE_API_INPUT export ABSTENTIONS (${exportAbstentions.size}): " +
      exportAbstentions.map { case (lhs, reason) => s"$lhs=$reason" }.mkString(" | "))
  }
  val packageApiSources: List[nodes.Expression] = distinctExportedFns.flatMap { e =>
    e.method.parameter.filter(_.name != "this").l.flatMap { p =>
      p.method.ast.isIdentifier.name(p.name).l.map(id => id: nodes.Expression)
    }
  }.distinct
  System.err.println(s"[$srcLabel] PACKAGE_API_INPUT source candidates (exported-param references): ${packageApiSources.size}")

  // ===== combine: does EITHER source family reach a DANGEROUS-pattern sink's input operand? =====
  // Same batched-query performance fix as export_redos_integ.sc (one multi-source
  // reachableByFlows call per sink per source family, never one call per individual source).
  case class OutRow(sinkId: String, sinkLine: Int, srcId: String, srcLine: Int, srcCode: String,
                     originFamily: String, note: String)
  val outRows = scala.collection.mutable.ListBuffer[OutRow]()

  val dangerousSinks = sinkTargets.filter(_.classification == "DANGEROUS")
  System.err.println(s"[$srcLabel] running batched reachability: ${dangerousSinks.size} dangerous sinks x " +
    s"(${packageApiSources.size} PACKAGE_API_INPUT + ${applicationIngressSources.size} APPLICATION_INGRESS) sources")

  def runFamily(family: String, sources: List[nodes.Expression]): Unit = {
    if (sources.isEmpty) return
    dangerousSinks.zipWithIndex.foreach { case (target, idx) =>
      System.err.println(s"[$srcLabel]   [$family] sink ${idx + 1}/${dangerousSinks.size} (L${target.sinkCall.lineNumber.getOrElse(-1)})...")
      val flows = scala.util.Try {
        cpg.all.id(target.inputExpr.id).collectAll[nodes.Expression]
          .reachableByFlows(sources.iterator).l
      }.getOrElse(Nil)
      flows.foreach { f =>
        f.elements.headOption.foreach { origin =>
          outRows += OutRow(target.sinkCall.id.toString, target.sinkCall.lineNumber.getOrElse(-1),
            origin.id.toString, origin.lineNumber.getOrElse(-1), origin.code, family,
            s"pattern=${target.patternText} classification=DANGEROUS (${target.classNote})")
        }
      }
    }
  }
  runFamily("PACKAGE_API_INPUT", packageApiSources)
  runFamily("APPLICATION_INGRESS", applicationIngressSources)

  new java.io.File(rawDir).mkdirs()
  val sf = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/source_facts.tsv", true))
  val pr = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/propagation_relations.tsv", true))
  val po = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/property_outcome.tsv", true))
  val ti = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/transform_identity.tsv", true))
  outRows.foreach { r =>
    // column 4 (originFamily) is a free-text field adjudicate_js.py carries through unchanged
    // into evidence_final.json's own origin.origin_family -- confirmed by direct inspection, see
    // this file's own header comment.
    sf.println(Seq(r.sinkId, r.sinkLine, r.srcId, r.originFamily, "ESTABLISHED", "","","","","","","").mkString("\t"))
    pr.println(Seq(r.sinkId, "", "", r.srcId, r.srcLine, r.srcCode, "", "", "").mkString("\t"))
    po.println(Seq(r.sinkId, r.srcId, "ESTABLISHED", "-1", "-1").mkString("\t"))
    System.err.println(s"[$srcLabel] EMIT sink=${r.sinkId}(L${r.sinkLine}) src=${r.srcId}(L${r.srcLine}:${r.srcCode}) " +
      s"family=${r.originFamily} note=${r.note}")
  }
  sf.close(); pr.close(); po.close(); ti.close()
  System.err.println(s"[$srcLabel] REDOS_NPM_INTEG_COMPLETE rows=${outRows.size} " +
    s"(package_api=${outRows.count(_.originFamily == "PACKAGE_API_INPUT")}, " +
    s"application_ingress=${outRows.count(_.originFamily == "APPLICATION_INGRESS")})")

  // Also emit a summary the reducer can use WITHOUT needing to run adjudicate_js.py at all when
  // there are zero dangerous sinks or zero sources for a package -- real, disclosed, cheap
  // early-exit information, not required for correctness (redos_verdict.py re-derives the same
  // facts from source_facts.tsv directly either way).
  val summary = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/redos_npm_summary.json"))
  summary.println(s"""{"sink_targets": ${sinkTargets.size}, "dangerous_sinks": ${dangerousSinks.size}, """ +
    s""""package_api_sources": ${packageApiSources.size}, "application_ingress_sources": ${applicationIngressSources.size}, """ +
    s""""exported_functions_resolved": ${distinctExportedFns.size}, "export_abstentions": ${exportAbstentions.size}, """ +
    s""""rows_emitted": ${outRows.size}}""")
  summary.close()
}
