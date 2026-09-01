// NPM-INTEG-R02: extends export_redos_npm_integ.sc (R01, FROZEN, never modified -- that file is
// left byte-for-byte untouched; this is a NEW, separate file) with the 4 real source/dataflow
// capabilities scoped by audit/R02_DECISION.md's "Decision 1: R02 source/dataflow scope":
//   1. Exported class instance-method recognition (velociradix's `export { Context }` shape).
//   2. Object-literal shorthand export recognition (`module.exports = { foo, bar }`,
//      fuse-napi's `lib/macfuse.js` shape).
//   3. Constructor parameter -> exact `this.field` identity -> method-use propagation
//      (velociradix's `Context.graphql()` reading `this.req.body`).
//   4. Cross-method/closure resolution using LEXICAL/CAPTURE identity, not identifier-name
//      matching (ssh2's `RE_HEADER`, mariasql's `RE_PARAM`).
// plus (5, cross-cutting, not a separate capability) explicit, distinctly-labeled abstention for
// every shadowing/reassignment/ambiguity case each of 1-4 introduces -- never a guess.
//
// Per direct instruction, the STAGE 1 SINK-IDENTIFICATION LOOP (REGEXP_RECEIVER_METHODS/
// STRING_RECEIVER_METHODS/SOURCE_PATTERN/MESSAGE_SOURCE_PATTERN, the `cpg.call.l.foreach` sink
// enumeration itself) and ALL of STAGE 2 (`classifyPattern`, `NESTED_QUANTIFIER`, and every helper
// it calls) below are copied VERBATIM, byte-for-byte, from export_redos_npm_integ.sc and are NEVER
// modified anywhere in this file -- this is the frozen "classifier core" per direct instruction
// ("no classifier-core changes"). The one Stage-1 HELPER FUNCTION explicitly named as extendable
// by capability 4's own instruction text ("this capability is about extending resolvePattern, or
// an export-adjacent equivalent, not resolveExportRhs") -- `resolvePattern`, the per-sink
// identifier-to-literal resolution helper, textually adjacent to Stage 1 but NOT itself part of
// the frozen shape-classification rules -- is intentionally renamed `resolvePatternR02` here and
// extended with cross-scope (lexical/closure) resolution; `classifyPattern` itself, which it feeds,
// is never touched. The frozen APPLICATION_INGRESS source model (Meteor.methods/req.*/message.*)
// is likewise copied verbatim, unchanged, exactly as R01 itself copied it from export_redos_integ.sc.
//
// Every new resolution path below was verified against a REAL Joern jssrc2cpg CPG of the fixtures
// in study/redos_npm/r02_fixtures/src/ BEFORE this code was written (never guessed) -- see
// study/redos_npm/pilot25/audit/R02_IMPLEMENTATION.md for the real probe output quoted verbatim.
// Real, empirically-confirmed shapes this file relies on:
//   - `export { Context }` desugars to EXACTLY the same `Context = <MethodRef to <init>>` +
//     `exports.Context = Context` shape as `module.exports = SomeClass` -- confirmed directly, no
//     separate ESM-specific code path needed (same as R01's own finding for plain function exports).
//   - `m.typeDecl` (for any Method, including `<init>`) navigates DIRECTLY to the owning class's
//     TypeDecl node; `td.method.l` lists every method the class owns (constructor included).
//   - `module.exports = { foo, bar }` desugars to an assignment whose RHS is a `Block` containing
//     (in order) a `Local` temp, one `<operator>.assignment` Call PER property
//     (`_tmp.foo = foo`, LHS a `<operator>.fieldAccess` with a `FieldIdentifier` naming the
//     property, RHS the property's value expression) as DIRECT children of that Block, then a
//     trailing Identifier referencing the temp. `{ [computedKey]: foo }` desugars identically
//     EXCEPT the per-property assignment's LHS is `<operator>.indexAccess` with a non-literal key
//     argument -- confirmed real, distinct from the already-handled top-level dynamic export key.
//   - `this.req = req` (inside a constructor) desugars to an `<operator>.assignment` whose LHS
//     (`this.req`) is an `<operator>.fieldAccess` Call with argument(1) = Identifier("this") and
//     argument(2) = FieldIdentifier("req"), and whose RHS is a plain Identifier when the value is
//     an exact, untransformed reference to a parameter -- a Call (e.g. `transform(req)`) or a
//     Binary/other expression when it is NOT an exact identity, confirmed real via a fixture that
//     exercises both shapes. A LATER, separate `this.req = ...` assignment anywhere else in the
//     class's own methods is a second real, independent assignment Call node to the same field.
//   - `method.astParent`, for a Method that is itself a named/anonymous function declared inside
//     another function's body, resolves DIRECTLY to that ENCLOSING Method node (confirmed real,
//     not merely a Block or other AST wrapper) -- walking it repeatedly is a real, correct lexical
//     (not call-graph, not name-matching) scope-nesting walk; a top-level `:program` Method's own
//     `astParent` is a TypeDecl (real, confirmed base case terminating the walk). Scoping an
//     identifier-assignment search to `a.method.fullName == currentLevelMethod.fullName` at each
//     step (rather than the frozen `resolvePattern`'s unscoped `method.ast...` search, which
//     because `.ast` itself descends into nested-closure subtrees would otherwise silently pick up
//     a DIFFERENT, unrelated inner closure's own same-named declaration) is what makes the walk
//     correctly per-scope rather than accidentally-transitive -- confirmed real via a
//     two-independent-closures fixture (see study/redos_npm/r02_fixtures/src/closure_cross_scope.js).
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

@main def exec(cpgFile: String, rawDir: String, srcLabel: String) = {
  importCpg(cpgFile)
  implicit val ec: EngineContext = EngineContext()

  // ===== Stage 1 (frozen, verbatim copy from export_redos_npm_integ.sc): sink semantics =====
  val REGEXP_RECEIVER_METHODS = Set("test", "exec")
  val STRING_RECEIVER_METHODS = Set("match", "matchAll", "search", "replace", "replaceAll")
  val SOURCE_PATTERN = "(req|request)\\.(body|query|params|headers|payload|url)(\\..*)?"
  val MESSAGE_SOURCE_PATTERN = "(message|item)\\.(urls|text|attachments|msg)(\\..*)?"

  // ===== Stage 2 (frozen, verbatim copy from export_redos_npm_integ.sc): complexity classification =====
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

  // ===== NEW (capability 4): resolvePatternR02 -- extends the frozen resolvePattern's identifier
  // resolution with a real LEXICAL/CAPTURE scope walk (method.astParent chain), never
  // identifier-name matching across unrelated methods. At EACH scope level, the assignment search
  // is strictly scoped to that level's OWN Method (`a.method.fullName == levelMethod.fullName`) --
  // NOT `levelMethod.ast` unscoped, because `.ast` itself descends into nested-closure subtrees and
  // would otherwise silently pick up an unrelated inner closure's own same-named declaration
  // (confirmed real risk, not hypothetical -- see closure_cross_scope.js). More than one live
  // assignment to the same identifier at a single scope level is a genuine reassignment/ambiguity
  // and aborts the walk (abstain), never guessing which one is "the real" binding; the search never
  // continues past an ambiguous level to another candidate.
  val patternAbstentions = scala.collection.mutable.ListBuffer[(String, String)]()

  def resolvePatternR02(operand: nodes.Expression, method: nodes.Method): (String, String) = operand match {
    case lit: nodes.Literal if lit.code.trim.startsWith("/") => ("DIRECT_LITERAL", lit.code)
    case id: nodes.Identifier =>
      def extractFromAssign(a: nodes.Call): Option[(String, String)] = {
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
      def searchLevel(levelMethod: nodes.Method): Either[String, (String, String)] = {
        val assigns = levelMethod.ast.isCall.name("<operator>.assignment").l.filter { a =>
          a.method.fullName == levelMethod.fullName &&
          a.argument.l.find(_.argumentIndex == 1).exists {
            case lhsId: nodes.Identifier => lhsId.code.trim == id.code.trim
            case _ => false
          }
        }
        assigns.size match {
          case 0 => Left("NONE_AT_LEVEL")
          case 1 => extractFromAssign(assigns.head) match {
            case Some(r) => Right(r)
            case None => Left("UNRESOLVED_RHS_SHAPE_AT_LEVEL")
          }
          case _ => Left("MULTIPLE_LIVE_ASSIGNMENTS_TO_IDENTIFIER")
        }
      }
      def walkUp(levelMethod: nodes.Method, depth: Int): Either[String, (String, String)] = {
        if (depth > 64) Left("AMBIGUOUS_CLOSURE_BINDING_SCOPE_DEPTH_EXCEEDED")
        else searchLevel(levelMethod) match {
          case Right(r) => Right(r)
          case Left("NONE_AT_LEVEL") =>
            levelMethod.astParent match {
              case parentMethod: nodes.Method => walkUp(parentMethod, depth + 1)
              case _ => Left("UNRESOLVED_IDENTIFIER_NO_ENCLOSING_SCOPE_BINDING")
            }
          case Left(other) => Left(other)
        }
      }
      walkUp(method, 0) match {
        case Right(r) => r
        case Left(reason) =>
          patternAbstentions += ((id.code, reason))
          ("UNRESOLVED_IDENTIFIER", id.code)
      }
    case other => ("UNRESOLVED_OTHER", other.code)
  }

  // ===== sink enumeration (frozen, unchanged from export_redos_npm_integ.sc -- the enumeration
  // loop itself is byte-for-byte identical; only the identifier-resolution HELPER it calls is the
  // new resolvePatternR02 in place of the frozen resolvePattern, per capability 4's own explicit
  // instruction to extend that helper) =====
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
          val (resKind, resText) = resolvePatternR02(r, method)
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
          val (resKind, resText) = resolvePatternR02(p, method)
          val isResolved = resKind != "UNRESOLVED_IDENTIFIER" && resKind != "UNRESOLVED_OTHER" && resKind != "VARIABLE_TO_NEW_REGEXP_DYNAMIC"
          val (cls, note) = classifyPattern(resText, isResolved)
          sinkTargets += SinkTarget(c, r, resKind, resText, cls, note)
        case _ =>
      }
    }
  }
  System.err.println(s"[$srcLabel] sink targets found: ${sinkTargets.size}")
  System.err.println(s"[$srcLabel] DANGEROUS pattern sinks: ${sinkTargets.count(_.classification == "DANGEROUS")}")
  if (patternAbstentions.nonEmpty) {
    System.err.println(s"[$srcLabel] resolvePatternR02 ABSTENTIONS (${patternAbstentions.size}): " +
      patternAbstentions.map { case (name, reason) => s"$name=$reason" }.mkString(" | "))
  }

  // ===== APPLICATION_INGRESS source enumeration (frozen, unchanged from export_redos_npm_integ.sc) =====
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

  // ===== NEW: PACKAGE_API_INPUT source enumeration (npm public-API export surface), extended
  // with capabilities 1, 2, 3 and their capability-5 abstentions. `resolveExportRhs`'s bare-
  // MethodRef and single-prior-assignment identifier resolution (the R01 logic) is preserved
  // exactly; the class-constructor case is extended (rather than only abstaining) to also surface
  // the class's own OTHER instance methods, and a new Block-shaped RHS case handles object-literal
  // shorthand exports. =====
  sealed trait ExportResolution
  case class SingleFunction(m: nodes.Method) extends ExportResolution
  case class ClassExport(td: nodes.TypeDecl) extends ExportResolution

  val exportAbstentions = scala.collection.mutable.ListBuffer[(String, String)]()

  def resolveExportRhs(rhs: nodes.Expression, scopeMethod: nodes.Method): Either[String, ExportResolution] = {
    def methodFromRef(ref: nodes.MethodRef): Either[String, ExportResolution] = {
      val candidates = cpg.method.fullName(ref.methodFullName).l
      candidates match {
        case Nil => Left("METHODREF_TARGET_NOT_FOUND")
        case m :: Nil if m.name == "<init>" =>
          // Capability 1: a class's own constructor is still NOT itself the public API surface
          // (CLASS_CONSTRUCTOR_NOT_PUBLIC_API, unchanged framing from R01) -- but the class's
          // OTHER instance methods now become recognized sources via ClassExport, below.
          val tds = m.typeDecl.l
          tds match {
            case td :: Nil =>
              // capability-5 defensive check: more than one <init> owned by the same TypeDecl
              // would mean "the" constructor isn't uniquely determined -- abstain rather than
              // picking one. (Realistic ambiguity for a genuinely reassigned/shadowed exported
              // identifier is caught earlier, in the Identifier branch below, by the existing
              // AMBIGUOUS_IDENTIFIER_MULTIPLE_METHODREF_ASSIGNMENTS path -- reused unchanged.)
              if (td.method.name("<init>").l.size > 1) Left("MULTIPLE_CANDIDATE_CONSTRUCTORS")
              else Right(ClassExport(td))
            case Nil => Left("CLASS_CONSTRUCTOR_NOT_PUBLIC_API")
            case _ => Left("MULTIPLE_CANDIDATE_CONSTRUCTORS")
          }
        case m :: Nil => Right(SingleFunction(m))
        case _ => Left("MULTIPLE_CANDIDATE_CONSTRUCTORS")
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
      case blk: nodes.Block =>
        // Capability 2: object-literal shorthand export, `module.exports = { foo, bar }` (and
        // `{ foo: renamedFoo }`) -- confirmed real shape: RHS is a Block whose direct children
        // include one `<operator>.assignment` Call PER property. Each property is resolved via
        // the SAME single-prior-assignment rules above (recursing into resolveExportRhs), never
        // guessed. Handled at the object-literal-export call site below (needs to emit MULTIPLE
        // ExportedFn entries, one per property) rather than here, which returns exactly one
        // ExportResolution -- so this case is intentionally NOT matched here; see
        // `resolveObjectLiteralExport` below, invoked directly by the export-assignment loop.
        Left("UNRESOLVED_RHS_SHAPE")
      case _ => Left("UNRESOLVED_RHS_SHAPE")
    }
  }

  // Capability 2 (continued): resolves an object-literal-shorthand export Block into a list of
  // (propertyName, ExportResolution) pairs, or an abstention reason per unresolved property.
  // Abstains (capability 5) on any property whose value is not resolvable by the exact same rules
  // resolveExportRhs already uses, and on a COMPUTED property key (`{ [computedKey]: fn }`) --
  // confirmed real, distinct shape from the top-level `module.exports[computedExpr]` dynamic key
  // (DYNAMIC_COMPUTED_EXPORT_KEY, unchanged) already handled by R01.
  def resolveObjectLiteralExport(blk: nodes.Block, scopeMethod: nodes.Method): List[(String, Either[String, ExportResolution])] = {
    val propAssigns = blk.astChildren.isCall.name("<operator>.assignment").l
    propAssigns.map { pa =>
      val lhs = pa.argument.l.find(_.argumentIndex == 1)
      val rhsOpt = pa.argument.l.find(_.argumentIndex == 2)
      lhs match {
        case Some(c: nodes.Call) if c.name == "<operator>.fieldAccess" =>
          val propName = c.argument.l.find(_.argumentIndex == 2) match {
            case Some(fi: nodes.FieldIdentifier) => fi.canonicalName
            case Some(other) => other.code
            case None => "<unknown-property>"
          }
          rhsOpt match {
            case Some(rhs) => (propName, resolveExportRhs(rhs, scopeMethod))
            case None => (propName, Left("UNRESOLVED_RHS_SHAPE"))
          }
        case Some(c: nodes.Call) if c.name == "<operator>.indexAccess" =>
          ("<computed-property>", Left("COMPUTED_OBJECT_LITERAL_PROPERTY_KEY"))
        case _ =>
          ("<unknown-property>", Left("UNRESOLVED_RHS_SHAPE"))
      }
    }
  }

  case class ExportedFn(method: nodes.Method, exportName: String)
  val exportedFns = scala.collection.mutable.ListBuffer[ExportedFn]()
  val exportedClasses = scala.collection.mutable.ListBuffer[(nodes.TypeDecl, String)]()

  def registerResolution(exportName: String, res: ExportResolution): Unit = res match {
    case SingleFunction(m) => exportedFns += ExportedFn(m, exportName)
    case ClassExport(td) =>
      exportedClasses += ((td, exportName))
      td.method.filterNot(_.name == "<init>").l.foreach { m =>
        exportedFns += ExportedFn(m, s"$exportName.prototype.${m.name}")
      }
  }

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
      val exportName = exportNameOpt.getOrElse("<unknown>")
      rhsExpr match {
        case blk: nodes.Block =>
          // Capability 2: object-literal shorthand export.
          val results = resolveObjectLiteralExport(blk, a.method)
          if (results.isEmpty) {
            exportAbstentions += ((lhsCode, "UNRESOLVED_RHS_SHAPE"))
          } else {
            results.foreach {
              case (propName, Right(res)) => registerResolution(propName, res)
              case (propName, Left(reason)) => exportAbstentions += ((s"$lhsCode.$propName", reason))
            }
          }
        case _ =>
          resolveExportRhs(rhsExpr, a.method) match {
            case Right(res) => registerResolution(exportName, res)
            case Left(reason) => exportAbstentions += ((lhsCode, reason))
          }
      }
    }
  }
  val distinctExportedFns = exportedFns.toList.groupBy(_.method.id).values.map(_.head).toList
  System.err.println(s"[$srcLabel] PACKAGE_API_INPUT exported functions resolved: ${distinctExportedFns.size} " +
    s"(${distinctExportedFns.map(e => s"${e.exportName}@${e.method.name}").mkString(",")})")
  System.err.println(s"[$srcLabel] PACKAGE_API_INPUT exported classes resolved: ${exportedClasses.size} " +
    s"(${exportedClasses.map { case (td, n) => s"$n=${td.name}" }.mkString(",")})")
  if (exportAbstentions.nonEmpty) {
    System.err.println(s"[$srcLabel] PACKAGE_API_INPUT export ABSTENTIONS (${exportAbstentions.size}): " +
      exportAbstentions.map { case (lhs, reason) => s"$lhs=$reason" }.mkString(" | "))
  }

  // Parameter-to-source enumeration (R01 base case, unchanged: `this` still excluded here since a
  // constructor's `this` is never a caller-supplied argument -- capability 3 below adds a
  // SEPARATE, narrower `this.field` source path, not a relaxation of this filter).
  val packageApiParamSources: List[nodes.Expression] = distinctExportedFns.flatMap { e =>
    e.method.parameter.filter(_.name != "this").l.flatMap { p =>
      p.method.ast.isIdentifier.name(p.name).l.map(id => id: nodes.Expression)
    }
  }.distinct
  System.err.println(s"[$srcLabel] PACKAGE_API_INPUT source candidates (exported-param references): ${packageApiParamSources.size}")

  // ===== Capability 3: constructor parameter -> exact this.field identity -> method-use
  // propagation. For every exported class (capability 1), find every `this.FIELD = <rhs>`
  // assignment across ALL of the class's own methods. Abstain (capability 5) if a field is
  // assigned more than once anywhere in the class (REASSIGNED_THIS_FIELD -- generalizes the
  // "do not resolve to the FIRST or ANY assignment if there is more than one live candidate"
  // discipline to instance fields), if the single assignment does not live inside the
  // constructor (`<init>`) itself (NON_CONSTRUCTOR_THIS_FIELD_ASSIGNMENT), or if its RHS is not
  // EXACTLY an Identifier naming one of the constructor's own parameters
  // (COMPUTED_THIS_FIELD_ASSIGNMENT -- covers both a transformed value like `param + 1` and a
  // call like `someFunc(param)`). Only a field that survives ALL of these checks contributes
  // `this.FIELD` read-site expressions (found in the class's OTHER instance methods) to the
  // PACKAGE_API_INPUT source list, fed into the SAME reachableByFlows engine as every other
  // source -- no separate taint mechanism.
  val thisFieldAbstentions = scala.collection.mutable.ListBuffer[(String, String)]()
  val thisFieldSources = scala.collection.mutable.ListBuffer[nodes.Expression]()

  // Real, direct CPG evidence (see R02_IMPLEMENTATION.md): this Joern version's reachableByFlows
  // does NOT propagate from a sub-expression to a compound parent expression built directly on
  // top of it (confirmed: even a bare exported-parameter Identifier `x` does not reach `x.foo` --
  // a real, pre-existing limitation of the WHOLE R01 base design, not introduced here; R01 itself
  // worked around exactly this for its own APPLICATION_INGRESS model by matching the full
  // compound `req.body`-shaped expression AS the source directly, via SOURCE_PATTERN/
  // MESSAGE_SOURCE_PATTERN regex on the expression's own code, rather than relying on flow-through
  // from a bare `req` identifier). Capability 3 has no fixed vocabulary of field names to match a
  // regex against (the field name is whatever the constructor's own parameter was assigned to),
  // so the equivalent fix here is structural: walk the field-access chain built on top of the
  // resolved `this.FIELD` node (e.g. `this.req` -> `this.req.body` -> ...) within the SAME
  // containing method, adding every level as its own source -- never guessing which level a real
  // sink will consume, just like R01 already special-cases whichever `req.*`/`message.*` shape
  // literally appears in the source.
  def collectFieldAccessChain(base: nodes.Expression, container: nodes.Method): List[nodes.Expression] = {
    val parents = container.ast.isCall.l.filter { c =>
      (c.name == "<operator>.fieldAccess" || c.name == "<operator>.indexAccess") &&
      c.argument.l.find(_.argumentIndex == 1).exists(_.id == base.id)
    }
    base :: parents.flatMap(p => collectFieldAccessChain(p: nodes.Expression, container))
  }

  def findThisFieldAssigns(td: nodes.TypeDecl): List[(String, nodes.Method, nodes.Call)] = {
    td.method.l.flatMap { m =>
      m.ast.isCall.name("<operator>.assignment").l.flatMap { a =>
        a.argument.l.find(_.argumentIndex == 1) match {
          case Some(fa: nodes.Call) if fa.name == "<operator>.fieldAccess" =>
            val recvIsThis = fa.argument.l.find(_.argumentIndex == 1).exists {
              case idn: nodes.Identifier => idn.code.trim == "this"
              case _ => false
            }
            val fieldNameOpt = fa.argument.l.find(_.argumentIndex == 2) match {
              case Some(fi: nodes.FieldIdentifier) => Some(fi.canonicalName)
              case _ => None
            }
            if (recvIsThis) fieldNameOpt.map(fn => (fn, m, a)) else None
          case _ => None
        }
      }
    }
  }

  exportedClasses.toList.groupBy(_._1.fullName).values.map(_.head).foreach { case (td, exportName) =>
    val ctorOpt = td.method.name("<init>").l match {
      case c :: Nil => Some(c)
      case Nil => None
      case _ => None // MULTIPLE_CANDIDATE_CONSTRUCTORS already abstained above; nothing to do here
    }
    ctorOpt.foreach { ctor =>
      val ctorParamNames = ctor.parameter.filter(_.name != "this").name.toSet
      val allFieldAssigns = findThisFieldAssigns(td)
      val byField = allFieldAssigns.groupBy(_._1)
      byField.foreach { case (fieldName, sites) =>
        if (sites.size > 1) {
          thisFieldAbstentions += ((s"$exportName.this.$fieldName", "REASSIGNED_THIS_FIELD"))
        } else {
          val (_, ownerMethod, assignCall) = sites.head
          if (ownerMethod.fullName != ctor.fullName) {
            thisFieldAbstentions += ((s"$exportName.this.$fieldName", "NON_CONSTRUCTOR_THIS_FIELD_ASSIGNMENT"))
          } else {
            assignCall.argument.l.find(_.argumentIndex == 2) match {
              case Some(rhsId: nodes.Identifier) if ctorParamNames.contains(rhsId.name) =>
                // capability-5: the constructor parameter itself must not be reassigned within
                // the constructor before this point -- otherwise its "exact identity" is not
                // sound either. Reuses the same multiple-live-assignment discipline.
                val paramReassigns = ctor.ast.isCall.name("<operator>.assignment").l.filter { a2 =>
                  a2.method.fullName == ctor.fullName &&
                  a2.argument.l.find(_.argumentIndex == 1).exists {
                    case lhsId: nodes.Identifier => lhsId.name == rhsId.name
                    case _ => false
                  }
                }
                if (paramReassigns.size > 1) {
                  thisFieldAbstentions += ((s"$exportName.this.$fieldName", "MULTIPLE_LIVE_ASSIGNMENTS_TO_IDENTIFIER"))
                } else {
                  // EXACT identity confirmed: find reads of this.FIELD in the class's OTHER
                  // (non-constructor) instance methods and add them as sources.
                  td.method.filterNot(m => m.name == "<init>").l.foreach { otherM =>
                    otherM.ast.isCall.name("<operator>.fieldAccess").l.foreach { fa =>
                      val recvIsThis = fa.argument.l.find(_.argumentIndex == 1).exists {
                        case idn: nodes.Identifier => idn.code.trim == "this"
                        case _ => false
                      }
                      val isField = fa.argument.l.find(_.argumentIndex == 2).exists {
                        case fi: nodes.FieldIdentifier => fi.canonicalName == fieldName
                        case _ => false
                      }
                      if (recvIsThis && isField) thisFieldSources ++= collectFieldAccessChain(fa: nodes.Expression, otherM)
                    }
                  }
                }
              case Some(_) =>
                thisFieldAbstentions += ((s"$exportName.this.$fieldName", "COMPUTED_THIS_FIELD_ASSIGNMENT"))
              case None =>
                thisFieldAbstentions += ((s"$exportName.this.$fieldName", "UNRESOLVED_RHS_SHAPE"))
            }
          }
        }
      }
    }
  }
  val distinctThisFieldSources = thisFieldSources.toList.distinct
  System.err.println(s"[$srcLabel] PACKAGE_API_INPUT this-field source candidates (capability 3): ${distinctThisFieldSources.size}")
  if (thisFieldAbstentions.nonEmpty) {
    System.err.println(s"[$srcLabel] this-field ABSTENTIONS (${thisFieldAbstentions.size}): " +
      thisFieldAbstentions.map { case (name, reason) => s"$name=$reason" }.mkString(" | "))
  }

  val packageApiSources: List[nodes.Expression] = (packageApiParamSources ++ distinctThisFieldSources).distinct
  System.err.println(s"[$srcLabel] PACKAGE_API_INPUT source candidates (total, params + this-fields): ${packageApiSources.size}")

  // ===== combine: does EITHER source family reach a DANGEROUS-pattern sink's input operand? =====
  // Same batched-query performance approach as export_redos_npm_integ.sc (one multi-source
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
    sf.println(Seq(r.sinkId, r.sinkLine, r.srcId, r.originFamily, "ESTABLISHED", "","","","","","","").mkString("\t"))
    pr.println(Seq(r.sinkId, "", "", r.srcId, r.srcLine, r.srcCode, "", "", "").mkString("\t"))
    po.println(Seq(r.sinkId, r.srcId, "ESTABLISHED", "-1", "-1").mkString("\t"))
    System.err.println(s"[$srcLabel] EMIT sink=${r.sinkId}(L${r.sinkLine}) src=${r.srcId}(L${r.srcLine}:${r.srcCode}) " +
      s"family=${r.originFamily} note=${r.note}")
  }
  sf.close(); pr.close(); po.close(); ti.close()
  System.err.println(s"[$srcLabel] REDOS_NPM_INTEG_R02_COMPLETE rows=${outRows.size} " +
    s"(package_api=${outRows.count(_.originFamily == "PACKAGE_API_INPUT")}, " +
    s"application_ingress=${outRows.count(_.originFamily == "APPLICATION_INGRESS")})")

  val summary = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/redos_npm_summary.json"))
  summary.println(s"""{"sink_targets": ${sinkTargets.size}, "dangerous_sinks": ${dangerousSinks.size}, """ +
    s""""package_api_sources": ${packageApiSources.size}, "application_ingress_sources": ${applicationIngressSources.size}, """ +
    s""""exported_functions_resolved": ${distinctExportedFns.size}, "exported_classes_resolved": ${exportedClasses.size}, """ +
    s""""this_field_sources": ${distinctThisFieldSources.size}, """ +
    s""""export_abstentions": ${exportAbstentions.size}, "this_field_abstentions": ${thisFieldAbstentions.size}, """ +
    s""""pattern_abstentions": ${patternAbstentions.size}, """ +
    s""""rows_emitted": ${outRows.size}}""")
  summary.close()
}
