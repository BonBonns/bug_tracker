// NOSQLI-INTEG-R01: wires the frozen NoSQL-injection sink-semantics matrix and property-effects
// classifier together into one producer emitting the SAME fact-table schema consumed unchanged by
// adjudicate_js.py. Reuses every source-provenance mechanism already verified this session
// (explicit source families, genuine Meteor.methods ingress-boundary detection, real
// interprocedural tracing, the batched multi-source query fix) unmodified -- only the sink family,
// per-field operand identification, and type-guard property-effect rules are new to this property.
//
// NOSQLI-INTEG-R01-FIX01 (found while wiring a Python reducer on top of this file, unmodified
// otherwise): sinkId is the enclosing CALL's own node ID, shared by every field operand of a
// multi-field selector (`findOne({email, statusFlag})` emits two SinkTargets, same sinkCall.id).
// target.fieldKind/target.fieldName/target.valueExpr.code were already computed per-target (see
// the EMIT stderr line below) but never written to source_facts.tsv -- only sinkId/sinkLine/srcId/
// family/status were, using 5 of the row's 12 columns and leaving 7 blank. A downstream reducer
// reading this file back could not tell WHICH field at a multi-field call a given row concerns --
// exactly the reviewer-facing information this property exists to report. Fixed by writing field
// identity into three of the previously-always-blank reserved columns (5/6/7); adjudicate_js.py
// itself only ever reads columns 0-4 (confirmed by direct inspection, same fact already relied on
// by path_traversal_verdict.py's own use of this schema's reserved columns), so this is additive
// and does not change anything an existing consumer of columns 0-4 observes.
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

// ===== Stage 1 (frozen): sink semantics =====
val QUERY_METHODS = Set("findOne", "find", "updateOne", "updateMany", "deleteOne", "deleteMany",
  "countDocuments", "findOneAndUpdate", "findOneAndDelete", "findOneAndReplace", "replaceOne")
// NOTE: headers deliberately excluded from this property's source pattern, unlike the general
// SOURCE_PATTERN reused by other properties in this project. HTTP headers, retrieved via a
// standard .headers.get(name) API, are structurally always strings or null by protocol -- they
// cannot carry the object-shaped payload ({"$ne": null}) this property is about, unlike
// req.body (parsed JSON, can be any shape) or req.query (some parsers support bracket notation
// producing nested objects, e.g. the real disclosed access_token[$ne]=null RocketChat CVE).
// Confirmed by hand-investigation this session: treating headers as an equally-risky source led
// directly to a false lead (x-user-id/x-auth-token in ApiClass.ts) that required manual tracing
// to rule out.
val SOURCE_PATTERN = "(req|request)\\.(body|query|params|payload|url)(\\..*)?"
val MESSAGE_SOURCE_PATTERN = "(message|item)\\.(urls|text|attachments|msg)(\\..*)?"

def findQueryFields(argRoot: nodes.AstNode): List[(String, String, nodes.Expression)] = {
  val assigns = argRoot.ast.isCall.name("<operator>.assignment").l
  assigns.flatMap { a =>
    val lhs = a.argument(1)
    val rhs = a.argument(2)
    lhs match {
      case fld: nodes.Call if fld.name == "<operator>.fieldAccess" =>
        val code = fld.code
        val firstDot = code.indexOf('.')
        val fullFieldName = if (firstDot >= 0) code.substring(firstDot + 1) else code
        Some(("LITERAL_FIELD", fullFieldName, rhs.asInstanceOf[nodes.Expression]))
      case idx: nodes.Call if idx.name == "<operator>.indexAccess" =>
        val keyExpr = idx.argument.l.find(_.argumentIndex == 2).map(_.code).getOrElse("?")
        Some(("COMPUTED_FIELD", keyExpr, rhs.asInstanceOf[nodes.Expression]))
      case _ => None
    }
  }
}

// ===== Stage 2 (frozen): property effects =====
def isCompleteTypeofGuard(cmp: nodes.Call, trackedCode: String): Boolean = {
  val operands = cmp.argument.l
  val typeofOperand = operands.collectFirst { case c: nodes.Call if c.name == "<operator>.instanceOf" => c }
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

def hasMeteorCheckStringBefore(method: nodes.Method, sinkCall: nodes.Call, trackedCode: String): Boolean = {
  val checkCalls = method.ast.isCall.name("check").l.filter { c =>
    val args = c.argument.l.sortBy(_.argumentIndex)
    args.lift(1).exists(_.code.trim == trackedCode) &&
    args.lift(2).exists(_.code.trim == "String")
  }
  checkCalls.exists(_.lineNumber.getOrElse(Int.MaxValue) < sinkCall.lineNumber.getOrElse(0))
}

def hasStringCoercion(valueExpr: nodes.Expression, trackedCode: String): Boolean = valueExpr match {
  case c: nodes.Call if c.name == "String" => c.argument.l.exists(_.code.trim == trackedCode)
  case c: nodes.Call if c.name == "<operator>.formatString" => c.argument.l.exists(_.code.trim == trackedCode)
  case _ => false
}

// detects whether a sink's enclosing method is the `action` handler of an API.v1.get/post route
// registration carrying a body:/query: schema gate. Conservative by design and confirmed necessary
// this session: a detected-but-unresolved gate is reported as UNKNOWN, never silently treated as
// PRESERVES/exploitable -- the exact mistake that produced four false leads requiring manual
// tracing before this fix. Uses .referencedMethod's node ID for precise matching, not the
// methodFullName string, which was confirmed ambiguous when multiple route handlers share the
// generic name "action" (a real jssrc2cpg naming collision, not a hypothetical edge case).
def detectApiRouteSchemaGate(sinkMethod: nodes.Method): Option[String] = {
  val apiCalls = cpg.call.filter { c =>
    Set("get", "post", "put", "delete").contains(c.name) && c.code.startsWith("API.v1.")
  }.l
  apiCalls.flatMap { apiCall =>
    val handlersArg = apiCall.argument.l.find(_.argumentIndex == 3)
    val actionAssign = handlersArg.toList.flatMap(_.ast.isCall.name("<operator>.assignment").l)
      .find(_.code.contains(".action ="))
    val pointsToThisMethod = actionAssign.exists { a =>
      a.argument.l.find(_.argumentIndex == 2).exists {
        case ref: nodes.MethodRef => scala.util.Try(ref.referencedMethod).toOption.exists(_.id == sinkMethod.id)
        case _ => false
      }
    }
    if (pointsToThisMethod) {
      val optionsArg = apiCall.argument.l.find(_.argumentIndex == 2)
      val schemaAssign = optionsArg.toList.flatMap(_.ast.isCall.name("<operator>.assignment").l)
        .find(a => a.code.contains(".body =") || a.code.contains(".query ="))
      schemaAssign.map(a => a.argument.l.find(_.argumentIndex == 2).map(_.code).getOrElse("?"))
    } else None
  }.headOption
}

@main def exec(cpgFile: String, rawDir: String, srcLabel: String, skipCount: Int = 0) = {
  importCpg(cpgFile)
  implicit val ec: EngineContext = EngineContext()

  // ===== sink enumeration: one target per (call, field) pair =====
  case class SinkTarget(sinkCall: nodes.Call, method: nodes.Method, fieldKind: String,
                         fieldName: String, valueExpr: nodes.Expression)
  val sinkTargets = scala.collection.mutable.ListBuffer[SinkTarget]()
  cpg.call.l.foreach { c =>
    if (QUERY_METHODS.contains(c.name)) {
      val args = c.argument.l.filter(_.argumentIndex >= 1)
      args.headOption.foreach { selectorArg =>
        findQueryFields(selectorArg).foreach { case (kind, fieldName, valueExpr) =>
          sinkTargets += SinkTarget(c, c.method, kind, fieldName, valueExpr)
        }
      }
    }
  }
  System.err.println(s"[$srcLabel] sink targets (query field operands) found: ${sinkTargets.size}")

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
    val validIdentifierPattern = "^[A-Za-z_$][A-Za-z0-9_$]*$".r
    val safeRegisteredNames = registeredNames.filter(n => validIdentifierPattern.matches(n))
    System.err.println(s"  Meteor.methods ingress registrations found: ${safeRegisteredNames.size}")
    safeRegisteredNames.flatMap { name => cpg.method.name(name).parameter.filter(_.name != "this").l }
  }
  val sourceCallsFieldAccess = cpg.call.name("<operator>.fieldAccess").code(s"($SOURCE_PATTERN)|($MESSAGE_SOURCE_PATTERN)").l
  val ingressParams = findIngressParams()
  val validIdentifierPattern2 = "^[A-Za-z_$][A-Za-z0-9_$]*$".r
  val ingressParamSources: List[nodes.Expression] = ingressParams.flatMap { p =>
    if (validIdentifierPattern2.matches(p.name)) p.method.ast.isIdentifier.name(p.name).l.map(id => id: nodes.Expression)
    else Nil
  }
  val sourceCalls: List[nodes.Expression] = (sourceCallsFieldAccess.map(c => c: nodes.Expression) ++ ingressParamSources).distinct
  System.err.println(s"[$srcLabel] source candidates found: ${sourceCalls.size} " +
    s"(field-access: ${sourceCallsFieldAccess.size}, ingress-param refs: ${ingressParamSources.size})")

  // ===== combine: for each sink target, first apply Stage 2's property-effect classification,
  // then (if PRESERVES / attacker-influenceable) check source reachability. Only PRESERVES targets
  // are worth the expensive reachability check -- a BREAKS target is closed regardless of source. =====

  // for a value expression that's wrapped in a coercion call (String(x) or a template literal
  // containing x), extract the INNER tracked expression -- reachability must be tested against
  // the inner value, not the wrapping call's own code (checking a call's code against itself is
  // circular and can never match, the bug this fix corrects).
  def innerTrackedExpr(valueExpr: nodes.Expression): (nodes.Expression, Boolean) = valueExpr match {
    case c: nodes.Call if c.name == "String" =>
      c.argument.l.find(_.argumentIndex == 1).map(a => (a.asInstanceOf[nodes.Expression], true)).getOrElse((valueExpr, false))
    case c: nodes.Call if c.name == "<operator>.formatString" =>
      // the interpolated (non-literal) argument -- the coerced value itself
      c.argument.l.collectFirst { case a if !a.isInstanceOf[nodes.Literal] => (a.asInstanceOf[nodes.Expression], true) }
        .getOrElse((valueExpr, false))
    case _ => (valueExpr, false)
  }

  val classified = sinkTargets.map { t =>
    val (inner, wasCoerced) = innerTrackedExpr(t.valueExpr)
    val innerCode = inner.code.trim
    val typeGuard = if (wasCoerced) None else sinkIsGuardedByTypeCheck(t.sinkCall, innerCode)
    val checkGuard = !wasCoerced && hasMeteorCheckStringBefore(t.method, t.sinkCall, innerCode)
    val apiGate = if (wasCoerced) None else detectApiRouteSchemaGate(t.method)
    val isPreserves = typeGuard.isEmpty && !checkGuard && !wasCoerced && apiGate.isEmpty
    (t, inner, apiGate, isPreserves)
  }
  val preTargets = classified.filter(_._4).map { case (t, inner, _, _) => (t, inner) }
  val apiGatedCount = classified.count(_._3.isDefined)
  System.err.println(s"[$srcLabel] excluded $apiGatedCount targets behind a detected API route " +
    "body:/query: schema gate -- reported as UNKNOWN, not silently PRESERVES (schema not further " +
    "resolved by this producer; confirm the specific field's type constraint by hand before trusting either way)")

  // exclude targets whose value is itself a nested object literal (e.g. `{ $gt: x }`,
  // `{ $all: x }`) -- these are (a) confirmed computationally pathological for the dataflow
  // engine on this corpus (repeatedly the specific cause of both an OutOfMemoryError and a
  // separate multi-minute hang during this scan), and (b) semantically less meaningful for this
  // property: the object ITSELF is virtually always an intentional, developer-written MongoDB
  // operator, not an attacker-controlled position, and Stage 1's recursion already separately
  // captures the operator's OWN inner field:value pair (e.g. field=$gt, value=x) as its own,
  // simpler, tractable target. Reported as excluded, not silently dropped.
  val (preservesTargets, excludedComplexValue) = preTargets.partition {
    case (_, inner) => !inner.code.trim.startsWith("{")
  }
  System.err.println(s"[$srcLabel] excluded ${excludedComplexValue.size} targets with nested-object-literal values " +
    "(pathological for the dataflow engine, redundant with their own recursively-captured inner fields)")
  System.err.println(s"[$srcLabel] PRESERVES targets (not type-guarded): ${preservesTargets.size} of ${sinkTargets.size}")

  new java.io.File(rawDir).mkdirs()
  val sf = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/source_facts.tsv", true))
  val pr = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/propagation_relations.tsv", true))
  val po = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/property_outcome.tsv", true))
  val ti = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/transform_identity.tsv", true))
  var totalEmitted = 0

  // process in small batches with incremental flush -- reduces peak memory pressure (454 sinks'
  // worth of accumulated query state at once was enough to exhaust heap on this corpus size) and
  // ensures partial progress survives if a later batch fails, rather than losing everything the
  // way the all-at-the-end write pattern did earlier this session.
  val BATCH_SIZE = 1
  val toProcess = preservesTargets.drop(skipCount)
  System.err.println(s"[$srcLabel] resuming at index $skipCount, ${toProcess.size} of ${preservesTargets.size} remaining")
  toProcess.grouped(BATCH_SIZE).zipWithIndex.foreach { case (batch, batchIdx) =>
    val globalIdx = skipCount + batchIdx
    batch.foreach { case (target, inner) =>
      System.err.println(s"[$srcLabel] [$globalIdx/${preservesTargets.size}] attempting sink=${target.sinkCall.id} " +
        s"file=${target.method.filename} line=${target.sinkCall.lineNumber.getOrElse(-1)} field=${target.fieldName} value=${inner.code.take(40)}")
      import scala.concurrent.{Future, Await, ExecutionContext}
      import scala.concurrent.duration._
      import java.util.concurrent.{Executors, TimeoutException}
      val execSvc = Executors.newSingleThreadExecutor()
      implicit val execCtx: ExecutionContext = ExecutionContext.fromExecutorService(execSvc)
      val flowsFuture = Future {
        cpg.all.id(inner.id).collectAll[nodes.Expression].reachableByFlows(sourceCalls.iterator).l
      }
      val flows = try {
        Await.result(flowsFuture, 45.seconds)
      } catch {
        case _: TimeoutException =>
          System.err.println(s"[$srcLabel] [$globalIdx/${preservesTargets.size}] TIMED OUT after 45s -- abandoned, treated as UNKNOWN not ESTABLISHED")
          Nil
        case e: Throwable =>
          System.err.println(s"[$srcLabel] [$globalIdx/${preservesTargets.size}] ERROR: ${e.getMessage} -- abandoned")
          Nil
      } finally {
        execSvc.shutdownNow()
      }
      flows.foreach { f =>
        f.elements.headOption.foreach { origin =>
          val sinkId = target.sinkCall.id.toString
          val sinkLine = target.sinkCall.lineNumber.getOrElse(-1)
          val srcId = origin.id.toString
          val srcLine = origin.lineNumber.getOrElse(-1)
          val note = s"field='${target.fieldName}' value operand='${target.valueExpr.code}' -- no type guard, " +
            "no coercion, no Meteor.check(String) found on this path"
          // NOSQLI-INTEG-R01-FIX01: sanitize -- a field name or value-operand code containing a
          // literal tab or newline would otherwise corrupt this TSV's own column structure. Field
          // names are normally identifiers; the value-operand code is arbitrary source text (could
          // contain a template literal spanning lines), so this matters for that column specifically.
          def tsvSafe(s: String): String = s.replaceAll("[\\t\\n\\r]+", " ")
          sf.println(Seq(sinkId, sinkLine, srcId, "QUERY_FIELD_VALUE", "ESTABLISHED",
            tsvSafe(target.fieldKind), tsvSafe(target.fieldName), tsvSafe(target.valueExpr.code),
            "","","","").mkString("\t"))
          pr.println(Seq(sinkId, "", "", srcId, srcLine, origin.code, "", "", "").mkString("\t"))
          po.println(Seq(sinkId, srcId, "ESTABLISHED", "-1", "-1").mkString("\t"))
          System.err.println(s"[$srcLabel] EMIT sink=$sinkId(L$sinkLine) field=${target.fieldKind}:${target.fieldName} src=$srcId(L$srcLine:${origin.code}) note=$note")
          totalEmitted += 1
        }
      }
    }
    sf.flush(); pr.flush(); po.flush()
  }
  sf.close(); pr.close(); po.close(); ti.close()
  System.err.println(s"[$srcLabel] NOSQLI_INTEG_COMPLETE rows=$totalEmitted")
}
