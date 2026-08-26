// PATH-TRAV-INTEG-R01: wires the frozen path-traversal sink-semantics matrix and property-effects
// rules together into one producer emitting the SAME fact-table schema consumed unchanged by
// adjudicate_js.py. Reuses every source-provenance mechanism already verified for SSRF (explicit
// source families, genuine ingress-boundary detection via Meteor.methods, real interprocedural
// tracing, the sibling-argument artifact filter, the TS-overload structural resolver) unmodified --
// only the sink family, destination-operand identification, and property-effect rules are new.
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

// ===== Stage 1 (frozen): sink semantics =====
val FS_FAMILY = Set("readFile", "readFileSync", "writeFile", "writeFileSync",
  "createReadStream", "createWriteStream", "unlink", "unlinkSync", "open", "openSync",
  "stat", "existsSync")
val PATH_JOINING_CALLS = Set("join", "resolve")
val LOCATION_PRESERVING_TRANSFORM_NAMES = Set("normalize")
val COMPARISON_OPS = Set("<operator>.equals", "<operator>.strictEquals")
val CONTAINMENT_CHECK_METHODS = Set("includes", "startsWith")
val SOURCE_PATTERN = "(req|request)\\.(body|query|params|headers|payload|url)(\\..*)?"
val MESSAGE_SOURCE_PATTERN = "(message|item)\\.(urls|text|attachments)(\\..*)?"

@main def exec(cpgFile: String, rawDir: String, srcLabel: String) = {
  importCpg(cpgFile)
  implicit val ec: EngineContext = EngineContext()

  def familyOf(c: nodes.Call): Option[String] = {
    val code = c.code
    if (code.startsWith("fs.")) { if (FS_FAMILY.contains(c.name)) Some(s"fs.${c.name}") else None }
    else if (code.startsWith("res.sendFile(")) Some("express.sendFile")
    else if (code.startsWith("res.download(")) Some("express.download")
    else None
  }

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

  case class SinkTarget(sinkCall: nodes.Call, family: String, destExpr: nodes.Expression)
  val sinkTargets = scala.collection.mutable.ListBuffer[SinkTarget]()
  cpg.call.l.foreach { c =>
    familyOf(c).foreach { fam =>
      val args = c.argument.l.filter(_.argumentIndex >= 1)
      args.headOption.foreach { a0 =>
        if (fam.startsWith("fs.")) {
          sinkTargets += SinkTarget(c, fam, a0)  // uniform positional case, no root concept
        } else if (fam == "express.sendFile") {
          val optionsArg = args.lift(1)
          val rootField = optionsArg.flatMap(opt => findObjectField(opt, Seq("root")))
          rootField match {
            case Some((_, rootExpr)) =>
              // root present: root is the genuine location-determining operand for this sink.
              // The path arg is CONTAINED (Express prevents '..'-escape above a fixed root) -- do
              // NOT enumerate it as a full-location alternative, matching the frozen Stage-1 finding.
              sinkTargets += SinkTarget(c, fam, rootExpr)
            case None =>
              sinkTargets += SinkTarget(c, fam, a0)
          }
        } else if (fam == "express.download") {
          sinkTargets += SinkTarget(c, fam, a0)  // arg1, if present, is a display filename -- ignore
        }
      }
    }
  }
  System.err.println(s"[$srcLabel] sink targets found: ${sinkTargets.size}")

  // ===== Stage 2 (frozen): property effects =====
  def isConstructorCall(c: nodes.Call): Boolean = c.name == "<operator>.new"

  def enclosingCall(n: nodes.AstNode): Option[nodes.Call] = {
    var cur: nodes.AstNode = n; var hops = 0
    while (hops < 8) {
      val p = scala.util.Try(cur.astParent).toOption
      p match { case Some(c: nodes.Call) => return Some(c); case Some(null) => return None
                case Some(pp) => cur = pp; hops += 1; case None => return None }
    }
    None
  }

  def sinkIsGuardedBy(sinkCall: nodes.Call, trackedCodes: Set[String]): Option[String] = {
    def isGenuineValueGuard(cmp: nodes.Call): Boolean = cmp.argument.l.exists(o => trackedCodes.contains(o.code.trim))
    def isGenuineContainmentCheck(m: nodes.Call): Boolean = m.argument.l.exists(o => trackedCodes.contains(o.code.trim))
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
            val genuineComparison = cond.toList.flatMap(_.ast.isCall.filter(c => COMPARISON_OPS.contains(c.name)).l)
              .find(isGenuineValueGuard)
            val genuineContainment = cond.toList.flatMap(_.ast.isCall.filter(c => CONTAINMENT_CHECK_METHODS.contains(c.name)).l)
              .find(isGenuineContainmentCheck)
            (genuineComparison, genuineContainment) match {
              case (Some(c), _) => return Some(c.code)
              case (_, Some(m)) => return Some(m.code)
              case _ =>
            }
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

  def hasLiteralDotDotStrip(m: nodes.Method, trackedCode: String): Option[String] = {
    m.ast.isCall.name("replace").find { c =>
      val args = c.argument.l.sortBy(_.argumentIndex)
      args.headOption.exists(_.code.trim == trackedCode.trim) &&
      args.lift(1).exists(a => a.code.contains("..") || a.code.contains("\\.\\."))
    }.map(_.code)
  }

  // PATH-REALPOS-R01: a narrower, distinct sibling to TS-INSTANCE-PROP-R01 -- resolves
  // `X.propName(...)` calls that Joern's own linker cannot resolve (a plain shared object mutated
  // across files via require(), no class/constructor involved) by finding a GLOBALLY UNIQUE
  // function-value assignment `Y.propName = function(...){...}` anywhere in the corpus. Safe
  // specifically BECAUSE there is no ambiguity to resolve when exactly one such assignment
  // exists -- no receiver-type confirmation is needed the way TS-INSTANCE-PROP-R01 needed it,
  // since uniqueness alone rules out any alternative binding. If more than one assignment of the
  // same property name exists anywhere, this correctly abstains rather than guessing which one.
  def resolveGloballyUniquePropertyAssignment(propName: String): Option[nodes.Method] = {
    val functionValueAssigns = cpg.call.name("<operator>.assignment").l.filter { a =>
      // EXCLUDE constructor-scoped assignments (enclosingMethod == "<init>") -- those are
      // TS-INSTANCE-PROP-R01's domain specifically, which requires receiver-type confirmation
      // and a reassignment-dominance check before bridging (verified necessary: RocketChat's
      // LocalStore.getReadStream case, a constructor-scoped assignment, must NOT be silently
      // resolved by this looser rule, since doing so would bypass the exact safeguards that
      // rule was built and fixture-verified to require). This bridge is scoped ONLY to
      // module/top-level-scoped property assignments (the jsPDF case: `jsPDFAPI.loadFile =
      // function(){...}` at IIFE/module scope, never inside any class constructor).
      if (a.method.name == "<init>") false
      else {
        val lhs = a.argument.l.find(_.argumentIndex == 1)
        val rhs = a.argument.l.find(_.argumentIndex == 2)
        val lhsMatches = lhs.exists {
          case fld: nodes.Call if fld.name == "<operator>.fieldAccess" => fld.code.split("\\.").lastOption.contains(propName)
          case _ => false
        }
        val rhsIsFunctionRef = rhs.exists(_.isInstanceOf[nodes.MethodRef])
        lhsMatches && rhsIsFunctionRef
      }
    }
    if (functionValueAssigns.size != 1) None
    else {
      val rhs = functionValueAssigns.head.argument.l.find(_.argumentIndex == 2)
      rhs.collect { case ref: nodes.MethodRef => ref.methodFullName }.flatMap(fn => cpg.method.fullName(fn).headOption)
    }
  }

  // PATH-PROV-R01 (frozen, fixture-verified against 6 controlled cases including the exact real
  // RocketChat regex): classifies the character class of a regex capture group used to extract
  // path/filename segments. Regex extraction is NOT automatically sanitization -- the pattern's
  // actual accepted language determines whether traversal syntax survives.
  def classifyRegexCapture(patternText: String): String = {
    val restrictedSafe = """\[A-Za-z0-9_\-\]""".r
    val excludesSlashClass = """\[\^[^\]]*/[^\]]*\]""".r
    if (restrictedSafe.findFirstIn(patternText).isDefined) "RESTRICTED_SAFE"
    else if (excludesSlashClass.findFirstIn(patternText).isDefined) {
      val negClassContent = excludesSlashClass.findFirstIn(patternText).get
      if (negClassContent.contains("\\.") || negClassContent.replace("[^","").replace("]","").contains("."))
        "RESTRICTED_SAFE"
      else "EXCLUDES_SLASH_ALLOWS_DOT"
    } else "UNRESTRICTED"
  }
  // finds a regex capture used within this method that the tracked value derives through: looks
  // for a `.exec()` call preceded by a literal `new RegExp(pattern)` construction, whose result
  // (via match[n] indexAccess) is part of the SAME confirmed flow.
  def regexCaptureClassificationInFlow(m: nodes.Method, flowElements: Seq[nodes.AstNode]): Option[(String, String)] = {
    val execCalls = flowElements.collect { case c: nodes.Call if c.name == "exec" => c }
    execCalls.flatMap { execCall =>
      val receiverId = execCall.argument.l.find(_.argumentIndex == 0).map(_.code)
      val newRegexCalls = m.ast.isCall.name("<operator>.new").filter(_.code.startsWith("new RegExp(")).l
      // match the exec() receiver back to a RegExp construction assigned to the same variable name
      val relevantConstruction = newRegexCalls.find { nc =>
        val assignedTo = m.ast.isCall.name("<operator>.assignment").l.find { assign =>
          assign.argument.l.find(_.argumentIndex == 2).exists(_.ast.isCall.filter(_.id == nc.id).nonEmpty)
        }.flatMap(_.argument.l.find(_.argumentIndex == 1)).map(_.code)
        assignedTo.isDefined && receiverId.isDefined && assignedTo == receiverId
      }
      relevantConstruction.flatMap { nc =>
        nc.argument.l.find(_.argumentIndex == 1).collect { case lit: nodes.Literal => (lit.code, classifyRegexCapture(lit.code)) }
      }
    }.headOption
  }

  def lookupKeyInfluence(m: nodes.Method, srcExpr: nodes.Expression, sinkExprs: List[nodes.Expression],
                          otherSinkArgIds: Set[Long]): Option[String] = {
    val keyUses = srcExpr.ast.l.collect { case id: nodes.Identifier => id }
      .flatMap(id => enclosingCall(id))
      .filter(c => !c.name.startsWith("<operator>") || c.name == "<operator>.indexAccess")
      .distinct
    keyUses.flatMap { lookupCall =>
      val fieldAccessOnResult = scala.util.Try(lookupCall.astParent).toOption.collect {
        case fa: nodes.Call if fa.name == "<operator>.fieldAccess" => fa
      }
      val candidateSources: List[nodes.Expression] =
        (cpg.all.id(lookupCall.id).collectAll[nodes.Expression].l ++
         fieldAccessOnResult.toList.flatMap(fa => cpg.all.id(fa.id).collectAll[nodes.Expression].l))
      if (sinkExprs.isEmpty || candidateSources.isEmpty) None
      else {
        val flows = candidateSources.flatMap(s => sinkExprs.reachableByFlows(Iterator(s)).l)
          .filterNot(f => f.elements.dropRight(1).exists(e => otherSinkArgIds.contains(e.id)))
        if (flows.nonEmpty) Some(lookupCall.code) else None
      }
    }.headOption
  }

  // ===== TS-OVERLOAD-R01 bridge (frozen, verified) =====
  def bodyChildCount(mth: nodes.Method): Int =
    mth.block.astChildren.filterNot(_.isInstanceOf[nodes.MethodParameterIn]).size
  def stripTrailingDigits(name: String): String = name.reverse.dropWhile(_.isDigit).reverse
  def resolveOverloadImplementation(callSite: nodes.Call): Option[nodes.Method] = {
    callSite.callee.headOption.flatMap { callee =>
      if (bodyChildCount(callee) > 0) Some(callee)
      else {
        val baseName = stripTrailingDigits(callee.name)
        val paramCount = callee.parameter.filterNot(_.name == "this").size
        val candidates = cpg.method.filter { mth =>
          mth.filename == callee.filename && stripTrailingDigits(mth.name) == baseName &&
          mth.parameter.filterNot(_.name == "this").size == paramCount
        }.l
        val withBody = candidates.filter(bodyChildCount(_) > 0)
        if (withBody.size == 1) Some(withBody.head) else None
      }
    }
  }
  def computeOverloadBridgedSources(allSources: List[nodes.Expression]): List[nodes.Expression] = {
    val stubCalls = cpg.call.filter(c => c.callee.headOption.exists(callee => bodyChildCount(callee) == 0)).l
    if (allSources.isEmpty || stubCalls.isEmpty) Nil
    else stubCalls.flatMap { c =>
      resolveOverloadImplementation(c) match {
        case Some(realImpl) if c.callee.headOption.exists(_.id != realImpl.id) =>
          val args = c.argument.l.filter(_.argumentIndex >= 1)
          val argsWithFlow = args.filter { arg =>
            scala.util.Try(cpg.all.id(arg.id).collectAll[nodes.Expression]
              .reachableByFlows(allSources.iterator).l.nonEmpty).getOrElse(false)
          }
          argsWithFlow.flatMap { arg =>
            realImpl.parameter.filter(_.index == arg.argumentIndex).flatMap(p =>
              realImpl.ast.isIdentifier.name(p.name).l).map(id => id: nodes.Expression)
          }
        case _ => Nil
      }
    }
  }
  // PATH-REALPOS-R01 bridge: for call sites whose OWN callee never resolves at all (unlike the
  // overload case, there is no candidate .callee to compare against -- Joern found nothing, not
  // a wrong stub), check whether the call's property name has a globally unique function-value
  // assignment, and bridge to it the same way.
  def computePropertyAssignmentBridgedSources(allSources: List[nodes.Expression]): List[nodes.Expression] = {
    val unresolvedPropertyCalls = cpg.call.filter { c =>
      !c.name.startsWith("<operator>") && c.callee.nonEmpty &&
      c.callee.l.forall(callee => bodyChildCount(callee) == 0)
    }.l
    if (allSources.isEmpty || unresolvedPropertyCalls.isEmpty) Nil
    else unresolvedPropertyCalls.flatMap { c =>
      resolveGloballyUniquePropertyAssignment(c.name) match {
        case Some(realImpl) =>
          val args = c.argument.l.filter(_.argumentIndex >= 1)
          val argsWithFlow = args.filter { arg =>
            scala.util.Try(cpg.all.id(arg.id).collectAll[nodes.Expression]
              .reachableByFlows(allSources.iterator).l.nonEmpty).getOrElse(false)
          }
          argsWithFlow.flatMap { arg =>
            realImpl.parameter.filter(_.index == arg.argumentIndex).flatMap(p =>
              realImpl.ast.isIdentifier.name(p.name).l).map(id => id: nodes.Expression)
          }
        case None => Nil
      }
    }
  }

  // ===== ingress-boundary detection (frozen, verified): Meteor.methods registrations =====
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
    System.err.println(s"  Meteor.methods ingress registrations found: ${registeredNames.mkString(",")}")
    registeredNames.flatMap { name => cpg.method.name(name).parameter.filter(_.name != "this").l }
  }

  val sourceCallsFieldAccess = cpg.call.name("<operator>.fieldAccess").code(s"($SOURCE_PATTERN)|($MESSAGE_SOURCE_PATTERN)").l
  val ingressParams = findIngressParams()
  val ingressParamSources: List[nodes.Expression] = ingressParams.flatMap { p =>
    p.method.ast.isIdentifier.name(p.name).l.map(id => id: nodes.Expression)
  }
  val baseSourceCalls: List[nodes.Expression] = sourceCallsFieldAccess.map(c => c: nodes.Expression) ++ ingressParamSources
  val overloadBridged = computeOverloadBridgedSources(baseSourceCalls)
  val propertyBridged = computePropertyAssignmentBridgedSources(baseSourceCalls)
  System.err.println(s"[$srcLabel] overload-bridged sources added: ${overloadBridged.size}")
  System.err.println(s"[$srcLabel] property-assignment-bridged sources added: ${propertyBridged.size}")
  val sourceCalls: List[nodes.Expression] = (baseSourceCalls ++ overloadBridged ++ propertyBridged).distinct
  System.err.println(s"[$srcLabel] source candidates found: ${sourceCalls.size} " +
    s"(field-access: ${sourceCallsFieldAccess.size}, ingress-param refs: ${ingressParamSources.size}, " +
    s"overload-bridged: ${overloadBridged.size})")

  case class OutRow(sinkId: String, sinkLine: Int, srcId: String, srcLine: Int, srcCode: String,
                     outcome: String, transformChain: List[(nodes.Call, String)], note: String)
  val outRows = scala.collection.mutable.ListBuffer[OutRow]()

  sinkTargets.foreach { target =>
    val sinkCall = target.sinkCall
    val destExpr = target.destExpr
    val m = sinkCall.method
    sourceCalls.foreach { src =>
      val otherSinkArgIds = sinkCall.argument.l.filter(_.argumentIndex >= 1)
        .filterNot(_.id == destExpr.id).map(_.id).toSet
      val flowsRaw = scala.util.Try {
        cpg.all.id(destExpr.id).collectAll[nodes.Expression]
          .reachableByFlows(Iterator(src: nodes.Expression)).l
      }.getOrElse(Nil)
      val flows = flowsRaw.filterNot(f => f.elements.dropRight(1).exists(e => otherSinkArgIds.contains(e.id)))
      if (flows.isEmpty) {
        val sinkExprs = cpg.all.id(destExpr.id).collectAll[nodes.Expression].l
        lookupKeyInfluence(m, src, sinkExprs, otherSinkArgIds).foreach { lookupCode =>
          outRows += OutRow(sinkCall.id.toString, sinkCall.lineNumber.getOrElse(-1), src.id.toString,
            src.lineNumber.getOrElse(-1), src.code, "OPEN", Nil,
            s"LOOKUP_KEY_INFLUENCE: key reaches $lookupCode, value itself does not flow to sink")
        }
      } else {
        // derived-variable tracking (frozen, verified): every identifier confirmed part of the
        // flow is guard-relevant, not just the original source name.
        val derivedNames: Set[String] = flows.flatMap(_.elements.collect { case id: nodes.Identifier => id.code.trim }).toSet
        val trackedCodes = Set(src.code.trim) ++ derivedNames
        val guardMatch = sinkIsGuardedBy(sinkCall, trackedCodes)
        val stripMatch = hasLiteralDotDotStrip(m, src.code)
        val regexMatch = flows.headOption.flatMap(f => regexCaptureClassificationInFlow(m, f.elements))
        (guardMatch, stripMatch, regexMatch) match {
          case (Some(cond), _, _) =>
            outRows += OutRow(sinkCall.id.toString, sinkCall.lineNumber.getOrElse(-1), src.id.toString,
              src.lineNumber.getOrElse(-1), src.code, "BROKEN", Nil, s"guarded by: $cond")
          case (None, Some(rc), _) =>
            outRows += OutRow(sinkCall.id.toString, sinkCall.lineNumber.getOrElse(-1), src.id.toString,
              src.lineNumber.getOrElse(-1), src.code, "BROKEN", Nil, s"literal '..' strip: $rc")
          case (None, None, Some((pattern, classification))) if classification == "RESTRICTED_SAFE" =>
            outRows += OutRow(sinkCall.id.toString, sinkCall.lineNumber.getOrElse(-1), src.id.toString,
              src.lineNumber.getOrElse(-1), src.code, "BROKEN", Nil,
              s"regex capture restricted (pattern=$pattern, $classification)")
          case (None, None, Some((pattern, classification))) if classification == "EXCLUDES_SLASH_ALLOWS_DOT" =>
            outRows += OutRow(sinkCall.id.toString, sinkCall.lineNumber.getOrElse(-1), src.id.toString,
              src.lineNumber.getOrElse(-1), src.code, "OPEN", Nil,
              s"regex excludes '/' but allows '.' (pattern=$pattern) -- bounded single-level " +
              "escape possible, neither PRESERVES nor BREAKS accurately describes this -- " +
              "flagged for semantic review")
          case (None, None, Some((pattern, "UNRESTRICTED"))) =>
            outRows += OutRow(sinkCall.id.toString, sinkCall.lineNumber.getOrElse(-1), src.id.toString,
              src.lineNumber.getOrElse(-1), src.code, "ESTABLISHED", Nil,
              s"regex capture unrestricted (pattern=$pattern) -- location control survives extraction")
          case (None, None, _) =>
            var effect = "PRESERVES"
            var note = ""
            val transformChain = scala.collection.mutable.ListBuffer[(nodes.Call, String)]()
            val seen = scala.collection.mutable.Set[Long]()
            flows.foreach { f =>
              f.elements.foreach { e =>
                val isIdentifier = e.isInstanceOf[nodes.Identifier]
                if (!isIdentifier) {
                  val directCallOpt: Option[nodes.Call] = e match {
                    case c: nodes.Call if (!c.name.startsWith("<operator>") || isConstructorCall(c)) && !familyOf(c).isDefined => Some(c)
                    case _ => None
                  }
                  val ecOpt = directCallOpt.orElse(enclosingCall(e).filter(c =>
                    (!c.name.startsWith("<operator>") || isConstructorCall(c)) && !familyOf(c).isDefined))
                  ecOpt.foreach { c =>
                    if (!seen.contains(c.id)) {
                      seen += c.id
                      val calleeShort = if (c.name == "<operator>.fieldAccess")
                        c.code.split("\\.").lastOption.getOrElse(c.name) else c.name
                      val isPathJoiningCall = PATH_JOINING_CALLS.contains(calleeShort)
                      val isKnownPreserving = LOCATION_PRESERVING_TRANSFORM_NAMES.contains(calleeShort)
                      if (isPathJoiningCall) {
                        transformChain += ((c, s"$calleeShort (no containment)"))
                      } else if (!isKnownPreserving && effect == "PRESERVES") {
                        effect = "UNKNOWN"; note = s"unrecognized call: $calleeShort"
                        transformChain += ((c, calleeShort))
                      } else {
                        transformChain += ((c, calleeShort))
                      }
                    }
                  }
                }
              }
            }
            val finalOutcome = effect match { case "PRESERVES" => "ESTABLISHED"; case _ => "OPEN" }
            outRows += OutRow(sinkCall.id.toString, sinkCall.lineNumber.getOrElse(-1), src.id.toString,
              src.lineNumber.getOrElse(-1), src.code, finalOutcome, transformChain.toList, note)
        }
      }
    }
  }

  new java.io.File(rawDir).mkdirs()
  val sf = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/source_facts.tsv", true))
  val pr = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/propagation_relations.tsv", true))
  val po = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/property_outcome.tsv", true))
  val ti = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/transform_identity.tsv", true))
  outRows.foreach { r =>
    sf.println(Seq(r.sinkId, r.sinkLine, r.srcId, "HTTP_PATH_INPUT", "ESTABLISHED", "","","","","","","").mkString("\t"))
    pr.println(Seq(r.sinkId, "", "", r.srcId, r.srcLine, r.srcCode, "", "", "").mkString("\t"))
    po.println(Seq(r.sinkId, r.srcId, r.outcome, "-1", "-1").mkString("\t"))
    r.transformChain.zipWithIndex.foreach { case ((c, kind), order) =>
      ti.println(Seq("x", r.srcId, order.toString, c.id.toString, kind, "", "", "UNKNOWN").mkString("\t"))
    }
    System.err.println(s"[$srcLabel] EMIT sink=${r.sinkId}(L${r.sinkLine}) src=${r.srcId}(L${r.srcLine}:${r.srcCode}) outcome=${r.outcome} note=${r.note}")
  }
  sf.close(); pr.close(); po.close(); ti.close()
  System.err.println(s"[$srcLabel] PATH_TRAV_INTEG_COMPLETE rows=${outRows.size}")
}
