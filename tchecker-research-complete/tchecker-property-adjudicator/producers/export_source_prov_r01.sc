// SOURCE-PROV-R01: fixes the two confirmed recall-failure causes from the Rocket.Chat baseline
// (0/2). Two changes, kept separate as required:
//   (1) SOURCE SEMANTICS: origin recognition generalized beyond req.* pattern-matching to
//       structural/type-based rules (HTTP framework source, Meteor externally-callable method
//       argument, message/user-content source by TS type).
//   (2) INTERPROCEDURAL PROPAGATION: narrow, exact-identity-gated proof rules only --
//       caller argument -> exact local callee parameter, callee return -> exact caller call
//       result. UNKNOWN (never guessed) when callee identity is ambiguous. Reuses the SAME
//       Stage-1 sink-semantics and Stage-2 property-effects classification built and frozen in
//       SSRF-INTEG-R01, applied at EACH hop -- no new property logic, no IP/network-range
//       reasoning folded in (explicitly out of scope for this milestone).
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

val HOST_PRESERVING_TRANSFORM_NAMES = Set("trim", "toLowerCase", "toUpperCase",
  "decodeURIComponent", "String", "hostname")
val COMPARISON_OPS = Set("<operator>.equals", "<operator>.strictEquals")
val ALLOWLIST_METHODS = Set("includes", "has")
val MESSAGE_CONTENT_TYPES = Set("IMessage")   // extensible allowlist of TS types treated as
                                                // user-authored-content sources; type-based, not
                                                // name-based
val MAX_HOPS = 4

@main def exec(cpgFile: String, rawDir: String, srcLabel: String) = {
  importCpg(cpgFile)
  implicit val ec: EngineContext = EngineContext()

  // ===== Stage 1 (frozen, unchanged): sink semantics =====
  def familyOf(c: nodes.Call): Option[String] = {
    val code = c.code
    if (code.startsWith("fetch(")) Some("fetch")
    else if (code.startsWith("axios.get(")) Some("axios")
    else if (code.startsWith("axios.post(")) Some("axios")
    else if (code.startsWith("axios(")) Some("axios")
    else if (code.startsWith("http.request(")) Some("http")
    else if (code.startsWith("https.request(")) Some("https")
    else if (code.startsWith("got(")) Some("got")
    else if (code.startsWith("request(")) Some("request")
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
        val isConstructorArg = a0.ast.isCall.filter(_.name == "<operator>.new").nonEmpty
        val isObjectLiteralArg = !isConstructorArg &&
          (a0.astChildren.isCall.name("<operator>.assignment").nonEmpty || a0.code.trim.startsWith("{"))
        if (!isObjectLiteralArg) {
          sinkTargets += SinkTarget(c, fam, a0)
        } else {
          val hostKeys = fam match {
            case "http" | "https" => Seq("hostname", "host")
            case "axios"          => Seq("baseURL")
            case "got" | "request"=> Seq("url", "uri", "baseUrl")
            case _ => Seq()
          }
          val hostField = findObjectField(a0, hostKeys)
          val urlField = if (fam == "axios") findObjectField(a0, Seq("url")) else None
          (hostField, urlField) match {
            case (Some((_, hv)), _) => sinkTargets += SinkTarget(c, fam, hv)
            case (None, Some((_, uv))) => sinkTargets += SinkTarget(c, fam, uv)
            case (None, None) =>
          }
        }
      }
    }
  }
  System.err.println(s"[$srcLabel] sink targets found: ${sinkTargets.size}")
  sinkTargets.foreach(t => System.err.println(s"  family=${t.family} sink_line=${t.sinkCall.lineNumber.getOrElse(-1)} dest=${t.destExpr.code.take(60)}"))

  // ===== NEW: source semantics layer =====
  case class SourceCandidate(node: nodes.Expression, originKind: String, provenanceNote: String)
  val SOURCE_PATTERN = "req\\.(body|query|params|headers)(\\..*)?"

  // (a) HTTP framework source -- unchanged pattern, still the right rule for Express-style code
  val httpSources = cpg.call.name("<operator>.fieldAccess").code(SOURCE_PATTERN).l
    .map(c => SourceCandidate(c, "HTTP_FRAMEWORK_SOURCE", "matches req.(body|query|params|headers)"))

  // (b) Meteor externally-callable method argument -- structural: find every method whose
  // fullName is referenced as a methodRef inside a Meteor.methods({...}) call's object-literal
  // argument. That method's OWN parameters are externally supplied.
  val meteorRegisteredMethods = cpg.call.code("Meteor\\.methods.*").l.flatMap { mm =>
    mm.argument.l.filter(_.argumentIndex >= 1).flatMap(_.ast.isMethodRef.referencedMethod.l)
  }.distinct
  val meteorMethodSources = meteorRegisteredMethods.flatMap { m =>
    m.parameter.l.filter(p => p.name != "this").flatMap { p =>
      // MethodParameterIn is not collectible as Expression directly (confirmed by direct test);
      // use identifier REFERENCES within the method body instead -- ALL of them, not just the
      // first, since multiple same-name references can exist (e.g. a validation call alongside
      // the real use-site), matching the fix already applied in Stage 2.
      m.ast.isIdentifier.name(p.name).l.map(idExpr =>
        SourceCandidate(idExpr, "EXTERNAL_METHOD_ARGUMENT",
          s"parameter of ${m.fullName}, registered via Meteor.methods()"))
    }
  }
  System.err.println(s"[$srcLabel] Meteor-registered methods found: ${meteorRegisteredMethods.map(_.fullName).mkString(", ")}")

  // (c) Message/user-content source -- TYPE-based, not name-based: any parameter whose
  // typeFullName matches a known user-content type, and every field access reachable from it.
  val messageParams = cpg.method.parameter.l.filter(p => MESSAGE_CONTENT_TYPES.exists(t => p.typeFullName.contains(t)))
  val messageFieldSources = messageParams.flatMap { p =>
    cpg.method.id(p.method.id).ast.isCall.name("<operator>.fieldAccess")
      .filter(_.argument.headOption.exists(_.code == p.name)).l
      .map(fa => SourceCandidate(fa, "MESSAGE_CONTENT_SOURCE", s"field access on ${p.name}: ${p.typeFullName}"))
  }

  val allSources = (httpSources ++ meteorMethodSources ++ messageFieldSources)
  System.err.println(s"[$srcLabel] source candidates found: ${allSources.size} " +
    s"(HTTP=${httpSources.size}, METEOR=${meteorMethodSources.size}, MESSAGE=${messageFieldSources.size})")

  // ===== Stage 2 (frozen, unchanged): property effects, applied per-hop =====
  def isConstructorCall(c: nodes.Call): Boolean = c.name == "<operator>.new"
  def isUrlConstructor(c: nodes.Call): Boolean = isConstructorCall(c) && c.code.startsWith("new URL(")
  def enclosingCallOf(n: nodes.AstNode): Option[nodes.Call] = {
    var cur: nodes.AstNode = n; var hops = 0
    while (hops < 10) {
      val p = scala.util.Try(cur.astParent).toOption
      p match { case Some(c: nodes.Call) => return Some(c); case Some(null) => return None
                case Some(pp) => cur = pp; hops += 1; case None => return None }
    }
    None
  }
  def sinkIsGuardedBy(sinkCall: nodes.Call, trackedCode: String): Option[String] = {
    var cur: nodes.AstNode = sinkCall; var hops = 0
    while (hops < 12) {
      val parentOpt = scala.util.Try(cur.astParent).toOption
      parentOpt match {
        case Some(ifNode: nodes.ControlStructure) if ifNode.controlStructureType == "IF" =>
          val thenBlock = ifNode.astChildren.l.drop(1).headOption
          if (thenBlock.exists(_.ast.contains(sinkCall))) {
            val cond = ifNode.condition.l.headOption
            val condCode = cond.map(_.code).getOrElse("")
            val comparesTracked = condCode.contains(trackedCode) &&
              (COMPARISON_OPS.exists(op => cond.exists(_.ast.isCall.name(op).nonEmpty)) ||
               ALLOWLIST_METHODS.exists(m => condCode.contains(s".$m(")))
            if (comparesTracked) return Some(condCode)
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
  def hasHostOverwrite(m: nodes.Method): Option[String] = {
    m.ast.isCall.name("<operator>.assignment").l.find { a =>
      val lhs = a.argument(1); val rhs = a.argument(2)
      val isHostField = lhs match {
        case fld: nodes.Call if fld.name == "<operator>.fieldAccess" =>
          Set("hostname", "host").contains(fld.code.split("\\.").lastOption.getOrElse(""))
        case _ => false
      }
      isHostField && rhs.isInstanceOf[nodes.Literal]
    }.map(_.code)
  }

  // classify ONE HOP: does `srcExpr` (within method m) reach ANY sink target within m? Returns
  // Some(effect, transformNote) if a direct within-function flow exists; None otherwise (meaning
  // the caller should try recursing into a call instead).
  def classifyWithinFunction(srcExpr: nodes.Expression, m: nodes.Method): Option[(SinkTarget, String, String)] = {
    val localSinks = sinkTargets.filter(_.sinkCall.method == m)
    localSinks.foreach { target =>
      val flows = scala.util.Try {
        cpg.all.id(target.destExpr.id).collectAll[nodes.Expression].reachableByFlows(Iterator(srcExpr)).l
      }.getOrElse(Nil)
      val otherSinkArgIds = target.sinkCall.argument.l.filter(_.argumentIndex >= 1)
        .filterNot(_.id == target.destExpr.id).map(_.id).toSet
      val cleanFlows = flows.filterNot(f => f.elements.dropRight(1).exists(e => otherSinkArgIds.contains(e.id)))
      if (cleanFlows.nonEmpty) {
        val guardMatch = sinkIsGuardedBy(target.sinkCall, srcExpr.code)
        val overwriteMatch = hasHostOverwrite(m)
        if (guardMatch.isDefined) return Some((target, "OPEN", s"guard-dominance candidate: ${guardMatch.get}"))
        if (overwriteMatch.isDefined) return Some((target, "BROKEN", s"host overwritten: ${overwriteMatch.get}"))
        var effect = "PRESERVES"; var note = ""
        val seen = scala.collection.mutable.Set[Long]()
        cleanFlows.foreach { f =>
          f.elements.foreach { e =>
            val isIdentifier = e.isInstanceOf[nodes.Identifier]
            if (!isIdentifier) {
              val directCallOpt: Option[nodes.Call] = e match {
                case c: nodes.Call if (!c.name.startsWith("<operator>") || isConstructorCall(c)) && !familyOf(c).isDefined => Some(c)
                case _ => None
              }
              val ecOpt = directCallOpt.orElse(enclosingCallOf(e).filter(c => (!c.name.startsWith("<operator>") || isConstructorCall(c)) && !familyOf(c).isDefined))
              ecOpt.foreach { c =>
                if (!seen.contains(c.id)) {
                  seen += c.id
                  if (isUrlConstructor(c)) {
                    val cargs = c.argument.l.filter(_.argumentIndex >= 1)
                    if (cargs.size >= 2 && !cargs.headOption.exists(_.isInstanceOf[nodes.Literal]) && effect != "BREAKS") {
                      effect = "UNKNOWN"; note = "two-arg new URL(x, base) not resolvable"
                    }
                  } else if (isConstructorCall(c)) {
                    if (effect == "PRESERVES") { effect = "UNKNOWN"; note = s"unrecognized constructor: ${c.code.take(50)}" }
                  } else {
                    val calleeShort = if (c.name == "<operator>.fieldAccess") c.code.split("\\.").lastOption.getOrElse(c.name) else c.name
                    if (!HOST_PRESERVING_TRANSFORM_NAMES.contains(calleeShort) && effect == "PRESERVES") {
                      effect = "UNKNOWN"; note = s"unrecognized call: $calleeShort"
                    }
                  }
                }
              }
            }
          }
        }
        val outcome = effect match { case "PRESERVES" => "ESTABLISHED"; case "BREAKS" => "BROKEN"; case _ => "OPEN" }
        return Some((target, outcome, note))
      }
    }
    None
  }

  // resolve EXACT callee identity for a call: try Joern's own call-graph resolution first
  // (call.callee); if empty, fall back to a name-uniqueness check across the CPG (the
  // trace-backed-identity pattern used throughout this project). Ambiguous (0 or 2+ matches) ->
  // None, never guessed.
  // A callee is only a usable identity if it has a real, non-empty body -- an empty Block (a
  // TypeScript overload signature declaration with no implementation) is not a callable target,
  // regardless of what Joern's raw .callee edge points to. Confirmed by direct inspection: for a
  // function with multiple TS overload signatures plus one real implementation sharing the same
  // short name, .callee can resolve to a SIGNATURE STUB (empty body) rather than the real impl,
  // silently. Filtering for a real body first is not "guessing by name" -- it is the same
  // has-a-body requirement the project's trace-identity machinery has always applied
  // (transform_identity.tsv's "body" field exists for exactly this reason).
  def hasRealBody(m: nodes.Method): Boolean = m.ast.isIdentifier.nonEmpty || m.ast.isCall.filter(!_.name.startsWith("<operator>")).nonEmpty

  def resolveExactCallee(c: nodes.Call): Option[nodes.Method] = {
    val direct = c.callee.l.filter(hasRealBody)
    if (direct.size == 1) return Some(direct.head)
    if (direct.size > 1) return None
    // jssrc2cpg disambiguates multiple same-named declarations in one scope (e.g. TS function
    // overload signatures plus the real implementation) by appending a numeric suffix to the
    // name ("setUserAvatar", "setUserAvatar1", "setUserAvatar2" for the real impl) -- a lookup
    // using the call's own literal source text will never match the suffixed real implementation.
    // Confirmed by direct inspection. Search base-name-plus-optional-numeric-suffix, scoped to the
    // SAME FILE as the call site (to avoid matching an unrelated same-named function elsewhere),
    // filtered for a real body, and still require exact uniqueness -- never guessed if more than
    // one real-bodied candidate remains.
    val callFile = c.file.name.headOption
    val namePattern = ("^" + java.util.regex.Pattern.quote(c.name) + "\\d*$").r
    val byName = cpg.method.l
      .filter(m => namePattern.matches(m.name))
      .filter(m => callFile.isEmpty || m.file.name.headOption == callFile)
      .filter(hasRealBody)
    if (byName.size == 1) Some(byName.head) else None
  }

  // Multiple Identifier nodes for the same parameter name can exist within a method body (e.g. a
  // validation call like `check(dataURI, String)` alongside the actual use-site that reaches the
  // sink) -- picking "the first" is unreliable, confirmed by direct trace inspection (same defect
  // class fixed in Stage 2's property-effects classifier). Try every reference.
  def allReferencesOf(paramName: String, m: nodes.Method): List[nodes.Expression] =
    m.ast.isIdentifier.name(paramName).l

  // INTERPROCEDURAL SEARCH: given a source expression in method m, either classify it directly
  // (within-function), or find exact-identity calls taking it as an argument and recurse into the
  // corresponding callee parameter. Bounded depth. Returns the full hop chain on success.
  case class ProvResult(target: SinkTarget, outcome: String, note: String, chain: List[String])
  def search(srcExpr: nodes.Expression, m: nodes.Method, depth: Int, chain: List[String]): Option[ProvResult] = {
    classifyWithinFunction(srcExpr, m).foreach { case (t, outcome, note) =>
      return Some(ProvResult(t, outcome, note, chain :+ s"${m.name}(reaches sink directly)"))
    }
    if (depth >= MAX_HOPS) return None
    // find calls in m where srcExpr flows into an argument
    val candidateCalls = m.ast.isCall.filter(c => !c.name.startsWith("<operator>") && !familyOf(c).isDefined).l
    candidateCalls.foreach { c =>
      val cArgs = c.argument.l.filter(_.argumentIndex >= 1)
      cArgs.zipWithIndex.foreach { case (argExpr, idx) =>
        val flowsToArg = scala.util.Try {
          cpg.all.id(argExpr.id).collectAll[nodes.Expression].reachableByFlows(Iterator(srcExpr)).l
        }.getOrElse(Nil)
        if (flowsToArg.nonEmpty) {
          resolveExactCallee(c).foreach { callee =>
            val calleeParams = callee.parameter.l.filter(_.name != "this").sortBy(_.index)
            val calleeParamRefs = if (idx < calleeParams.size) allReferencesOf(calleeParams(idx).name, callee) else Nil
            calleeParamRefs.foreach { calleeParam =>
              val result = search(calleeParam, callee, depth + 1,
                chain :+ s"${m.name} -> ${callee.name} (arg $idx, exact identity)")
              if (result.isDefined) return result
            }
          }
        }
      }
    }
    None
  }

  case class OutRow(sinkId: String, sinkLine: Int, srcId: String, srcLine: Int, srcCode: String,
                     originKind: String, outcome: String, note: String, chain: String)
  val outRows = scala.collection.mutable.ListBuffer[OutRow]()
  allSources.foreach { src =>
    val m = src.node.method
    search(src.node, m, 0, Nil).foreach { result =>
      outRows += OutRow(result.target.sinkCall.id.toString, result.target.sinkCall.lineNumber.getOrElse(-1),
        src.node.id.toString, src.node.lineNumber.getOrElse(-1), src.node.code, src.originKind,
        result.outcome, result.note, result.chain.mkString(" | "))
    }
  }

  outRows.foreach(r => System.err.println(s"[$srcLabel] EMIT origin=${r.originKind} src=${r.srcCode}(L${r.srcLine}) " +
    s"sink=L${r.sinkLine} outcome=${r.outcome} chain=[${r.chain}] note=${r.note}"))
  System.err.println(s"[$srcLabel] SOURCE_PROV_COMPLETE rows=${outRows.size}")

  new java.io.File(rawDir).mkdirs()
  val sf = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/source_facts.tsv", true))
  val pr = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/propagation_relations.tsv", true))
  val po = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/property_outcome.tsv", true))
  outRows.foreach { r =>
    sf.println(Seq(r.sinkId, r.sinkLine, r.srcId, r.originKind, "ESTABLISHED", "","","","","","","").mkString("\t"))
    pr.println(Seq(r.sinkId, "", "", r.srcId, r.srcLine, r.srcCode, "", "", "").mkString("\t"))
    po.println(Seq(r.sinkId, r.srcId, r.outcome, "-1", "-1").mkString("\t"))
  }
  sf.close(); pr.close(); po.close()
}
