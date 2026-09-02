// SSRF-INTEG-R01: wires the frozen Stage-1 sink-semantics matrix and Stage-2 property-effects
// rules together into one producer that emits the SAME fact-table schema (source_facts.tsv,
// propagation_relations.tsv, property_outcome.tsv, transform_identity.tsv) consumed unchanged by
// adjudicate_js.py. No new adjudication logic here -- this is purely upstream fact production,
// exactly mirroring how export_property_propagation.sc feeds the serialize-DoS adjudicator.
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

// ===== Stage 1 (frozen): sink semantics =====
val HOST_PRESERVING_TRANSFORM_NAMES = Set("trim", "toLowerCase", "toUpperCase",
  "decodeURIComponent", "String", "hostname")
val COMPARISON_OPS = Set("<operator>.equals", "<operator>.strictEquals")
val ALLOWLIST_METHODS = Set("includes", "has")
val SOURCE_PATTERN = "(req|request)\\.(body|query|params|headers|payload|url)(\\..*)?"
val MESSAGE_SOURCE_PATTERN = "(message|item)\\.(urls|text|attachments)(\\..*)?"

@main def exec(cpgFile: String, rawDir: String, srcLabel: String, browserSourceTsv: String = "") = {
  importCpg(cpgFile)
  implicit val ec: EngineContext = EngineContext()

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
      val lhs = fa.argument(1)
      val rhs = fa.argument(2)
      lhs match {
        case fld: nodes.Call if fld.name == "<operator>.fieldAccess" =>
          val fieldName = fld.code.split("\\.").lastOption.getOrElse("")
          if (keys.contains(fieldName)) return Some((fieldName, rhs))
        case _ =>
      }
    }
    None
  }

  // returns (destinationOperandExpr, isPathOnly) for each sink call found, per the frozen
  // sink-semantics rules -- PATH_ONLY entries are never treated as host-bearing.
  case class SinkTarget(sinkCall: nodes.Call, family: String, destExpr: nodes.Expression, isHostBearing: Boolean)
  val sinkTargets = scala.collection.mutable.ListBuffer[SinkTarget]()
  cpg.call.l.foreach { c =>
    familyOf(c).foreach { fam =>
      val args = c.argument.l.filter(_.argumentIndex >= 1)
      args.headOption.foreach { a0 =>
        val isConstructorArg = a0.ast.isCall.filter(_.name == "<operator>.new").nonEmpty
        val isObjectLiteralArg = !isConstructorArg &&
          (a0.astChildren.isCall.name("<operator>.assignment").nonEmpty || a0.code.trim.startsWith("{"))
        if (!isObjectLiteralArg) {
          sinkTargets += SinkTarget(c, fam, a0, true)
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
            case (Some((_, hv)), _) => sinkTargets += SinkTarget(c, fam, hv, true)
            case (None, Some((_, uv))) => sinkTargets += SinkTarget(c, fam, uv, true)
            case (None, None) => // no host-bearing field -- correctly nothing added
          }
        }
      }
    }
  }
  System.err.println(s"[$srcLabel] sink targets found: ${sinkTargets.size}")
  sinkTargets.foreach(t => System.err.println(s"  family=${t.family} sink_line=${t.sinkCall.lineNumber.getOrElse(-1)} dest=${t.destExpr.code.take(60)}"))

  // ===== Stage 2 (frozen): property effects =====
  def isConstructorCall(c: nodes.Call): Boolean = c.name == "<operator>.new"
  def isUrlConstructor(c: nodes.Call): Boolean = isConstructorCall(c) && c.code.startsWith("new URL(")

  def sinkIsGuardedBy(sinkCall: nodes.Call, trackedCode: String): Option[String] = {
    // A comparison only counts as a genuine VALUE guard if the tracked identifier is a DIRECT
    // operand of THAT SPECIFIC comparison (not merely present somewhere in a larger &&-joined
    // condition where a DIFFERENT sub-comparison happens to match), and that comparison is not a
    // typeof/instanceof check (which constrains representation/type, not the chosen value).
    def isGenuineValueGuard(cmp: nodes.Call): Boolean = {
      val operands = cmp.argument.l
      val directOperand = operands.exists(_.code.trim == trackedCode.trim)
      val isTypeCheck = operands.exists {
        case c: nodes.Call => c.code.trim.startsWith("typeof ") || c.name == "<operator>.instanceOf"
        case _ => false
      }
      directOperand && !isTypeCheck
    }
    def isGenuineAllowlistGuard(m: nodes.Call): Boolean = {
      // e.g. allowedHosts.includes(trackedCode) / allowed.has(trackedCode) -- the tracked
      // identifier must be a direct ARGUMENT to the allowlist method call itself.
      m.argument.l.exists(_.code.trim == trackedCode.trim)
    }
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
            val genuineAllowlist = cond.toList.flatMap(_.ast.isCall.filter(c => ALLOWLIST_METHODS.contains(c.name)).l)
              .find(isGenuineAllowlistGuard)
            (genuineComparison, genuineAllowlist) match {
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

  def classifyStringBuild(c: nodes.Call, trackedCode: String): Option[String] = {
    if (c.name == "<operator>.addition") {
      val args = c.argument.l.sortBy(_.argumentIndex)
      if (args.size == 2) {
        val left = args(0); val right = args(1)
        if (right.code.trim == trackedCode && left.isInstanceOf[nodes.Literal]) {
          val prefix = left.code.stripPrefix("'").stripPrefix("\"").stripSuffix("'").stripSuffix("\"")
          val hasScheme = prefix.matches("^https?://.+")
          val hostClosed = hasScheme && prefix.stripPrefix("http://").stripPrefix("https://").contains("/")
          if (hasScheme && hostClosed) return Some("PATH")
          if (hasScheme) return Some("HOST")
        }
      }
    } else if (c.name == "<operator>.formatString") {
      val args = c.argument.l.sortBy(_.argumentIndex)
      val trackedIdx = args.indexWhere(_.code.trim == trackedCode)
      if (trackedIdx > 0) {
        val precedingLiterals = args.take(trackedIdx).collect { case l: nodes.Literal => l.code.stripPrefix("\"").stripSuffix("\"") }
        val prefix = precedingLiterals.mkString("")
        val hasScheme = prefix.matches("^https?://.*")
        val hostClosed = hasScheme && prefix.stripPrefix("http://").stripPrefix("https://").contains("/")
        if (hasScheme && hostClosed) return Some("PATH")
        if (hasScheme) return Some("HOST")
      }
    }
    None
  }

  def hasHostOverwrite(m: nodes.Method): Option[String] = {
    val assigns = m.ast.isCall.name("<operator>.assignment").l
    assigns.find { a =>
      val lhs = a.argument(1); val rhs = a.argument(2)
      val isHostField = lhs match {
        case fld: nodes.Call if fld.name == "<operator>.fieldAccess" =>
          val fieldName = fld.code.split("\\.").lastOption.getOrElse("")
          fieldName == "hostname" || fieldName == "host"
        case _ => false
      }
      isHostField && rhs.isInstanceOf[nodes.Literal]
    }.map(_.code)
  }

  def enclosingCallOf(n: nodes.AstNode): Option[nodes.Call] = {
    var cur: nodes.AstNode = n; var hops = 0
    while (hops < 10) {
      val p = scala.util.Try(cur.astParent).toOption
      p match { case Some(c: nodes.Call) => return Some(c); case Some(null) => return None
                case Some(pp) => cur = pp; hops += 1; case None => return None }
    }
    None
  }

  def lookupKeyInfluence(m: nodes.Method, srcExpr: nodes.Expression, sinkExprs: List[nodes.Expression],
                          otherSinkArgIds: Set[Long]): Option[String] = {
    val keyUses = srcExpr.ast.l.collect { case id: nodes.Identifier => id }
      .flatMap(id => enclosingCallOf(id))
      .filter(c => (!c.name.startsWith("<operator>") || c.name == "<operator>.indexAccess") && !familyOf(c).isDefined)
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

  // ===== SOURCE-PROV-R01: ingress-boundary detection (NOT name-based guessing) =====
  // Meteor.methods({...}) registers functions that are externally invocable by any connected
  // client. EVERY parameter of a method registered this way is attacker-controlled by
  // construction -- this is established by recognizing the REGISTRATION MECHANISM itself, not by
  // pattern-matching a parameter's name against a "looks dangerous" list.
  def findIngressParams(): List[nodes.MethodParameterIn] = {
    val registrations = cpg.call.code(".*Meteor\\.methods.*").filter(_.name != "Meteor.methods").l
    val meteorMethodsCalls = cpg.call.name("Meteor.methods").l ++
      cpg.call.filter(_.code.startsWith("Meteor.methods")).l
    val objArgs = meteorMethodsCalls.flatMap(_.argument.l.filter(a => a.argumentIndex == 1)).distinct
    val registeredNames = objArgs.flatMap { obj =>
      obj.ast.isCall.name("<operator>.assignment").l.flatMap { assign =>
        val rhs = assign.argument(2)
        rhs match {
          case id: nodes.Identifier => Some(id.name)
          case ref: nodes.MethodRef => Some(ref.methodFullName.split("[:.]").lastOption.getOrElse(ref.code))
          case _ => None
        }
      }
    }.distinct
    System.err.println(s"  Meteor.methods ingress registrations found: ${registeredNames.mkString(",")}")
    registeredNames.flatMap { name =>
      cpg.method.name(name).parameter.filter(_.name != "this").l
    }
  }
  // ===== TS-OVERLOAD-R01: structural overload-to-implementation resolver (frozen, no name-suffix
  // heuristic -- see resolve_ts_overload.sc for the standalone, fixture-verified version this is
  // copied from verbatim) =====
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
        if (withBody.size == 1) Some(withBody.head) else None  // ambiguous or none -> abstain
      }
    }
  }
  // bridge: when a call's naive .callee resolves to a body-less overload stub but the structural
  // resolver finds exactly one real implementation, treat that implementation's matching-position
  // parameter as reachable from whatever reaches the call's corresponding argument. This is a
  // ONE-HOP bridge (not general recursion) -- sufficient for the diagnosed blocker, and bounded so
  // it cannot silently chain through multiple ambiguous redirects.
  // bridge: computed ONCE, up front, not per (source, sink) pair. For each body-less overload
  // stub call site, check with a SINGLE batched reachableByFlows call (all established sources at
  // once, not one query per source) whether ANY established source reaches its argument; if so,
  // and the structural resolver finds exactly one real implementation, add that implementation's
  // matching-position parameter identifier refs to the source pool -- they then flow through the
  // ordinary per-sink pairing loop exactly like any other source, with no further special-casing.
  def computeOverloadBridgedSources(allSources: List[nodes.Expression]): List[nodes.Expression] = {
    val stubCalls = cpg.call.filter(c => c.callee.headOption.exists(callee => bodyChildCount(callee) == 0)).l
    System.err.println(s"  overload-stub calls found: ${stubCalls.size}")
    if (allSources.isEmpty || stubCalls.isEmpty) Nil
    else stubCalls.flatMap { c =>
      resolveOverloadImplementation(c) match {
        case Some(realImpl) if c.callee.headOption.exists(_.id != realImpl.id) =>
          val args = c.argument.l.filter(_.argumentIndex >= 1)
          val argsWithFlow = args.filter { arg =>
            scala.util.Try {
              cpg.all.id(arg.id).collectAll[nodes.Expression]
                .reachableByFlows(allSources.iterator).l.nonEmpty
            }.getOrElse(false)
          }
          argsWithFlow.flatMap { arg =>
            val paramIdx = arg.argumentIndex
            realImpl.parameter.filter(_.index == paramIdx).flatMap(p =>
              realImpl.ast.isIdentifier.name(p.name).l).map(id => id: nodes.Expression)
          }
        case _ => Nil
      }
    }
  }

  // JS-SSRF-SOURCE-R01/R02: optional identity bridge from the portable source
  // sidecar. The Python adapter has already enforced origin/target/location and
  // derivation purity. Revalidate the CPG node shape here and add only the
  // concrete URL read expression to the ordinary SSRF source pool. This does
  // NOT assert reachability or host-control preservation; the unchanged logic
  // below must still establish both.
  val allowedBrowserLocations = Set("tabs.onCreated.tab.url",
    "tabs.onUpdated.changeInfo.url", "tabs.onUpdated.tab.url")
  case class PortableBrowserRow(nodeId: Long, origin: String, target: String, location: String)
  val portableBrowserRows: List[PortableBrowserRow] =
    if (browserSourceTsv.trim.isEmpty) Nil
    else {
      val source = scala.io.Source.fromFile(browserSourceTsv)
      try source.getLines().filter(_.trim.nonEmpty).zipWithIndex.map { case (line, i) =>
        val cols = line.split("\\t", -1)
        if (cols.length != 4) throw new IllegalArgumentException(
          s"browser source TSV line ${i + 1}: expected 4 columns, got ${cols.length}")
        val nodeId = cols(0).toLong
        val tabUrl = cols(1) == "WEBEXT_TAB_URL_INPUT" && cols(2) == "STATE_READ" &&
          allowedBrowserLocations.contains(cols(3))
        val externalMessage = cols(1) == "WEBEXT_EXTERNAL_MESSAGE_INPUT" &&
          cols(2) == "PARAMETER" && cols(3) == "runtime.onMessageExternal"
        if (!tabUrl && !externalMessage)
          throw new IllegalArgumentException(s"browser source TSV line ${i + 1}: impure source class")
        PortableBrowserRow(nodeId, cols(1), cols(2), cols(3))
      }.toList finally source.close()
    }
  if (portableBrowserRows.map(_.nodeId).distinct.size != portableBrowserRows.size)
    throw new IllegalArgumentException("duplicate portable browser source node id")
  val portableBrowserSourceFamilies: List[(nodes.Expression, String)] = portableBrowserRows.flatMap { row =>
    if (row.origin == "WEBEXT_TAB_URL_INPUT") {
      val matches = cpg.all.id(row.nodeId).collectAll[nodes.Expression].l.distinctBy(_.id)
      if (matches.size != 1) throw new IllegalArgumentException(
        s"portable browser source node ${row.nodeId} resolved to ${matches.size} expressions")
      matches.head match {
        case c: nodes.Call if c.name == "<operator>.fieldAccess" &&
            c.code.split("\\.").lastOption.contains("url") => List((c: nodes.Expression, row.origin))
        case other => throw new IllegalArgumentException(
          s"portable browser source node ${row.nodeId} is not a literal .url field read: ${other.code}")
      }
    } else {
      val params = cpg.all.id(row.nodeId).collectAll[nodes.MethodParameterIn].l.distinctBy(_.id)
      if (params.size != 1) throw new IllegalArgumentException(
        s"portable external-message parameter ${row.nodeId} resolved to ${params.size} parameters")
      val p = params.head
      if (p.index != 1) throw new IllegalArgumentException(
        s"portable external-message parameter ${row.nodeId} is not payload index 1")
      val exactRefs = p.method.ast.isIdentifier.nameExact(p.name).l
        .filter(i => i.refOut.l.exists(_.id == p.id))
      // Joern does not always propagate a base-object identifier into the fieldAccess
      // expression that directly contains it. Carry both identities, but only for a
      // one-hop field read whose base argument is THIS exact REF-linked identifier.
      // This is use-scoped expansion, not a same-name or sibling-field guess.
      val directFieldReads = exactRefs.flatMap { i =>
        scala.util.Try(i.astParent).toOption.collect {
          case c: nodes.Call if c.name == "<operator>.fieldAccess" &&
              c.argument.l.exists(a => a.argumentIndex == 1 && a.id == i.id) => c: nodes.Expression
        }
      }
      (exactRefs.map(i => i: nodes.Expression) ++ directFieldReads).distinctBy(_.id)
        .map(i => (i, row.origin))
    }
  }
  val conflictingPortableFamilies = portableBrowserSourceFamilies.groupBy(_._1.id)
    .filter { case (_, xs) => xs.map(_._2).distinct.size != 1 }
  if (conflictingPortableFamilies.nonEmpty)
    throw new IllegalArgumentException("portable browser source expression belongs to multiple source classes")
  val portableBrowserSources: List[nodes.Expression] = portableBrowserSourceFamilies.map(_._1).distinctBy(_.id)
  val portableFamilyByNode = portableBrowserSourceFamilies.map { case (expr, family) =>
    expr.id -> family
  }.toMap
  val sourceCallsFieldAccess = cpg.call.name("<operator>.fieldAccess").code(s"($SOURCE_PATTERN)|($MESSAGE_SOURCE_PATTERN)").l
  val ingressParams = findIngressParams()
  // an ingress parameter's identity must propagate via its identifier REFERENCES within its own
  // method body (MethodParameterIn is not itself an Expression in Joern's schema -- same lesson
  // learned building the Stage-2 property-effects characterization).
  val ingressParamSources: List[nodes.Expression] = ingressParams.flatMap { p =>
    p.method.ast.isIdentifier.name(p.name).l.map(id => id: nodes.Expression)
  }
  val baseSourceCalls: List[nodes.Expression] =
    sourceCallsFieldAccess.map(c => c: nodes.Expression) ++ ingressParamSources ++ portableBrowserSources
  // TS-OVERLOAD-R01 bridge: computed once here, added to the source pool before the main pairing
  // loop runs -- NOT re-tested per (source, sink) pair, which is what made the naive version time out.
  val overloadBridged = computeOverloadBridgedSources(baseSourceCalls)
  System.err.println(s"[$srcLabel] overload-bridged sources added: ${overloadBridged.size}")
  val sourceCalls: List[nodes.Expression] = (baseSourceCalls ++ overloadBridged).distinct
  System.err.println(s"[$srcLabel] source candidates found: ${sourceCalls.size} " +
    s"(field-access: ${sourceCallsFieldAccess.size}, ingress-param refs: ${ingressParamSources.size}, " +
    s"portable-browser-tab-url: ${portableBrowserSourceFamilies.count(_._2 == "WEBEXT_TAB_URL_INPUT")}, " +
    s"portable-browser-external-message: ${portableBrowserSourceFamilies.count(_._2 == "WEBEXT_EXTERNAL_MESSAGE_INPUT")}, " +
    s"overload-bridged: ${overloadBridged.size})")

  case class OutRow(sinkId: String, sinkLine: Int, srcId: String, srcLine: Int, srcCode: String,
                     outcome: String, transformChain: List[(nodes.Call, String)], note: String)
  val outRows = scala.collection.mutable.ListBuffer[OutRow]()

  sinkTargets.filter(_.isHostBearing).foreach { target =>
    val sinkCall = target.sinkCall
    val destExpr = target.destExpr
    val m = sinkCall.method
    sourceCalls.foreach { src =>
      {  // SOURCE-PROV-R01: same-function restriction removed. Joern's reachableByFlows already
         // performs genuine interprocedural tracing (parameter->argument, return->caller) -- this
         // was an artificial restriction added for tractability, not a real engine limitation,
         // confirmed by this session's earlier cross-file customs.js/o1 trace.
        val flowsRaw = scala.util.Try {
          cpg.all.id(destExpr.id).collectAll[nodes.Expression]
            .reachableByFlows(Iterator(src: nodes.Expression)).l
        }.getOrElse(Nil)
        // SIBLING-ARGUMENT ARTIFACT FILTER: reachableByFlows can report a path that detours
        // through the sink call's OTHER argument (e.g. the request BODY) before "landing" on
        // destExpr (e.g. the host argument) -- this is a dataflow-engine imprecision (confirmed by
        // direct trace inspection: req.query.state genuinely flows into the JSON body, a sibling
        // argument, and the engine connects that to the unrelated host argument via the shared
        // call node), not a genuine host-control path. Discard any flow whose element sequence
        // contains one of the sink call's OTHER arguments as an intermediate step.
        //
        // SSRF-INTEG-R01-FIX02 (found via real-world validation against mozilla/fxa's own
        // fxa-profile-server, not a synthetic fixture -- see this file's own FIX02/FIX03 comments
        // below for the fuller disclosure of why): the original filter excluded only the OTHER
        // argument's OWN node id, not its descendants. `fetch(url, { headers: worker_headers,
        // body: payload })` genuinely has req.headers/req.payload reach the CALL (via the real
        // callee img-workers.js's own `headers`/`payload` parameters, correctly resolved) -- but
        // they land inside the SECOND argument's own object-literal subtree (the `headers:`
        // property value), never on `url` (the first argument, this call's own destExpr). The
        // original filter's `.map(_.id)` only ever excluded the second argument's own outer node,
        // never nodes INSIDE it, so this detour slipped through undetected. Fixed by excluding the
        // OTHER argument's entire AST subtree (`.ast.id.l`), not just its own node -- confirmed via
        // a same-fixture regression run (fixtures/ssrf_r01/) that this produces byte-identical row
        // counts to before the fix (none of that fixture's own cases exercise a multi-property
        // options object), and via a direct re-run against fxa-profile-server that this speciic
        // false positive (req.headers from upload.js:56) is gone afterward.
        val otherSinkArgIds = sinkCall.argument.l.filter(_.argumentIndex >= 1)
          .filterNot(_.id == destExpr.id).flatMap(_.ast.id.l).toSet
        val flowsSiblingFiltered = flowsRaw.filterNot { f =>
          f.elements.dropRight(1).exists(e => otherSinkArgIds.contains(e.id))
        }
        // SSRF-INTEG-R01-FIX03 (found via the same real-world validation, a materially more
        // severe defect than FIX02): a genuine same-short-name-different-function collision --
        // two structurally unrelated functions (in this case, img-workers.js's own real
        // `exports.upload` and a completely separate Hapi route handler in server/worker.js, also
        // named `upload`, purely by coincidence) get conflated by Joern's own automatic
        // interprocedural call-linking (the same root-cause CLASS already diagnosed and fixed once
        // in this project for NoSQLi's AJV-gate detector's "action" collision -- see
        // NOSQLI_SCANNER_FIXES.md -- but THAT fix was over this project's own custom Scala
        // resolution; here the ambiguity is baked into Joern's own built-in call graph, which this
        // producer never overrides, so the fix here is a post-hoc validator, not a swap to
        // `.referencedMethod`). A flow that crosses from the source's own enclosing method into a
        // DIFFERENT enclosing method (the sink's) is only trusted if the flow's OWN reported path
        // is corroborated by a REAL call site: specifically, the last element of the flow that is
        // still within the SOURCE's own enclosing method (the "exit point" -- using the flow's own
        // elements, not a fresh independent trace, so a real flow via an intermediate local
        // variable inside the source's own method is still correctly recognized) must itself be a
        // real ARGUMENT (matched by node id, never by code text or name alone -- two unrelated
        // `req.payload` expressions in two unrelated route handlers are textually identical, which
        // is exactly how this defect's own false positive slipped through a text-based check
        // during investigation) of some call whose own NAME matches the sink method's name. For a
        // genuinely unrelated function sharing a name (never actually called from the source's own
        // method, only coincidentally similarly named), no such real call site exists and the flow
        // is discarded. Verified: this exact real fxa-profile-server false positive (req.params.id/
        // req.payload from server/worker.js:64, a wholly separate module, attributed to
        // img-workers.js:46's fetch() call) is gone after this fix, while the same fixture's own
        // genuine intra-package flows (and every WebExtension bridge gate) are unaffected.
        def crossMethodFlowIsReal(f: Path): Boolean = {
          val srcMethod = src.method
          if (srcMethod.id == m.id) return true  // no interprocedural crossing to validate
          val elementsInSrcMethod = f.elements.collect {
            case cfg: nodes.CfgNode if scala.util.Try(cfg.method.id).toOption.contains(srcMethod.id) => cfg
          }
          val bridgeNodeId = elementsInSrcMethod.lastOption.map(_.id).getOrElse(src.id)
          cpg.call.l.exists(c => c.name == m.name && c.argument.l.exists(_.id == bridgeNodeId))
        }
        // SSRF-INTEG-R01-FIX04 (found by directly querying the exact flow path of the false
        // positive FIX02/FIX03 alone did not close, not by guessing): the sibling-argument-
        // artifact class recurs at ANY intermediate call the flow passes through, not only the
        // final sink call FIX02 already guards. Direct inspection of this specific flow's own
        // elements (a live Joern query against the real fxa-profile-server CPG) showed it jumping
        // from `worker_headers` -- argument 2 of the fire-and-forget `logger.debug('upload.headers',
        // worker_headers)` -- directly to `logger`, THAT SAME call's own receiver (argument 0) --
        // then AGAIN from a second, later `logger` reference to `url`, both children of the
        // unrelated, later `logger.verbose('upload', url)` call. Two separate logging calls,
        // chained only because they share the same unchanged `logger` import binding at both call
        // sites -- never a real value dependency, and neither logging call's own return value
        // (discarded in both real statements) is what the flow actually continues through.
        // Generalizes FIX02's own principle (which only ever checked the SINK call's own
        // siblings): for every CONSECUTIVE pair of elements in a flow, if both are direct
        // argument/receiver children of the SAME call node, and neither element IS that call's
        // own return value being propagated (the ordinary, legitimate case, e.g. `f(x)` used
        // later as `y = f(x)`), that pairing is a sibling-artifact hop and the whole flow is
        // discarded. Verified: this exact remaining false positive (req.headers from upload.js:56,
        // surviving FIX02/FIX03 alone) is gone after this fix; the ssrf_r01 fixture's own row
        // counts stay byte-identical (none of its cases exercise a multi-hop logging-style
        // detour), and every WebExtension bridge gate still passes unchanged.
        // Exemption found while verifying FIX04 against this file's own regression fixture: Joern
        // represents assignment, field access, constructor calls, etc. as CALL nodes internally
        // (`<operator>.assignment`, `<operator>.new`, ...), and their own LHS/RHS or arguments
        // legitimately share a parent call node for genuine SYNTACTIC reasons -- `const u = new
        // URL(userInput)` desugars to `userInput` (the constructor's argument) and a synthetic
        // `_tmp_N` result temp BOTH hanging off the `<operator>.new` call, and separately `u`
        // (LHS) and that same temp (RHS) both hanging off the enclosing `<operator>.assignment`
        // call -- real value-flow relationships, not artifacts. Confirmed by direct flow
        // inspection: the hostOverwritten fixture case (a real BROKEN control) was being
        // incorrectly discarded entirely before this exemption. The real bug this fix targets
        // (fire-and-forget calls like `logger.debug(x, y)` whose return value is never used, so a
        // LATER, unrelated use of the same receiver at a DIFFERENT call site gets spuriously
        // connected) only ever involves NAMED, user-level function/method calls -- so this filter
        // is scoped to calls whose own name does NOT start with "<operator>" at all, never
        // Joern's own internal operator desugaring.
        // Second exemption, also found while verifying FIX04 against this file's own regression
        // fixture: the SAME "argument and a synthetic `_tmp_N` result-binding temp both hang off
        // the same call node" desugaring applies to REGULAR named calls too, not just operators/
        // constructors -- `const processed = someExternalNormalizer(userInput)` binds its own
        // result the same way. `_tmp_N` is jssrc2cpg's own established synthetic-temp naming
        // convention (already relied on elsewhere in this project -- see
        // NOSQLI_SINK_SEMANTICS_MATRIX.md's own real "`_tmp_9`" bug investigation), so a node
        // matching it is always a call's own return-value binding, never a genuinely independent
        // sibling argument -- exempted alongside the operator-name exemption above.
        // Third exemption, same regression-fixture verification pass: jssrc2cpg represents every
        // STANDALONE (non-member) function call, e.g. `someExternalNormalizer(userInput)`, with a
        // synthetic `this` receiver argument even though the source has no explicit receiver at
        // all -- another stable jssrc2cpg convention (not a guess: JavaScript call semantics
        // always bind SOME `this`, jssrc2cpg makes that binding explicit in the CPG), so a literal
        // `this` identifier sharing a call parent with the tracked value is never a genuine
        // second, independent argument -- exempted alongside the other two.
        def isCallResultTemp(n: nodes.AstNode): Boolean = n match {
          case id: nodes.Identifier => id.name.matches("_tmp_\\d+") || id.name == "this"
          case _ => false
        }
        def passThroughSiblingArtifact(f: Path): Boolean = {
          f.elements.sliding(2).exists {
            case Seq(e1, e2) =>
              val call1 = scala.util.Try(e1.astParent).toOption.collect { case c: nodes.Call => c }
              val call2 = scala.util.Try(e2.astParent).toOption.collect { case c: nodes.Call => c }
              (call1, call2) match {
                case (Some(c1), Some(c2)) if c1.id == c2.id
                  && !c1.name.startsWith("<operator>")
                  && !isCallResultTemp(e1) && !isCallResultTemp(e2) => true
                case _ => false
              }
            case _ => false
          }
        }
        val flows = flowsSiblingFiltered.filter(crossMethodFlowIsReal).filterNot(passThroughSiblingArtifact)
        if (flows.nonEmpty) {
          val guardMatch = sinkIsGuardedBy(sinkCall, src.code)
          val overwriteMatch = hasHostOverwrite(m)
          val sinkExprs = cpg.all.id(destExpr.id).collectAll[nodes.Expression].l
          if (guardMatch.isDefined) {
            outRows += OutRow(sinkCall.id.toString, sinkCall.lineNumber.getOrElse(-1), src.id.toString,
              src.lineNumber.getOrElse(-1), src.code, "OPEN", Nil,
              s"guard-dominance candidate (v1 syntactic approximation, not confirmed): ${guardMatch.get}")
          } else if (overwriteMatch.isDefined) {
            outRows += OutRow(sinkCall.id.toString, sinkCall.lineNumber.getOrElse(-1), src.id.toString,
              src.lineNumber.getOrElse(-1), src.code, "BROKEN", Nil,
              s"host overwritten by literal assignment: ${overwriteMatch.get}")
          } else {
            var effect = "PRESERVES"
            var note = ""
            val transformChain = scala.collection.mutable.ListBuffer[(nodes.Call, String)]()
            val seen = scala.collection.mutable.Set[Long]()
            flows.foreach { f =>
              // ITERATOR-EXTRACTION RECOGNITION (structurally verified per flow, not a blanket
              // trust of any call named "next"/"value" anywhere): only when THIS SPECIFIC flow
              // demonstrably contains an <operator>.iterator call whose OWN argument is the
              // tracked source itself, treat subsequent .next()/.value calls in THIS SAME flow as
              // preserving -- extracting an element from an array via the standard iteration
              // protocol does not substitute a different, server-controlled value when the array
              // itself is the tracked (attacker-authored) source.
              val hasVerifiedIteratorOnSource = f.elements.exists {
                case c: nodes.Call if c.name == "<operator>.iterator" =>
                  c.argument.l.exists(_.code.trim == src.code.trim)
                case _ => false
              }
              f.elements.foreach { e =>
                val isIdentifier = e.isInstanceOf[nodes.Identifier]
                val isStringBuildOp = e.isInstanceOf[nodes.Call] &&
                  (e.asInstanceOf[nodes.Call].name == "<operator>.addition" ||
                   e.asInstanceOf[nodes.Call].name == "<operator>.formatString")
                if (isStringBuildOp) {
                  val c = e.asInstanceOf[nodes.Call]
                  if (!seen.contains(c.id)) {
                    seen += c.id
                    val sb = classifyStringBuild(c, src.code)
                    if (sb.contains("PATH")) { effect = "BREAKS"; note = s"fixed-origin prefix closes host: ${c.code.take(60)}" }
                    else if (sb.isEmpty && effect == "PRESERVES") { effect = "UNKNOWN"; note = s"unrecognized string-build: ${c.code.take(60)}" }
                    transformChain += ((c, "string-build"))
                  }
                } else if (!isIdentifier) {
                  val directCallOpt: Option[nodes.Call] = e match {
                    case c: nodes.Call if (!c.name.startsWith("<operator>") || isConstructorCall(c)) && !familyOf(c).isDefined => Some(c)
                    case _ => None
                  }
                  val ecOpt = directCallOpt.orElse {
                    val ec2 = enclosingCallOf(e)
                    ec2.filter(c => (!c.name.startsWith("<operator>") || isConstructorCall(c)) && !familyOf(c).isDefined)
                  }
                  ecOpt.foreach { c =>
                    if (!seen.contains(c.id)) {
                      seen += c.id
                      val isIteratorProtocolCall = hasVerifiedIteratorOnSource && (c.name == "next" ||
                        (c.name == "<operator>.fieldAccess" && c.code.split("\\.").lastOption.contains("value")))
                      if (isIteratorProtocolCall) {
                        // recognized as part of a verified array-extraction chain -- preserving
                        transformChain += ((c, "iterator-protocol-extraction"))
                      } else if (isUrlConstructor(c)) {
                        val args = c.argument.l.filter(_.argumentIndex >= 1)
                        val firstArgIsLiteral = args.headOption.exists(_.isInstanceOf[nodes.Literal])
                        if (args.size >= 2 && !firstArgIsLiteral && effect != "BREAKS") {
                          effect = "UNKNOWN"; note = "two-arg new URL(x, base): x not a literal, not resolvable"
                        }
                        transformChain += ((c, "url-constructor"))
                      } else if (isConstructorCall(c)) {
                        // some other constructor -- treat conservatively as unrecognized
                        if (effect == "PRESERVES") { effect = "UNKNOWN"; note = s"unrecognized constructor: ${c.code.take(60)}" }
                        transformChain += ((c, "constructor"))
                      } else {
                        val calleeShort = if (c.name == "<operator>.fieldAccess")
                          c.code.split("\\.").lastOption.getOrElse(c.name) else c.name
                        val isKnownPreserving = HOST_PRESERVING_TRANSFORM_NAMES.contains(calleeShort)
                        if (!isKnownPreserving && effect == "PRESERVES") {
                          effect = "UNKNOWN"; note = s"unrecognized call: $calleeShort"
                        }
                        transformChain += ((c, calleeShort))
                      }
                    }
                  }
                }
              }
            }
            // lookup-key-influence check applies when the DIRECT flow found nothing informative
            // but is still relevant to double check -- run it regardless as an additional signal
            val lookupNote = lookupKeyInfluence(m, src, sinkExprs, otherSinkArgIds)
            val finalOutcome = effect match {
              case "PRESERVES" => "ESTABLISHED"
              case "BREAKS" => "BROKEN"
              case "UNKNOWN" => "OPEN"
              case _ => "OPEN"
            }
            outRows += OutRow(sinkCall.id.toString, sinkCall.lineNumber.getOrElse(-1), src.id.toString,
              src.lineNumber.getOrElse(-1), src.code, finalOutcome, transformChain.toList, note)
          }
        } else {
          // no direct flow -- check lookup-key-influence specifically (value never flows, only used as a key)
          val sinkExprs = cpg.all.id(destExpr.id).collectAll[nodes.Expression].l
          lookupKeyInfluence(m, src, sinkExprs, otherSinkArgIds).foreach { lookupCode =>
            outRows += OutRow(sinkCall.id.toString, sinkCall.lineNumber.getOrElse(-1), src.id.toString,
              src.lineNumber.getOrElse(-1), src.code, "OPEN", Nil,
              s"LOOKUP_KEY_INFLUENCE: key reaches $lookupCode, value itself does not flow to sink")
          }
        }
      }
    }
  }

  // ===== emit standard fact tables, SAME schema as export_property_propagation.sc =====
  // SSRF-INTEG-R01-FIX01 (found while wiring a Python reducer on top of this file, unmodified
  // otherwise): `r.note` (WHY a given (sink, origin) alternative was classified BROKEN/OPEN --
  // e.g. "host overwritten by literal assignment: ...", "guard-dominance candidate: ...",
  // "unrecognized call: ...") was already computed per row but only ever printed to stderr
  // (the EMIT line below) -- property_outcome.tsv's own trailing two columns were always the
  // literal placeholder "-1","-1", never carrying it. adjudicate_js.py itself confirmed (by
  // direct inspection) to only ever read columns 0/1/2 of this file (`rows("property_outcome.tsv",
  // 5)`, then only `r[0]`/`r[1]`/`r[2]`), so writing real text into column 3 is additive and safe
  // -- column 4 stays the literal "-1" placeholder, and the row stays exactly 5 columns wide
  // (changing that count would silently drop every row past adjudicate_js.py's own strict
  // len(parts)==5 filter, a far worse bug than the one being fixed here).
  def tsvSafe(s: String): String = s.replaceAll("[\\t\\n\\r]+", " ")
  new java.io.File(rawDir).mkdirs()
  val sf = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/source_facts.tsv", true))
  val pr = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/propagation_relations.tsv", true))
  val po = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/property_outcome.tsv", true))
  val ti = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/transform_identity.tsv", true))
  outRows.foreach { r =>
    val originFamily = portableFamilyByNode.getOrElse(r.srcId.toLong, "HTTP_HOST_INPUT")
    sf.println(Seq(r.sinkId, r.sinkLine, r.srcId, originFamily, "ESTABLISHED", "","","","","","","").mkString("\t"))
    pr.println(Seq(r.sinkId, "", "", r.srcId, r.srcLine, r.srcCode, "", "", "").mkString("\t"))
    po.println(Seq(r.sinkId, r.srcId, r.outcome, tsvSafe(r.note), "-1").mkString("\t"))
    r.transformChain.zipWithIndex.foreach { case ((c, kind), order) =>
      ti.println(Seq("x", r.srcId, order.toString, c.id.toString, kind, "", "", "UNKNOWN").mkString("\t"))
    }
    System.err.println(s"[$srcLabel] EMIT sink=${r.sinkId}(L${r.sinkLine}) src=${r.srcId}(L${r.srcLine}:${r.srcCode}) outcome=${r.outcome} note=${r.note}")
  }
  sf.close(); pr.close(); po.close(); ti.close()
  System.err.println(s"[$srcLabel] SSRF_INTEG_COMPLETE rows=${outRows.size}")
}
