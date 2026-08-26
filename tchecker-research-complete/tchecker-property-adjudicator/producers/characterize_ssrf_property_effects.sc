// SSRF-PROP-R01: property-effects classifier for ATTACKER_CONTROL_OF_REQUEST_HOST.
// Rule frozen per the design brief: NORMALIZATION IS NOT RESTRICTION. new URL(x), .trim(),
// .toLowerCase(), decodeURIComponent(x), String(x) all PRESERVE/TRANSFORM host control -- they
// change representation, not the attacker's ability to choose the host. Only a genuine
// RESTRICTION (fixed-prefix concatenation that already contains a complete origin, an assignment
// that overwrites the host with a literal after tracked input, or a comparison/allowlist check
// that actually gates the sink call) counts as BREAKS.
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

val HOST_PRESERVING_TRANSFORM_NAMES = Set("trim", "toLowerCase", "toUpperCase",
  "decodeURIComponent", "String", "hostname")
val COMPARISON_OPS = Set("<operator>.equals", "<operator>.strictEquals")
val ALLOWLIST_METHODS = Set("includes", "has")

@main def exec(cpgFile: String, outFile: String) = {
  importCpg(cpgFile)
  implicit val ec: EngineContext = EngineContext()

  case class Row(function: String, sourceParam: String, effect: String, note: String)
  val rows = scala.collection.mutable.ListBuffer[Row]()

  def isConstructorCall(c: nodes.Call): Boolean = c.name == "<operator>.new"
  def isUrlConstructor(c: nodes.Call): Boolean = isConstructorCall(c) && c.code.startsWith("new URL(")

  // Guard-dominance check (v1 approximation: SYNTACTIC nesting inside the then-branch of an
  // IfStatement whose condition compares the tracked identifier -- not full CFG dominator-tree
  // analysis. Documented limitation: won't catch guard-then-early-return patterns several
  // statements removed, or guards expressed via helper predicate functions. Sufficient to
  // correctly distinguish the positive/negative controls in this fixture set.)
  def sinkIsGuardedBy(sinkCall: nodes.Call, trackedName: String): Option[String] = {
    var cur: nodes.AstNode = sinkCall
    var hops = 0
    while (hops < 10) {
      val parentOpt = scala.util.Try(cur.astParent).toOption
      parentOpt match {
        case Some(ifNode: nodes.ControlStructure) if ifNode.controlStructureType == "IF" =>
          val thenBlock = ifNode.astChildren.l.drop(1).headOption
          val isInThen = thenBlock.exists(_.ast.contains(sinkCall))
          if (isInThen) {
            val cond = ifNode.condition.l.headOption
            val condCode = cond.map(_.code).getOrElse("")
            val comparesTracked = condCode.contains(trackedName) &&
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

  // classify a fixed-prefix string-build (<operator>.addition or <operator>.formatString):
  // returns Some("HOST") if the tracked value lands in host position, Some("PATH") if it lands
  // after a complete origin (scheme+host) already present in the literal prefix, None if
  // unrecognized shape.
  def classifyStringBuild(c: nodes.Call, trackedArgCode: String): Option[String] = {
    if (c.name == "<operator>.addition") {
      val args = c.argument.l.sortBy(_.argumentIndex)
      if (args.size == 2) {
        val left = args(0); val right = args(1)
        if (right.code.trim == trackedArgCode && left.isInstanceOf[nodes.Literal]) {
          val prefix = left.code.stripPrefix("'").stripPrefix("\"").stripSuffix("'").stripSuffix("\"")
          // a literal prefix is a COMPLETE origin if it has scheme:// followed by a host and then
          // either nothing more or a "/" (path separator) -- i.e. the host boundary is already closed
          val hasScheme = prefix.matches("^https?://.+")
          val hostClosed = hasScheme && prefix.stripPrefix("http://").stripPrefix("https://").contains("/")
          if (hasScheme && hostClosed) return Some("PATH")
          if (hasScheme) return Some("HOST")  // scheme present but no "/" yet -- tracked value extends the host itself
        }
      }
    } else if (c.name == "<operator>.formatString") {
      val args = c.argument.l.sortBy(_.argumentIndex)
      val trackedIdx = args.indexWhere(_.code.trim == trackedArgCode)
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

  // host-overwrite detection: a LATER assignment (by line order) of a LITERAL to a `.hostname` or
  // `.host` field on the SAME expression eventually passed to the sink overrides whatever the
  // constructor established -- this is a genuine restriction, BREAKS, not merely a transform.
  def hasHostOverwrite(m: nodes.Method): Option[String] = {
    val assigns = m.ast.isCall.name("<operator>.assignment").l
    assigns.find { a =>
      val lhs = a.argument(1)
      val rhs = a.argument(2)
      val isHostField = lhs match {
        case fld: nodes.Call if fld.name == "<operator>.fieldAccess" =>
          val fieldName = fld.code.split("\\.").lastOption.getOrElse("")
          fieldName == "hostname" || fieldName == "host"
        case _ => false
      }
      isHostField && rhs.isInstanceOf[nodes.Literal]
    }.map(_.code)
  }

  // lookup-key-influence detection: the tracked value never itself reaches the sink (NO_FLOW from
  // the identifier), but it IS used as an ARGUMENT to some call whose RESULT (or a field access on
  // that result) DOES reach the sink. This is the exact RocketChat findOneById lesson: attacker
  // control of a LOOKUP KEY does not establish attacker control of the VALUE the lookup returns.
  def lookupKeyInfluence(m: nodes.Method, paramName: String, sinkArgId: Long): Option[String] = {
    val keyUses = m.ast.isIdentifier.name(paramName).l.flatMap(id => enclosingCallOf(id))
      .filter(c => (!c.name.startsWith("<operator>") || c.name == "<operator>.indexAccess") && c.name != "fetch").distinct
    val sinkExprs = cpg.all.id(sinkArgId).collectAll[nodes.Expression].l
    keyUses.flatMap { lookupCall =>
      // check reachability from the call's own result AND from any immediately-enclosing field
      // access on that call (e.g. `lookupTenant(userId).webhookUrl`) -- reachableByFlows does not
      // reliably treat a bare call node as a dataflow source, but the field-access wrapping it
      // does correctly connect through to later uses.
      val fieldAccessOnResult = scala.util.Try(lookupCall.astParent).toOption.collect {
        case fa: nodes.Call if fa.name == "<operator>.fieldAccess" => fa
      }
      val candidateSources: List[nodes.Expression] =
        (cpg.all.id(lookupCall.id).collectAll[nodes.Expression].l ++
         fieldAccessOnResult.toList.flatMap(fa => cpg.all.id(fa.id).collectAll[nodes.Expression].l))
      if (sinkExprs.isEmpty || candidateSources.isEmpty) None
      else {
        val flows = candidateSources.flatMap(src => sinkExprs.reachableByFlows(Iterator(src)).l)
        if (flows.nonEmpty) Some(lookupCall.code) else None
      }
    }.headOption
  }
  def enclosingCallOf(n: nodes.AstNode): Option[nodes.Call] = {
    var cur: nodes.AstNode = n; var hops = 0
    while (hops < 8) {
      val p = scala.util.Try(cur.astParent).toOption
      p match { case Some(c: nodes.Call) => return Some(c); case Some(null) => return None
                case Some(pp) => cur = pp; hops += 1; case None => return None }
    }
    None
  }

  def enclosingCall(n: nodes.AstNode): Option[nodes.Call] = {
    var cur: nodes.AstNode = n; var hops = 0
    while (hops < 8) {
      val p = scala.util.Try(cur.astParent).toOption
      p match { case Some(c: nodes.Call) => return Some(c); case Some(null) => return None
                case Some(pp) => cur = pp; hops += 1; case None => return None }
    }
    None
  }

  // one (functionName, sourceParamName) case per fixture -- explicit, not auto-discovered, so
  // each row is traceable to exactly the intended controlled case.
  val cases = Seq(
    ("identity", "userHost", "PRESERVES (identity)"),
    ("urlWrap", "userInput", "PRESERVES/TRANSFORMS (new URL(x), normalization not restriction)"),
    ("stringCoerce", "userInput", "PRESERVES/TRANSFORMS (String(x))"),
    ("trimmed", "userInput", "PRESERVES/TRANSFORMS (.trim())"),
    ("lowercased", "userInput", "PRESERVES/TRANSFORMS (.toLowerCase())"),
    ("decoded", "userInput", "PRESERVES/TRANSFORMS (decodeURIComponent(x))"),
    ("extractedHostname", "userInput", "PRESERVES/TRANSFORMS (new URL(x).hostname)"),
    ("templateLiteralHost", "userInput", "PRESERVES (interpolation lands in host position)"),
    ("fixedPrefixConcat", "attackerPath", "BREAKS (fixed origin literal already closes the host)"),
    ("hostOverwritten", "userInput", "BREAKS (assigned over by a fixed literal after tracked input)"),
    ("urlWithBaseAmbiguous", "userInput", "UNKNOWN (two-arg new URL(); absolute-vs-relative not resolvable)"),
    ("guardDominatesSink", "userHost", "candidate BREAKS (comparison genuinely gates the sink call)"),
    ("allowlistIncludesDominates", "userHost", "candidate BREAKS (.includes() gates the sink call)"),
    ("setHasDominates", "userHost", "candidate BREAKS (.has() gates the sink call)"),
    ("guardDoesNotDominateSink", "userHost", "PRESERVES (comparison exists but does not gate the call)"),
    ("guardOnDifferentBranch", "userHost", "PRESERVES (comparison's then-branch does not contain the call)"),
    ("lookupByUserId", "userId", "OPEN/UNKNOWN (attacker controls the LOOKUP KEY, not the returned value)"),
    ("configLookupByKey", "userKey", "OPEN/UNKNOWN (same lookup-key lesson)"),
    ("unresolvedWrapperTransform", "userInput", "UNKNOWN (unresolved external transform, abstain)")
  )

  cases.foreach { case (fnName, paramName, expected) =>
    val method = cpg.method.name(fnName).headOption
    method match {
      case None => rows += Row(fnName, paramName, "NO_METHOD_FOUND", expected)
      case Some(m) =>
        val srcParam = m.parameter.name(paramName).headOption
        val sinkCalls = m.ast.isCall.name("fetch").l
        (srcParam, sinkCalls.headOption) match {
          case (None, _) => rows += Row(fnName, paramName, "NO_SOURCE_PARAM", expected)
          case (_, None) => rows += Row(fnName, paramName, "NO_SINK_CALL", expected)
          case (Some(src), Some(sink)) =>
            val flowsTry = scala.util.Try {
              sink.argument.l.filter(_.argumentIndex >= 1).headOption match {
                case Some(sinkArg) =>
                  // MethodParameterIn is not an Expression in Joern's schema, so use identifier
                  // REFERENCES to the parameter as flow sources instead. Multiple Identifier nodes
                  // for the same parameter name can exist on the same line (e.g. a method-call
                  // receiver vs. a nearby declaration-adjacent reference) -- try ALL of them and
                  // union the results, rather than guessing which one is "first".
                  val candidateSrcExprs = m.ast.isIdentifier.name(paramName).l
                  val sinkExprs = cpg.all.id(sinkArg.id).collectAll[nodes.Expression].l
                  if (candidateSrcExprs.isEmpty || sinkExprs.isEmpty) Nil
                  else candidateSrcExprs.flatMap(srcId =>
                    sinkExprs.reachableByFlows(Iterator(srcId: nodes.Expression)).l).distinct
                case None => Nil
              }
            }
            val flows = flowsTry.getOrElse(Nil)
            if (flowsTry.isFailure) {
              rows += Row(fnName, paramName, "ERROR: " + flowsTry.failed.get.getMessage.take(80), expected)
            } else if (flows.isEmpty) {
              // before declaring NO_FLOW, check the lookup-key-influence pattern: the tracked
              // value doesn't itself reach the sink, but IS used as a key/argument to a call whose
              // result does.
              val sinkArgIdOpt = sink.argument.l.filter(_.argumentIndex >= 1).headOption.map(_.id)
              val lookupMatch = sinkArgIdOpt.flatMap(id => lookupKeyInfluence(m, paramName, id))
              lookupMatch match {
                case Some(lookupCode) =>
                  rows += Row(fnName, paramName, "UNKNOWN (LOOKUP_KEY_INFLUENCE -- key reaches: " + lookupCode + ")", expected)
                case None =>
                  rows += Row(fnName, paramName, "NO_FLOW", expected)
              }
            } else {
              // guard-dominance check first: does ANY guard structurally gate this sink call?
              val guardMatch = sinkIsGuardedBy(sink, paramName)
              val overwriteMatch = hasHostOverwrite(m)
              (guardMatch, overwriteMatch) match {
                case (Some(cond), _) =>
                  rows += Row(fnName, paramName, "BREAKS (candidate -- guarded by: " + cond + ")", expected)
                case (None, Some(assignCode)) =>
                  rows += Row(fnName, paramName, "BREAKS (host overwritten by literal assignment: " + assignCode + ")", expected)
                case (None, None) =>
                  // walk the flow, classify each transform element
                  var effect = "PRESERVES"
                  var note = ""
                  val seen = scala.collection.mutable.Set[Long]()
                  flows.foreach { f =>
                    f.elements.foreach { e =>
                      val isIdentifier = e.isInstanceOf[nodes.Identifier]
                      val isStringBuildOp = e.isInstanceOf[nodes.Call] &&
                        (e.asInstanceOf[nodes.Call].name == "<operator>.addition" ||
                         e.asInstanceOf[nodes.Call].name == "<operator>.formatString")

                      if (isStringBuildOp) {
                        val c = e.asInstanceOf[nodes.Call]
                        if (!seen.contains(c.id)) {
                          seen += c.id
                          val sb = classifyStringBuild(c, paramName)
                          if (sb.contains("PATH")) { effect = "BREAKS"; note = s"fixed-origin prefix closes host boundary: ${c.code}" }
                          else if (sb.isEmpty && effect == "PRESERVES") { effect = "UNKNOWN"; note = s"unrecognized string-build shape: ${c.code}" }
                        }
                      } else if (!isIdentifier) {
                        // the transform call can appear EITHER as the flow element itself (e.g. a
                        // constructor call whose own node is directly on the path) OR only as the
                        // enclosing call of some nested element (e.g. an object-literal argument
                        // nested inside a call) -- check both, not just the enclosing-call case.
                        val directCallOpt: Option[nodes.Call] = e match {
                          case c: nodes.Call if (!c.name.startsWith("<operator>") || isConstructorCall(c)) && c.name != "fetch" => Some(c)
                          case _ => None
                        }
                        val ecOpt = directCallOpt.orElse(enclosingCall(e))
                        ecOpt.foreach { c =>
                          val isRelevant = (!c.name.startsWith("<operator>") || isConstructorCall(c)) &&
                                           !seen.contains(c.id) && c.name != "fetch"
                          if (isRelevant) {
                            seen += c.id
                            if (isUrlConstructor(c)) {
                              val args = c.argument.l.filter(_.argumentIndex >= 1)
                              val twoArgForm = args.size >= 2
                              val firstArgIsLiteral = args.headOption.exists(_.isInstanceOf[nodes.Literal])
                              if (twoArgForm && !firstArgIsLiteral && effect != "BREAKS") {
                                effect = "UNKNOWN"
                                note = "two-arg new URL(x, base): x not a literal, absolute-vs-relative not resolvable"
                              }
                              // one-arg, or two-arg with a known-literal first arg: falls through PRESERVES/TRANSFORMS
                            } else {
                              val calleeShort = if (c.name == "<operator>.fieldAccess")
                                c.code.split("\\.").lastOption.getOrElse(c.name) else c.name
                              val isKnownPreserving = HOST_PRESERVING_TRANSFORM_NAMES.contains(calleeShort)
                              if (!isKnownPreserving && effect == "PRESERVES") {
                                effect = "UNKNOWN"
                                note = s"unrecognized on-path call, not in known-preserving set: $calleeShort"
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                  rows += Row(fnName, paramName, effect, expected + (if (note.nonEmpty) s" | actual_note: $note" else ""))
              }
            }
        }
    }
  }

  val w = new java.io.PrintWriter(outFile)
  w.println(Seq("function","source_param","classified_effect","expected_and_note").mkString("\t"))
  rows.foreach(r => w.println(Seq(r.function, r.sourceParam, r.effect, r.note).mkString("\t")))
  w.close()
  println(s"PROPERTY_EFFECTS_COMPLETE rows=${rows.size}")
}
