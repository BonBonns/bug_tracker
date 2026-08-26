// PATH-TRAV-PROP-R01: property-effects classifier for ATTACKER_CONTROL_OF_FILESYSTEM_LOCATION.
// CRITICAL RULE, VERIFIED (not assumed) against real Node.js path semantics before writing any
// code: path.join(fixedBase, x) and path.resolve(fixedBase, x) provide ZERO containment against
// '..' traversal -- path.join('/safe/base','../../etc/passwd') genuinely resolves to '/etc/passwd'.
// This is the OPPOSITE of SSRF's axios({baseURL, url}) case, where a fixed baseURL DOES contain
// the host. A fixed "base" argument to path.join/resolve must NOT be classified as establishing
// containment -- doing so would silently misclassify a real, well-known vulnerability pattern.
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

val PATH_JOINING_CALLS = Set("join", "resolve")  // path.join / path.resolve -- NO containment, ever
val LOCATION_PRESERVING_TRANSFORM_NAMES = Set("normalize")  // path.normalize: reformats, doesn't restrict
val COMPARISON_OPS = Set("<operator>.equals", "<operator>.strictEquals")
val CONTAINMENT_CHECK_METHODS = Set("includes", "startsWith")
// deliberately excludes "endsWith": on a path-like value, startsWith checks a DIRECTORY PREFIX
// (location-relevant, the textbook resolve-then-verify-containment idiom) while endsWith checks a
// SUFFIX/extension (format-relevant, not location-relevant) -- confirmed by extensionCheckOnly's
// expected PRESERVES result, a structurally different case from a genuine containment check.

@main def exec(cpgFile: String, outFile: String) = {
  importCpg(cpgFile)
  implicit val ec: EngineContext = EngineContext()

  case class Row(function: String, sourceParam: String, effect: String, note: String)
  val rows = scala.collection.mutable.ListBuffer[Row]()

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

  // guard-dominance: same structural discipline as the (already fixed) SSRF version -- the
  // tracked identifier must be a DIRECT operand of the SPECIFIC comparison/method call, not merely
  // present somewhere in a larger condition. Handles negation (!X.includes('..')) since the
  // .includes() call is found via .ast (whole subtree), independent of the enclosing logicalNot.
  // KNOWN LIMITATION, stated here rather than silently assumed away: this only recognizes a guard
  // on the ORIGINAL tracked identifier's own text. It does NOT yet recognize a guard on a DERIVED
  // variable produced by an intermediate transform (e.g. `resolved = path.resolve(...); if
  // (resolved.startsWith(...))`) -- that correlation (derived-var-checked == derived-var-sunk ==
  // derived-from-tracked-source) is a real, separate capability not built in this pass. Cases
  // needing it will correctly fall through to UNKNOWN rather than being silently misclassified.
  def sinkIsGuardedBy(sinkCall: nodes.Call, trackedCodes: Set[String]): Option[String] = {
    def isGenuineValueGuard(cmp: nodes.Call): Boolean = {
      val operands = cmp.argument.l
      operands.exists(o => trackedCodes.contains(o.code.trim))
    }
    def isGenuineContainmentCheck(m: nodes.Call): Boolean = {
      m.argument.l.exists(o => trackedCodes.contains(o.code.trim))
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
    // X.replace(/\.\./g, '') or similar: a genuine value-transform that removes '..' sequences.
    // Verified structurally: the call is named "replace", its receiver is the tracked value (or a
    // value derived from it -- checked loosely here since replace chains are common), and its
    // first argument is a regex/string literal containing "..".
    m.ast.isCall.name("replace").find { c =>
      val args = c.argument.l.sortBy(_.argumentIndex)
      args.headOption.exists(_.code.trim == trackedCode.trim) &&
      args.lift(1).exists(a => a.code.contains("..") || a.code.contains("\\.\\."))
    }.map(_.code)
  }

  def lookupKeyInfluence(m: nodes.Method, srcExpr: nodes.Expression, sinkExprs: List[nodes.Expression]): Option[String] = {
    def enclosingCallOf(n: nodes.AstNode): Option[nodes.Call] = {
      var cur: nodes.AstNode = n; var hops = 0
      while (hops < 8) {
        val p = scala.util.Try(cur.astParent).toOption
        p match { case Some(c: nodes.Call) => return Some(c); case Some(null) => return None
                  case Some(pp) => cur = pp; hops += 1; case None => return None }
      }
      None
    }
    val keyUses = srcExpr.ast.l.collect { case id: nodes.Identifier => id }
      .flatMap(id => enclosingCallOf(id))
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
        if (flows.nonEmpty) Some(lookupCall.code) else None
      }
    }.headOption
  }

  val cases = Seq(
    ("identity", "userPath", "PRESERVES (identity)"),
    ("normalized", "userPath", "PRESERVES (path.normalize -- reformats, does not restrict)"),
    ("resolvedNoBase", "userPath", "PRESERVES (path.resolve(x), single-arg -- absolutizes only)"),
    ("joinedWithFixedBase", "userPath", "PRESERVES (path.join(base,x) -- fixed base provides NO containment, verified)"),
    ("resolvedWithFixedBase", "userPath", "PRESERVES (path.resolve(base,x) -- same non-containment)"),
    ("concatenatedWithFixedPrefix", "userPath", "PRESERVES (string concat -- obviously no containment)"),
    ("stripsDotDotLiterally", "userPath", "BREAKS (literal '..' removal is a genuine value-transform)"),
    ("guardDominatesSink", "userPath", "BREAKS (candidate -- !X.includes('..') genuinely gates the sink)"),
    ("guardDoesNotDominateSink", "userPath", "PRESERVES (guard exists but does not gate the call -- negative control)"),
    ("resolveThenVerifyContainment", "userPath", "UNKNOWN EXPECTED (guard is on a DERIVED variable, not yet recognized -- documented limitation, not a bug)"),
    ("resolveThenVerifyContainmentDoesNotDominate", "userPath", "PRESERVES (negative control -- guard doesn't gate even if it were recognized)"),
    ("extensionCheckOnly", "userPath", "PRESERVES (extension check validates FORMAT, not LOCATION -- must not be a guard)"),
    ("lookupByUserId", "userId", "OPEN/UNKNOWN (LOOKUP_KEY_INFLUENCE, same lesson as SSRF/serialize-dos)"),
    ("unresolvedWrapperTransform", "userPath", "UNKNOWN (unresolved external transform, abstain)")
  )

  cases.foreach { case (fnName, paramName, expected) =>
    val method = cpg.method.name(fnName).headOption
    method match {
      case None => rows += Row(fnName, paramName, "NO_METHOD_FOUND", expected)
      case Some(m) =>
        val sinkCalls = m.ast.isCall.name("readFile").l
        val srcCandidates = m.ast.isIdentifier.name(paramName).l
        (srcCandidates.isEmpty, sinkCalls.headOption) match {
          case (true, _) => rows += Row(fnName, paramName, "NO_SOURCE_PARAM", expected)
          case (_, None) => rows += Row(fnName, paramName, "NO_SINK_CALL", expected)
          case (false, Some(sink)) =>
            val sinkArgOpt = sink.argument.l.filter(_.argumentIndex >= 1).headOption
            val flowsTry = scala.util.Try {
              sinkArgOpt match {
                case Some(sinkArg) =>
                  val sinkExprs = cpg.all.id(sinkArg.id).collectAll[nodes.Expression].l
                  if (sinkExprs.isEmpty) Nil
                  else srcCandidates.flatMap(s =>
                    sinkExprs.reachableByFlows(Iterator(s: nodes.Expression)).l).distinct
                case None => Nil
              }
            }
            val flows = flowsTry.getOrElse(Nil)
            if (flowsTry.isFailure) {
              rows += Row(fnName, paramName, "ERROR: " + flowsTry.failed.get.getMessage.take(80), expected)
            } else if (flows.isEmpty) {
              val sinkExprs = sinkArgOpt.toList.flatMap(a => cpg.all.id(a.id).collectAll[nodes.Expression].l)
              val lookupMatch = srcCandidates.headOption.flatMap(s => lookupKeyInfluence(m, s: nodes.Expression, sinkExprs))
              lookupMatch match {
                case Some(lookupCode) => rows += Row(fnName, paramName, "UNKNOWN (LOOKUP_KEY_INFLUENCE: key reaches " + lookupCode + ")", expected)
                case None => rows += Row(fnName, paramName, "NO_FLOW", expected)
              }
            } else {
              // derived-variable tracking: any Identifier appearing as part of a CONFIRMED flow
              // from the tracked source to the sink is, by definition, carrying the tracked value
              // forward at that point -- collecting all such names (not just the original
              // parameter name) lets the guard check recognize `resolved.startsWith(...)` as
              // checking the tracked value, even though `resolved` is a variable introduced by an
              // intermediate transform (`const resolved = path.resolve(base, userPath)`). The
              // <operator>.assignment node itself does not appear as a flow element (confirmed by
              // direct trace inspection -- the call's result flows straight to the identifier), so
              // extracting names via assignment-node detection does not work; collecting flow-
              // element identifiers directly does.
              val derivedNames: Set[String] = flows.flatMap { f =>
                f.elements.collect { case id: nodes.Identifier => id.code.trim }
              }.toSet
              val trackedCodes = Set(paramName) ++ derivedNames
              val guardMatch = sinkIsGuardedBy(sink, trackedCodes)
              val stripMatch = hasLiteralDotDotStrip(m, paramName)
              (guardMatch, stripMatch) match {
                case (Some(cond), _) => rows += Row(fnName, paramName, "BREAKS (guarded by: " + cond + ")", expected)
                case (None, Some(rc)) => rows += Row(fnName, paramName, "BREAKS (literal '..' strip: " + rc + ")", expected)
                case (None, None) =>
                  var effect = "PRESERVES"
                  var note = ""
                  val seen = scala.collection.mutable.Set[Long]()
                  flows.foreach { f =>
                    f.elements.foreach { e =>
                      val isIdentifier = e.isInstanceOf[nodes.Identifier]
                      if (!isIdentifier) {
                        val directCallOpt: Option[nodes.Call] = e match {
                          case c: nodes.Call if (!c.name.startsWith("<operator>") || isConstructorCall(c)) && c.name != "readFile" => Some(c)
                          case _ => None
                        }
                        val ecOpt = directCallOpt.orElse(enclosingCall(e).filter(c => (!c.name.startsWith("<operator>") || isConstructorCall(c)) && c.name != "readFile"))
                        ecOpt.foreach { c =>
                          if (!seen.contains(c.id)) {
                            seen += c.id
                            val calleeShort = if (c.name == "<operator>.fieldAccess")
                              c.code.split("\\.").lastOption.getOrElse(c.name) else c.name
                            val isPathJoiningCall = PATH_JOINING_CALLS.contains(calleeShort)
                            val isKnownPreserving = LOCATION_PRESERVING_TRANSFORM_NAMES.contains(calleeShort)
                            if (isPathJoiningCall) {
                              // explicitly PRESERVES -- fixed base gives no containment, confirmed
                              note = if (note.isEmpty) s"path-joining call ($calleeShort) provides no containment" else note
                            } else if (!isKnownPreserving && effect == "PRESERVES") {
                              effect = "UNKNOWN"
                              note = s"unrecognized call: $calleeShort"
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
  println(s"PATH_PROPERTY_EFFECTS_COMPLETE rows=${rows.size}")
}
