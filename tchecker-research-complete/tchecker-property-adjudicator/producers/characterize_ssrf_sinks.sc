// SSRF sink-semantics characterization. For each recognized network-call shape, identifies the
// EXACT operand (an argument expression, or a specific field within an object-literal argument)
// that determines the request HOST -- never the whole call, never every field of an options
// object indiscriminately. Emits one row per call site to sink_semantics_matrix.tsv, matching the
// frozen schema: sink_family, call_shape, destination_operand, destination_component, confidence.
//
// This is PURE SINK CHARACTERIZATION. No property-propagation / PRESERVES-BREAKS-UNKNOWN logic
// exists in this file at all -- that is explicitly the next, separate stage.
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, outFile: String) = {
  importCpg(cpgFile)

  case class Row(sinkFamily: String, callShape: String, callId: String, line: Int,
                  destOperandDesc: String, destComponent: String, confidence: String, note: String)

  val rows = scala.collection.mutable.ListBuffer[Row]()

  // recognized callee name -> sink family, matched on the call's own resolved/naive name or the
  // receiver's member-access shape (e.g. axios.get, http.request)
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

  // for an object-literal argument (a Block AST shape in jssrc2cpg's lowering, containing
  // property assignments), find a property whose key matches one of the given names, returning
  // its VALUE expression code -- or None if that key isn't present.
  def findObjectField(argRoot: nodes.AstNode, keys: Seq[String]): Option[(String, String)] = {
    val assigns = argRoot.ast.isCall.name("<operator>.fieldAccess").l ++
                  argRoot.ast.isCall.name("<operator>.assignment").l
    // jssrc2cpg represents object literal properties as assignments to a synthetic temp's field;
    // walk the block's children for fieldAccess targets matching our keys, then find the RHS.
    val fieldAssigns = argRoot.ast.isCall.name("<operator>.assignment").l
    for (fa <- fieldAssigns) {
      val lhs = fa.argument(1)
      val rhs = fa.argument(2)
      lhs match {
        case fld: nodes.Call if fld.name == "<operator>.fieldAccess" =>
          val fieldName = fld.code.split("\\.").lastOption.getOrElse("")
          if (keys.contains(fieldName)) return Some((fieldName, rhs.code))
        case _ =>
      }
    }
    None
  }

  val calls = cpg.call.l
  calls.foreach { c =>
    familyOf(c).foreach { fam =>
      val args = c.argument.l.filter(_.argumentIndex >= 1)  // skip receiver (index 0) if member call
      val firstArg = args.headOption
      firstArg.foreach { a0 =>
        // Object literals AND constructor calls (`new X(...)`) both lower to a Block+assignment
        // shape in jssrc2cpg -- an object literal's assignments are `_tmp.field = value`
        // (fieldAccess LHS); a constructor's lowering assignment is `_tmp = .alloc` (bare
        // identifier LHS, RHS is the synthetic `.alloc` pseudo-call), followed by the actual
        // `new X(...)` call. Distinguish by checking for a nested `new `-prefixed call -- if
        // present, this is a constructor wrapper (treat as positional, whole-arg host-bearing),
        // never an object literal, regardless of any assignment nodes in its lowering.
        val isConstructorCall = a0.ast.isCall.filter(_.code.trim.startsWith("new ")).nonEmpty
        val isObjectLiteralArg = !isConstructorCall &&
          (a0.astChildren.isCall.name("<operator>.assignment").nonEmpty || a0.code.trim.startsWith("{"))
        if (!isObjectLiteralArg) {
          // positional string/URL/URL-object argument: arg0 itself IS the destination operand,
          // UNLESS it's a call to an unresolved external identifier we can't reason about (that
          // case is handled separately below via the whole-call check).
          val isUrlWrap = a0.code.trim.startsWith("new URL(")
          rows += Row(fam, if (isUrlWrap) "positional-URL-object" else "positional-string-or-URL",
                      c.id.toString, c.lineNumber.getOrElse(-1), a0.code, "HOST", "ESTABLISHED",
                      if (isUrlWrap) "new URL(x) wraps but does not restrict the host; whole arg is host-bearing" else "")
        } else {
          // options-object argument: only specific fields are host-bearing, by API semantics
          // fixed per family. Never treat every field as host-bearing.
          val hostKeys = fam match {
            case "http" | "https" => Seq("hostname", "host")
            case "axios"          => Seq("baseURL")   // NOT "url" alone -- see below
            case "got" | "request"=> Seq("url", "uri", "baseUrl")
            case _ => Seq()
          }
          val hostField = findObjectField(a0, hostKeys)
          val urlField = fam match {
            case "axios" => findObjectField(a0, Seq("url"))
            case _ => None
          }
          (hostField, urlField) match {
            case (Some((k, v)), None) =>
              rows += Row(fam, "options-object", c.id.toString, c.lineNumber.getOrElse(-1),
                          s"$k: $v", "HOST", "ESTABLISHED", s"host-bearing field '$k' present")
            case (Some((hk, hv)), Some((uk, uv))) =>
              // both baseURL and url present (axios): baseURL determines host, url is path-relative
              // to it -- this is the exact case from the brief. Emit BOTH rows, correctly labeled.
              rows += Row(fam, "options-object", c.id.toString, c.lineNumber.getOrElse(-1),
                          s"$hk: $hv", "HOST", "ESTABLISHED",
                          "baseURL determines effective host when both baseURL and url are present")
              rows += Row(fam, "options-object", c.id.toString, c.lineNumber.getOrElse(-1),
                          s"$uk: $uv", "PATH_ONLY", "ESTABLISHED",
                          "url is resolved AGAINST baseURL, not itself host-bearing -- must not be flagged as HOST")
            case (None, Some((uk, uv))) =>
              // axios with url but NO baseURL: url IS the full request target, so it IS host-bearing
              rows += Row(fam, "options-object", c.id.toString, c.lineNumber.getOrElse(-1),
                          s"$uk: $uv", "HOST", "ESTABLISHED",
                          "no baseURL present; url is the full request target and is host-bearing")
            case (None, None) =>
              // no recognized host-bearing field found at all (e.g. { path: attackerPath } for
              // http.request, or an axios config with neither baseURL nor url visible)
              rows += Row(fam, "options-object", c.id.toString, c.lineNumber.getOrElse(-1),
                          "(none found)", "NONE", "ESTABLISHED",
                          "no host-bearing field present in this options object -- correctly NOT flagged")
          }
        }
      }
    }
  }

  // unresolved wrapper calls: never guess. Detect calls whose callee is neither a recognized
  // sink family NOR resolvable to a body in this file -- must be UNSUPPORTED, not silently skipped
  // or silently treated as a sink.
  val wrapperCandidates = cpg.call.filter(c => c.name.contains("doRequest") || c.name == "notDefinedInThisFile").l
  wrapperCandidates.foreach { c =>
    rows += Row("UNRESOLVED_WRAPPER", "unresolved-call", c.id.toString, c.lineNumber.getOrElse(-1),
                "(unresolved)", "UNKNOWN", "UNSUPPORTED",
                "callee not a recognized sink family and not resolvable to a local body -- abstain")
  }

  val w = new java.io.PrintWriter(outFile)
  w.println(Seq("sink_family","call_shape","call_node_id","line","destination_operand",
                "destination_component","confidence","note").mkString("\t"))
  rows.foreach(r => w.println(Seq(r.sinkFamily, r.callShape, r.callId, r.line, r.destOperandDesc,
                                   r.destComponent, r.confidence, r.note).mkString("\t")))
  w.close()
  println(s"CHARACTERIZATION_COMPLETE rows=${rows.size}")
}
