// ESCAPE-PARITY-BOUNDARY-R01 -- quote-boundary rule fact producer.
//
// Property objective: identify parsers that decide whether a quote closes a quoted
// string by inspecting only the immediately preceding escape character, instead of
// establishing the parity of the complete consecutive escape run.
//
//     A quote is escaped when preceded by an ODD-length consecutive escape run.
//     A quote terminates the string when preceded by an EVEN-length escape run.
//
// This producer emits GRAPH FACTS ONLY. It never classifies. Every row carries the
// real CPG node id(s) it came from, so two structurally identical sites at different
// program points stay distinct all the way through the pipeline. Regex pattern text is
// emitted verbatim from the resolved literal node; the structural verdict for it is
// computed downstream by regex_boundary_model.py, which parses the pattern into a
// regex AST. Nothing here or downstream substring-matches file source text.
//
// Abstention is the default: any construct this producer cannot resolve is emitted
// with an explicit UNRESOLVED_* status rather than being dropped or guessed.
//
// Fact files (all TSV, all node-identity preserving):
//   regex_sites.tsv          file, method, method_id, line, node_id, resolution,
//                            pattern_body, flags, detail
//   parser_quote_sites.tsv   file, method, method_id, line, cmp_id, other_id,
//                            access_kind, delimiter_resolution
//   parser_index_checks.tsv  file, method, method_id, line, check_id, quote_cmp_id,
//                            esc_cmp_id, index_expr_id, offset, base_name, index_name
//   parity_mechanisms.tsv    file, method, method_id, line, node_id, mechanism
//   delayed_sources.tsv      file, method, line, node_id, api_identity,
//                            module_identity, import_node_id, resolution
//   transform_calls.tsv      file, method, line, node_id, family, callee_identity,
//                            regex_arg_id, resolution
//   replacement_callbacks.tsv file, line, replace_call_id, callback_id, kind, resolution
//   consumers.tsv            file, method, line, node_id, consumer_identity,
//                            module_identity, kind, resolution
//   chain_edges.tsv          from_kind, from_id, to_kind, to_id, edge_kind
//   execution_timing.tsv     file, method, line, node_id, timing_kind
//                            (recorded as EVIDENCE ONLY -- never a guard)
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, rawDir: String) = {
  importCpg(cpgFile)
  new java.io.File(rawDir).mkdirs()

  def cl(s: String): String =
    Option(s).getOrElse("").replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "")
      .replace("\t", "\\t").take(400)
  def w(n: String) = new java.io.PrintWriter(new java.io.File(s"$rawDir/$n"), "UTF-8")
  def ln(n: nodes.AstNode): Int = n.lineNumber.map(_.toInt).getOrElse(-1)

  /** Walk the AST upwards to the enclosing Method node. Done explicitly so every fact
    * row is anchored to a real method identity rather than to a traversal accident. */
  def methOf(n: nodes.AstNode): Option[nodes.Method] = {
    var cur: Option[nodes.AstNode] = Some(n)
    var res: Option[nodes.Method] = None
    var guard = 0
    while (cur.isDefined && res.isEmpty && guard < 500) {
      cur.get match {
        case m: nodes.Method => res = Some(m)
        case other => cur = other._astIn.collectFirst { case a: nodes.AstNode => a }
      }
      guard += 1
    }
    res
  }
  def fileOf(n: nodes.AstNode): String = methOf(n).map(_.filename).getOrElse("?")

  // ------------------------------------------------------------------ helpers
  /** A JS string/char literal node's code carries its surrounding quotes and an
    * already-unescaped value. Return that value, or None if it is not a string. */
  def stringValue(n: nodes.AstNode): Option[String] = n match {
    case l: nodes.Literal =>
      val c = Option(l.code).getOrElse("")
      if (c.length >= 2 && ((c.head == '"' && c.last == '"') || (c.head == '\'' && c.last == '\'')))
        Some(c.substring(1, c.length - 1))
      else None
    case _ => None
  }
  def intValue(n: nodes.AstNode): Option[Int] = n match {
    case l: nodes.Literal => scala.util.Try(Option(l.code).getOrElse("").trim.toInt).toOption
    case _ => None
  }
  val QUOTE_CHARS = Set("'", "\"", "`")
  def isQuoteLiteral(n: nodes.AstNode): Boolean = stringValue(n).exists(QUOTE_CHARS.contains)
  def isEscapeLiteral(n: nodes.AstNode): Boolean = stringValue(n).contains("\\")

  // ---------------------------------------------------- delimiter identity
  // Real parsers routinely compare against a delimiter VARIABLE rather than a
  // literal -- `input[p - 1] === escapeChar`. Requiring a literal on one side
  // made every such site invisible: not a candidate, not a negative, not even
  // an abstention. Resolution is deliberately all-or-nothing: a name counts as
  // a delimiter only when EVERY assignment reaching it in the file is a string
  // literal. One non-literal assignment (a config read, a parameter) makes the
  // identity unresolved, and an unresolved delimiter abstains rather than
  // guessing -- a configurable quote character genuinely cannot be decided
  // statically, and saying so is the honest answer.
  val LITERAL = "LITERAL"; val RESOLVED = "RESOLVED"; val UNRESOLVED = "UNRESOLVED"
  val ROLE_QUOTE = "QUOTE"; val ROLE_ESCAPE = "ESCAPE"; val ROLE_OTHER = "OTHER"

  // (file, identifier) -> every value assigned to it; None marks a non-literal
  // assignment, which poisons the name for resolution purposes.
  val assignedValues = scala.collection.mutable.Map[(String, String), List[Option[String]]]()
  var aliasEdges = List.empty[((String, String), (String, String))]
  cpg.call.nameExact("<operator>.assignment").l.foreach { a =>
    for {
      nm <- argAt(a, 1).collect { case i: nodes.Identifier => i.name }
      rhs <- argAt(a, 2)
    } {
      val k = (fileOf(a), nm)
      assignedValues(k) = assignedValues.getOrElse(k, Nil) :+ stringValue(rhs)
      rhs match {
        case i: nodes.Identifier => aliasEdges = aliasEdges :+ (k, (fileOf(a), i.name))
        case _ => ()
      }
    }
  }

  /** All literal values a name can hold, or None when any assignment is not a
    * literal or the name is never assigned in this file. */
  def resolveIdent(file: String, name: String): Option[Set[String]] = {
    assignedValues.get((file, name)) match {
      case Some(vs) if vs.nonEmpty && vs.forall(_.isDefined) => Some(vs.flatten.toSet)
      case _ => None
    }
  }

  // An unresolved name is a delimiter only when it PROVABLY holds a quote or
  // escape character on at least one path. Without this, any `x == y` between
  // two identifiers inside a method that indexes a container looked like a
  // quote-boundary site, which in real C++ means hundreds of records from
  // methods that parse nothing. The relation is transitive by one alias step
  // (`escapeChar = quoteChar` before `escapeChar = config.escapeChar`), which
  // is exactly the shape real parsers use to default one delimiter to another.
  def delimiterLike(): Set[(String, String)] = {
    // .iterator is load-bearing: collecting a PAIR out of a Map rebuilds a Map
    // keyed by the pair's first element, so every delimiter in a file but the
    // last silently vanished. Collect over the iterator to get a plain Set.
    var known = assignedValues.iterator.collect {
      case (k, vs) if vs.flatten.exists(v => QUOTE_CHARS.contains(v) || v == "\\") => k
    }.toSet
    var changed = true
    var rounds = 0
    while (changed && rounds < 4) {
      rounds += 1
      val next = known ++ aliasEdges.collect { case (k, src) if known.contains(src) => k }
      changed = next.size != known.size
      known = next
    }
    known
  }

  lazy val DELIMITER_LIKE = delimiterLike()

  def roleOfValues(vs: Set[String]): String =
    if (vs.nonEmpty && vs.forall(QUOTE_CHARS.contains)) ROLE_QUOTE
    else if (vs.nonEmpty && vs.forall(_ == "\\")) ROLE_ESCAPE
    else ROLE_OTHER

  /** The delimiter role of a comparison operand: a literal, a name resolved to
    * literals, or an unresolved name. Anything else is not a delimiter at all. */
  def delimRole(n: nodes.AstNode): Option[(String, String)] = n match {
    case l: nodes.Literal =>
      stringValue(l).map { v =>
        val r = if (QUOTE_CHARS.contains(v)) ROLE_QUOTE
                else if (v == "\\") ROLE_ESCAPE else ROLE_OTHER
        (r, LITERAL)
      }
    case i: nodes.Identifier =>
      resolveIdent(fileOf(i), i.name) match {
        case Some(vs) => Some((roleOfValues(vs), RESOLVED))
        case None =>
          if (DELIMITER_LIKE.contains((fileOf(i), i.name))) Some((ROLE_QUOTE, UNRESOLVED))
          else None
      }
    case _ => None
  }

  def isQuoteDelim(n: nodes.AstNode): Boolean =
    delimRole(n).exists { case (r, res) => r == ROLE_QUOTE && res != UNRESOLVED }
  def isEscapeDelim(n: nodes.AstNode): Boolean =
    delimRole(n).exists { case (r, res) => r == ROLE_ESCAPE && res != UNRESOLVED }
  def isUnresolvedDelim(n: nodes.AstNode): Boolean =
    delimRole(n).exists { case (_, res) => res == UNRESOLVED }

  def args(c: nodes.Call): List[nodes.Expression] = c.argument.l.sortBy(_.argumentIndex)
  def argAt(c: nodes.Call, i: Int): Option[nodes.Expression] = c.argument.l.find(_.argumentIndex == i)

  /** fieldAccess(base, FieldIdentifier) -> (baseCode, fieldName) */
  def fieldParts(n: nodes.AstNode): Option[(String, String, nodes.Expression)] = n match {
    case c: nodes.Call if c.name == "<operator>.fieldAccess" =>
      val b = argAt(c, 1)
      val f = argAt(c, 2).collect { case fi: nodes.FieldIdentifier => fi.canonicalName }
      for { bb <- b; ff <- f } yield (Option(bb.code).getOrElse(""), ff, bb)
    case _ => None
  }
  /** The receiver+member of a DYNAMIC_DISPATCH member call, via its fieldAccess. */
  def memberCallParts(c: nodes.Call): Option[(String, String)] =
    c.receiver.headOption.flatMap(fieldParts).map { case (b, f, _) => (b, f) }

  // ------------------------------------------------- module identity (require)
  // identifier name -> module specifier, from `const X = require('mod')` and from
  // ESM import nodes. Used so an API call is identified through a resolved import,
  // never through the spelling of a bare identifier alone.
  val moduleOfIdent = scala.collection.mutable.Map[String, String]()
  val importNodeOfIdent = scala.collection.mutable.Map[String, Long]()
  cpg.call.nameExact("<operator>.assignment").l.foreach { a =>
    val lhs = argAt(a, 1)
    val rhs = argAt(a, 2)
    (lhs, rhs) match {
      case (Some(i: nodes.Identifier), Some(r: nodes.Call)) if r.name == "require" =>
        argAt(r, 1).flatMap(stringValue).foreach { m =>
          moduleOfIdent(i.name) = m; importNodeOfIdent(i.name) = r.id
        }
      case _ => ()
    }
  }
  cpg.imports.l.foreach { im =>
    val spec = im.importedEntity.getOrElse("")
    im.importedAs.foreach { as => if (spec.nonEmpty) { moduleOfIdent(as) = spec; importNodeOfIdent(as) = im.id } }
  }

  // ------------------------------------------------------------ regex sites
  // A regex literal is recognised from the LITERAL NODE'S OWN VALUE (its lexical
  // form /body/flags), not by scanning source text.
  val regexLiteralRe = """^/(.*)/([dgimsuvy]*)$""".r
  val rs = w("regex_sites.tsv")
  val regexSiteIds = scala.collection.mutable.Map[Long, String]() // node id -> pattern body
  try {
    cpg.literal.l.foreach { l =>
      val code = Option(l.code).getOrElse("")
      code match {
        case regexLiteralRe(body, flags) if body.nonEmpty =>
          val m = methOf(l)
          rs.println(List(fileOf(l), m.map(_.fullName).getOrElse("?"), m.map(_.id).getOrElse(-1L),
            ln(l), l.id, "RESOLVED_LITERAL", cl(body), flags, "").mkString("\t"))
          regexSiteIds(l.id) = body
        case _ => ()
      }
    }
    // new RegExp(...) / RegExp(...) -- resolved only when the pattern argument is a
    // single string literal; a concatenation or variable is an explicit abstention.
    cpg.call.nameExact("<operator>.new").l.foreach { c =>
      val ctor = c.astChildren.l.headOption.collect { case i: nodes.Identifier => i.name }
      if (ctor.contains("RegExp")) {
        val patArg = c.astChildren.l.drop(2).headOption
        val flagArg = c.astChildren.l.drop(3).headOption.flatMap(stringValue).getOrElse("")
        val m = methOf(c)
        patArg match {
          case Some(p) if stringValue(p).isDefined =>
            val body = stringValue(p).get
            rs.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"), m.map(_.id).getOrElse(-1L),
              ln(c), c.id, "RESOLVED_CONST_STRING", cl(body), flagArg, s"pattern_node=${p.id}").mkString("\t"))
            regexSiteIds(c.id) = body
          case Some(p) =>
            rs.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"), m.map(_.id).getOrElse(-1L),
              ln(c), c.id, "UNRESOLVED_DYNAMIC", "", flagArg,
              s"pattern_node=${p.id};kind=${p.getClass.getSimpleName}").mkString("\t"))
          case None =>
            rs.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"), m.map(_.id).getOrElse(-1L),
              ln(c), c.id, "UNRESOLVED_DYNAMIC", "", flagArg, "no_pattern_argument").mkString("\t"))
        }
      }
    }
  } finally rs.close()

  // -------------------------------------------------- custom parser index checks
  // Structural signature of a one-position boundary rule:
  //   cmp( indexAccess(B, IDX)          , <quote literal> )   -- "is this a quote"
  //   cmp( indexAccess(B, IDX - <int>)  , <escape literal> )  -- "is the ONE char
  //                                                              before it an escape"
  // Both must use the same base and the same index variable. The integer offset is
  // recorded as-is; the downstream model treats a single fixed offset as incapable of
  // establishing run parity, whatever its value.
  val comparisonOps = Set("<operator>.equals", "<operator>.notEquals",
    "<operator>.strictEquals", "<operator>.strictNotEquals",
    "<operator>.notIdentical", "<operator>.identical")

  /** indexAccess(base, index) -> (baseName, indexNode) */
  def indexParts(n: nodes.AstNode): Option[(String, nodes.Expression)] = n match {
    case c: nodes.Call if c.name == "<operator>.indexAccess" =>
      for { b <- argAt(c, 1); i <- argAt(c, 2) } yield (Option(b.code).getOrElse(""), i)
    case c: nodes.Call if c.name == "charAt" || c.name == "charCodeAt" =>
      for { r <- c.receiver.headOption; i <- argAt(c, 1) }
        yield (fieldParts(r).map(_._1).getOrElse(Option(r.code).getOrElse("")), i)
    case _ => None
  }
  /** `IDX - <int literal>` -> (idxName, offset) ; bare `IDX` -> (idxName, 0) */
  def offsetParts(n: nodes.AstNode): Option[(String, Int)] = n match {
    case i: nodes.Identifier => Some((i.name, 0))
    case c: nodes.Call if c.name == "<operator>.subtraction" =>
      for {
        a <- argAt(c, 1).collect { case i: nodes.Identifier => i.name }
        k <- argAt(c, 2).flatMap(intValue)
      } yield (a, k)
    case _ => None
  }
  /** A comparison of an indexed char against a literal satisfying `lit`. */
  def indexedCharCmp(c: nodes.Call, lit: nodes.AstNode => Boolean)
      : Option[(String, String, Int, Long)] = {
    if (!comparisonOps.contains(c.name)) return None
    val as = args(c)
    val pairs = List((as.lift(0), as.lift(1)), (as.lift(1), as.lift(0)))
    pairs.flatMap {
      case (Some(x), Some(y)) if lit(y) =>
        for { (b, idxNode) <- indexParts(x); (nm, off) <- offsetParts(idxNode) }
          yield (b, nm, off, x.id)
      case _ => None
    }.headOption
  }


  // Real parsers usually extract the character first (`char c = s[i];`) and compare the
  // VARIABLE against the quote, while still testing `s[i-1]` against the escape directly.
  // Map such a variable back to the (base, index) it was read from, at offset zero, so the
  // two halves of a one-position rule can still be paired.
  val charVarOrigin = scala.collection.mutable.Map[(Long, String), (String, String)]()
  cpg.call.nameExact("<operator>.assignment").l.foreach { a =>
    val mId = methOf(a).map(_.id).getOrElse(-1L)
    val lhs = argAt(a, 1).collect { case i: nodes.Identifier => i.name }
    for {
      nm <- lhs
      rhs <- argAt(a, 2)
      (b, idxNode) <- indexParts(rhs)
      (idxName, off) <- offsetParts(idxNode)
      if off == 0
    } charVarOrigin((mId, nm)) = (b, idxName)
  }
  /** A comparison of a quote literal against an EXTRACTED character variable. */
  def extractedQuoteCmp(c: nodes.Call): Option[(String, String, Int, Long)] = {
    if (!comparisonOps.contains(c.name)) return None
    val as = args(c)
    val mId = methOf(c).map(_.id).getOrElse(-1L)
    val pairs = List((as.lift(0), as.lift(1)), (as.lift(1), as.lift(0)))
    pairs.flatMap {
      case (Some(x: nodes.Identifier), Some(y)) if isQuoteDelim(y) =>
        charVarOrigin.get((mId, x.name)).map { case (b, idx) => (b, idx, 0, x.id) }
      case _ => None
    }.headOption
  }

  // ------------------------------------------- search-established positions
  // A scanner often establishes "position p holds a quote" with a SEARCH rather
  // than a comparison: `p = input.indexOf(quoteChar, cursor)`. The pairing
  // below looked only for comparisons, so the quote half of a one-position rule
  // written this way was never found and the rule went unclassified.
  //
  // Only BACKWARD offsets pair (`input[p - 1]`). A forward look (`input[p + 1]`)
  // is the doubled-delimiter idiom -- it consumes the pair and is therefore
  // parity-correct -- so it must never feed the candidate path. offsetParts
  // recognises subtraction only, which is what keeps that true.
  val SEARCH_CALLS = Set("indexOf", "lastIndexOf")
  case class SearchPos(callId: Long, base: String, posVar: String, methodId: Long,
                       resolution: String, line: Int, file: String, method: String)
  val searchPositions = cpg.call.nameExact("<operator>.assignment").l.flatMap { a =>
    for {
      posVar <- argAt(a, 1).collect { case i: nodes.Identifier => i.name }
      call <- argAt(a, 2).collect { case c: nodes.Call if SEARCH_CALLS.contains(c.name) => c }
      needle <- argAt(call, 1)
      (role, res) <- delimRole(needle)
      if role == ROLE_QUOTE
      recv <- call.receiver.headOption
    } yield SearchPos(call.id,
                      fieldParts(recv).map(_._1).getOrElse(Option(recv.code).getOrElse("")),
                      posVar, methOf(a).map(_.id).getOrElse(-1L), res, ln(a),
                      fileOf(a), methOf(a).map(_.fullName).getOrElse("?"))
  }

  // Two comparisons belong to the SAME boundary rule only when one is reachable
  // from the other's nearest enclosing control structure: either they sit in the
  // very same condition (a flat `a && b` or `a || b`), or one is nested inside a
  // branch guarded by the other (`if (a) { if (b) {...} }`, in either order).
  // Matching on method + base-expression + index-variable alone (as before) pairs
  // an escape check with EVERY quote comparison anywhere in a function that shares
  // its buffer and loop index -- including unrelated sibling branches. Confirmed
  // as a real false positive on the C/C++ side (SourceMod's ParseStream_SMC has a
  // genuine one-position rule on its CLOSING-quote branch and a wholly separate
  // OPENING-quote branch with no escape check of its own); fixed here too so both
  // language producers hold the same precision guarantee.
  // nearestControlId is scoped to IF-shaped control structures only: a loop
  // (while/for/do) is not a decision -- its body runs every iteration, so
  // treating a loop as the "nearest control" would make every statement in
  // the loop body count as guarded by it.
  //
  // isWithinControl climbs through ANY ancestor -- including other, unrelated
  // `if` nodes -- EXCEPT a loop, which stops the climb. Nested ifs must still
  // pair (`if (a) { if (b) {...} }` is one boundary rule split across two
  // guards), so climbing must not stop at the first if that is not the
  // target. But a loop is not a guard at all: a search-established quote
  // position taken once per iteration (`p = s.indexOf(quote, cursor)` after
  // the escape-guarded branch) and the escape check nested in a SIBLING `if`
  // branch of the SAME while loop both have the loop as a common ancestor
  // without sharing a decision -- confirmed as a real false positive while
  // regenerating this fixture's facts under an earlier version of this fix
  // that had no loop check at all.
  def isIfNode(n: nodes.AstNode): Boolean = n match {
    case cs: nodes.ControlStructure => cs.controlStructureType == "IF"
    case _ => false
  }
  def isLoopNode(n: nodes.AstNode): Boolean = n match {
    case cs: nodes.ControlStructure =>
      Set("WHILE", "DO", "FOR").contains(cs.controlStructureType)
    case _ => false
  }
  def nearestControlId(n: nodes.AstNode): Option[Long] = {
    var cur: Option[nodes.AstNode] = n._astIn.collectFirst { case a: nodes.AstNode => a }
    var res: Option[Long] = None
    var guard = 0
    while (cur.isDefined && res.isEmpty && guard < 500) {
      cur.get match {
        case cs if isIfNode(cs) => res = Some(cs.id)
        case _: nodes.Method => cur = None
        case other => cur = other._astIn.collectFirst { case a: nodes.AstNode => a }
      }
      guard += 1
    }
    res
  }
  def isWithinControl(n: nodes.AstNode, controlId: Long): Boolean = {
    var cur: Option[nodes.AstNode] = Some(n)
    var found = false
    var guard = 0
    while (cur.isDefined && !found && guard < 500) {
      if (cur.get.id == controlId) found = true
      else cur.get match {
        case _: nodes.Method => cur = None
        case cs if isLoopNode(cs) => cur = None
        case other => cur = other._astIn.collectFirst { case a: nodes.AstNode => a }
      }
      guard += 1
    }
    found
  }
  def sameBoundaryScope(qc: nodes.AstNode, ec: nodes.AstNode): Boolean = {
    val qCtl = nearestControlId(qc)
    val eCtl = nearestControlId(ec)
    (qCtl.isDefined && qCtl == eCtl) ||
    (qCtl.isDefined && isWithinControl(ec, qCtl.get)) ||
    (eCtl.isDefined && isWithinControl(qc, eCtl.get))
  }

  val pic = w("parser_index_checks.tsv")
  try {
    val quoteCmps = cpg.call.l.flatMap(c =>
      indexedCharCmp(c, isQuoteDelim).orElse(extractedQuoteCmp(c)).map(r => (c, r)))
    // A resolved search position stands in for a quote comparison at offset 0 on
    // the same base and position variable. An unresolved delimiter does not: the
    // method abstains on delimiter identity and must not reach a verdict here.
    val searchQuotePos = searchPositions.filter(_.resolution != UNRESOLVED)
    val escCmps = cpg.call.l.flatMap(c => indexedCharCmp(c, isEscapeDelim).map(r => (c, r)))
    val callById = cpg.call.l.map(c => c.id -> c).toMap
    escCmps.foreach { case (ec, (eBase, eIdx, eOff, eIdxExprId)) =>
      if (eOff != 0) {
        val em = methOf(ec)
        // a quote comparison in the SAME method on the SAME base and index variable,
        // AND part of the same boundary rule (same condition, or one nested in the
        // other's guarded branch)
        val cmpMatches = quoteCmps.collect {
          case (qc, (qBase, qIdx, qOff, _))
            if qBase == eBase && qIdx == eIdx && qOff == 0 &&
               methOf(qc).map(_.id) == em.map(_.id) &&
               sameBoundaryScope(qc, ec) => qc.id
        }
        val searchMatches = searchQuotePos.collect {
          case sp if sp.base == eBase && sp.posVar == eIdx &&
                     Some(sp.methodId) == em.map(_.id) &&
                     callById.get(sp.callId).exists(spNode => sameBoundaryScope(spNode, ec)) =>
            sp.callId
        }
        (cmpMatches ++ searchMatches).distinct.foreach { qcId =>
          // the enclosing boolean combination, when there is one
          val check = ec.astParent match {
            case p: nodes.Call if p.name == "<operator>.logicalAnd" || p.name == "<operator>.logicalOr" => p.id
            case _ => ec.id
          }
          pic.println(List(fileOf(ec), em.map(_.fullName).getOrElse("?"), em.map(_.id).getOrElse(-1L),
            ln(ec), check, qcId, ec.id, eIdxExprId, eOff, eBase, eIdx).mkString("\t"))
        }
      }
    }
  } finally pic.close()

  // ------------------------------------------------- quoted-string scanner sites
  // A method is a character-scanning quoted-string parser when it compares a character
  // against a quote literal AND indexes a string (indexAccess / charAt) somewhere in the
  // same method. Emitting these makes a parity-correct hand-written parser a classified
  // NEGATIVE instead of an absent record.
  val pqs = w("parser_quote_sites.tsv")
  try {
    val methodsWithIndexing = cpg.call.l.filter { c =>
      c.name == "<operator>.indexAccess" || c.name == "charAt" || c.name == "charCodeAt"
    }.flatMap(methOf).map(_.id).toSet
    cpg.call.l.foreach { c =>
      if (comparisonOps.contains(c.name)) {
        val as = args(c)
        // A resolved quote delimiter on one side is the ordinary case.
        val quoteSide = as.find(isQuoteDelim)
        val otherSide = quoteSide.flatMap(q => as.find(_.id != q.id))
        // Otherwise: an indexed character compared against a delimiter whose
        // identity could not be resolved. That is still a quote-boundary site
        // and must be recorded -- as an abstention downstream, never silence.
        val unresolvedPair = {
          val pairs = List((as.lift(0), as.lift(1)), (as.lift(1), as.lift(0)))
          pairs.collectFirst {
            case (Some(x), Some(y))
              if isUnresolvedDelim(y) &&
                 (indexParts(x).isDefined ||
                  charVarOrigin.contains((methOf(c).map(_.id).getOrElse(-1L),
                                          x match { case i: nodes.Identifier => i.name
                                                    case _ => "" }))) => x
          }
        }
        val chosen: Option[(nodes.Expression, String)] =
          (quoteSide, otherSide) match {
            case (Some(q), Some(other)) =>
              Some((other, delimRole(q).map(_._2).getOrElse(LITERAL)))
            case _ => unresolvedPair.map(x => (x, UNRESOLVED))
          }
        chosen.foreach { case (other, resolution) =>
          val m = methOf(c)
          val mId = m.map(_.id).getOrElse(-1L)
          if (methodsWithIndexing.contains(mId)) {
            val directIdx = indexParts(other).isDefined
            pqs.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"), mId, ln(c),
              c.id, other.id, if (directIdx) "INDEXED_CHAR" else "EXTRACTED_CHAR",
              resolution).mkString("\t"))
          }
        }
      }
    }
    // A parser whose quote position comes from a search still has a boundary
    // rule, so it gets a site of its own rather than being an absent record.
    searchPositions.foreach { sp =>
      pqs.println(List(sp.file, sp.method, sp.methodId, sp.line, sp.callId, sp.callId,
        "SEARCH_POSITION", sp.resolution).mkString("\t"))
    }
  } finally pqs.close()

  // ------------------------------------------------------- parity mechanisms
  // Structural evidence that a method DOES establish escape-run parity. Any of these
  // makes the method a negative for this property.
  val pm = w("parity_mechanisms.tsv")
  try {
    // (a) an explicit modulo-2 test
    cpg.call.nameExact("<operator>.modulo").l.foreach { c =>
      if (argAt(c, 2).flatMap(intValue).contains(2)) {
        val m = methOf(c)
        pm.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"), m.map(_.id).getOrElse(-1L),
          ln(c), c.id, "MODULO_TWO").mkString("\t"))
      }
    }
    // (b) a boolean toggle: X = !X
    // (b) a boolean toggle that is genuinely ESCAPE-driven: X = !X where some
    //     controlling condition tests the CURRENT character for EQUALITY against the
    //     escape character. A toggle driven by a QUOTE comparison (`inQuotes = !inQuotes`
    //     under `if (c == '"' && ...)`) tracks string state, not escape-run parity, and
    //     must not exonerate a one-position boundary rule. Requiring EQUALITY at offset
    //     zero also excludes the `s[i-1] != ESCAPE` test that is itself the defect.
    def isEscapeEqualityAtZero(n: nodes.AstNode): Boolean = {
      val stack = scala.collection.mutable.Stack[nodes.AstNode](n)
      var found = false
      var guard = 0
      while (stack.nonEmpty && !found && guard < 5000) {
        val cur = stack.pop()
        guard += 1
        cur match {
          case c: nodes.Call if c.name == "<operator>.equals" ||
                                c.name == "<operator>.strictEquals" ||
                                c.name == "<operator>.identical" =>
            val as = c.argument.l
            val hasEsc = as.exists(isEscapeLiteral)
            val zeroOffset = as.exists { a =>
              indexParts(a).flatMap { case (_, idx) => offsetParts(idx) }.exists(_._2 == 0) ||
              a.isInstanceOf[nodes.Identifier]
            }
            if (hasEsc && zeroOffset) found = true
          case _ => ()
        }
        cur._astOut.foreach { case a: nodes.AstNode => stack.push(a); case _ => () }
      }
      found
    }
    def escapeDrivenToggle(a: nodes.Call): Boolean = {
      var cur: Option[nodes.AstNode] = Some(a)
      var found = false
      var g = 0
      while (cur.isDefined && !found && g < 300) {
        cur.get match {
          case cs: nodes.ControlStructure =>
            cs.condition.headOption.foreach(c => if (isEscapeEqualityAtZero(c)) found = true)
          case _ => ()
        }
        cur = cur.get._astIn.collectFirst { case x: nodes.AstNode => x }
        g += 1
      }
      found
    }
    // group toggles per (method, variable): the variable qualifies when ANY of its
    // toggles in that method is escape-driven, so the `if (escaped)` consume-branch
    // counts once the `if (ch == ESCAPE)` branch has established the variable's role.
    val toggles = scala.collection.mutable.ListBuffer[(Long, String, nodes.Call)]()
    cpg.call.nameExact("<operator>.assignment").l.foreach { a =>
      val lhs = argAt(a, 1).collect { case i: nodes.Identifier => i.name }
      val rhsNeg = argAt(a, 2).collect {
        case c: nodes.Call if c.name == "<operator>.logicalNot" =>
          argAt(c, 1).collect { case i: nodes.Identifier => i.name }
      }.flatten
      if (lhs.isDefined && lhs == rhsNeg)
        toggles += ((methOf(a).map(_.id).getOrElse(-1L), lhs.get, a))
    }
    val qualified = toggles.filter { case (_, _, a) => escapeDrivenToggle(a) }
      .map { case (m, v, _) => (m, v) }.toSet
    toggles.foreach { case (mId, v, a) =>
      if (qualified.contains((mId, v))) {
        val m = methOf(a)
        pm.println(List(fileOf(a), m.map(_.fullName).getOrElse("?"), mId, ln(a), a.id,
          "BOOLEAN_TOGGLE").mkString("\t"))
      }
    }
    // (c) a backwards walk over the escape run: a comparison of an indexed char
    //     against the escape literal whose index variable is decremented in the same
    //     method (i.e. the parser counts consecutive escape characters).
    val decrementedVars = scala.collection.mutable.Map[Long, scala.collection.mutable.Set[String]]()
    def noteDec(mId: Long, nm: String) =
      decrementedVars.getOrElseUpdate(mId, scala.collection.mutable.Set[String]()) += nm
    cpg.call.l.foreach { c =>
      val mId = methOf(c).map(_.id).getOrElse(-1L)
      if (c.name == "<operator>.preDecrement" || c.name == "<operator>.postDecrement")
        argAt(c, 1).collect { case i: nodes.Identifier => noteDec(mId, i.name) }
      if (c.name == "<operator>.assignmentMinus")
        argAt(c, 1).collect { case i: nodes.Identifier => noteDec(mId, i.name) }
      if (c.name == "<operator>.assignment") {
        val lhs = argAt(c, 1).collect { case i: nodes.Identifier => i.name }
        argAt(c, 2).collect {
          case s: nodes.Call if s.name == "<operator>.subtraction" =>
            val base = argAt(s, 1).collect { case i: nodes.Identifier => i.name }
            if (base.isDefined && base == lhs) lhs.foreach(noteDec(mId, _))
        }
      }
    }
    cpg.call.l.foreach { c =>
      indexedCharCmp(c, isEscapeLiteral).foreach { case (_, idxName, _, _) =>
        val m = methOf(c)
        val mId = m.map(_.id).getOrElse(-1L)
        if (decrementedVars.get(mId).exists(_.contains(idxName)))
          pm.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"), mId, ln(c), c.id,
            "ESCAPE_RUN_COUNT_LOOP").mkString("\t"))
      }
    }
  } finally pm.close()

  // ---------------------------------------------------------- delayed sources
  val FS_READ = Set("readFile", "readFileSync", "createReadStream", "read", "readv")
  val ARCHIVE_MODULES = Set("yauzl", "unzipper", "adm-zip", "adm_zip", "tar", "tar-stream",
    "node-stream-zip", "jszip", "archiver", "zlib", "node:zlib", "node:fs", "fs",
    "fs/promises", "node:fs/promises")
  val DB_MEMBERS = Set("query", "execute", "all", "get", "each", "exec")
  val DB_MODULES = Set("mysql", "mysql2", "pg", "sqlite3", "better-sqlite3", "mssql",
    "mariadb", "knex", "sequelize")
  val ds = w("delayed_sources.tsv")
  val delayedSourceIds = scala.collection.mutable.Set[Long]()
  val delayedSourceNodes = scala.collection.mutable.ListBuffer[nodes.Expression]()
  try {
    cpg.call.l.foreach { c =>
      memberCallParts(c).foreach { case (baseCode, member) =>
        val baseIdent = baseCode.split("\\.").headOption.getOrElse(baseCode)
        val mod = moduleOfIdent.get(baseIdent)
        val m = methOf(c)
        val importId = importNodeOfIdent.getOrElse(baseIdent, -1L)
        val isFsRead = mod.exists(x => x == "fs" || x == "node:fs" || x == "fs/promises" ||
          x == "node:fs/promises") && FS_READ.contains(member)
        val isArchive = mod.exists(ARCHIVE_MODULES.contains) && !isFsRead
        val isDb = mod.exists(DB_MODULES.contains) && DB_MEMBERS.contains(member)
        if (isFsRead || isArchive || isDb) {
          val kind = if (isFsRead) "STORED_FILE_READ" else if (isArchive) "ARCHIVE_READ" else "DATABASE_ROW_READ"
          ds.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"), ln(c), c.id,
            s"${mod.get}.$member", mod.get, importId, "RESOLVED_IMPORT", kind).mkString("\t"))
          delayedSourceIds += c.id; delayedSourceNodes += c
        } else if (mod.isEmpty && (FS_READ.contains(member) || DB_MEMBERS.contains(member))) {
          // shape looks like a delayed read but the receiver never resolved to an
          // import -- an explicit abstention, never a silent positive or negative.
          ds.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"), ln(c), c.id,
            s"$baseIdent.$member", "", -1L, "UNRESOLVED_SOURCE_IDENTITY", "").mkString("\t"))
        }
      }
    }
  } finally ds.close()

  // ------------------------------------------------------------- transforms
  val DECODE_ENCODINGS = Set("utf8", "utf-8", "ascii", "latin1", "binary", "ucs2", "ucs-2", "utf16le")
  val ENCODE_ENCODINGS = Set("base64", "base64url", "hex")
  val tc = w("transform_calls.tsv")
  val rcb = w("replacement_callbacks.tsv")
  val transformIds = scala.collection.mutable.Map[Long, String]()
  val transformNodes = scala.collection.mutable.Map[Long, nodes.Call]()
  try {
    cpg.call.l.foreach { c =>
      val m = methOf(c)
      def emit(family: String, ident: String, regexArg: Long, res: String) = {
        tc.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"), ln(c), c.id, family,
          ident, regexArg, res).mkString("\t"))
        transformIds(c.id) = family
        transformNodes(c.id) = c
      }
      // Buffer.from(x, ENC)
      if (c.name == "from") {
        val baseIsBuffer = c.methodFullName == "Buffer.from"
        if (baseIsBuffer) {
          val enc = argAt(c, 2).flatMap(stringValue).map(_.toLowerCase)
          enc match {
            case Some(e) if ENCODE_ENCODINGS.contains(e) => emit("DECODE", s"Buffer.from:$e", -1L, "RESOLVED")
            case Some(e) if DECODE_ENCODINGS.contains(e) => emit("ENCODE_INPUT", s"Buffer.from:$e", -1L, "RESOLVED")
            case _ => emit("DECODE", "Buffer.from", -1L, "UNRESOLVED_ENCODING")
          }
        }
      }
      // <buf>.toString(ENC)
      if (c.name == "toString") {
        val enc = argAt(c, 1).flatMap(stringValue).map(_.toLowerCase)
        enc match {
          case Some(e) if ENCODE_ENCODINGS.contains(e) => emit("ENCODE", s"toString:$e", -1L, "RESOLVED")
          case Some(e) if DECODE_ENCODINGS.contains(e) => emit("DECODE", s"toString:$e", -1L, "RESOLVED")
          case _ => ()
        }
      }
      if (c.name == "atob") emit("DECODE", "atob", -1L, "RESOLVED")
      if (c.name == "btoa") emit("ENCODE", "btoa", -1L, "RESOLVED")
      if (c.name == "decodeURIComponent" || c.name == "unescape") emit("DECODE", c.name, -1L, "RESOLVED")
      if (c.name == "encodeURIComponent" || c.name == "escape") emit("ENCODE", c.name, -1L, "RESOLVED")
      if (c.name == "stringify") {
        if (c.methodFullName == "JSON.stringify") emit("ENCODE", "JSON.stringify", -1L, "RESOLVED")
      }
      // .replace / .replaceAll -- the transformation that applies a boundary rule
      if (c.name == "replace" || c.name == "replaceAll") {
        val patArg = argAt(c, 1)
        // resolve an identifier pattern argument back to its regex assignment
        val patNodeId: Long = patArg match {
          case Some(l: nodes.Literal) if regexSiteIds.contains(l.id) => l.id
          case Some(i: nodes.Identifier) =>
            // scoped to the SAME FILE: a same-named constant in another file is a
            // different binding and must never be treated as this one's definition.
            val here = fileOf(c)
            val defs = cpg.call.nameExact("<operator>.assignment").l.filter { a =>
              fileOf(a) == here &&
              argAt(a, 1).collect { case x: nodes.Identifier => x.name }.contains(i.name)
            }
            val regexDefs = defs.flatMap(a => argAt(a, 2)).filter(x => regexSiteIds.contains(x.id))
            if (regexDefs.size == 1) regexDefs.head.id else -1L
          case Some(x) if regexSiteIds.contains(x.id) => x.id
          case _ => -1L
        }
        val res = patArg match {
          case None => "NO_PATTERN_ARGUMENT"
          case Some(_) if patNodeId >= 0 => "RESOLVED"
          case Some(l: nodes.Literal) if stringValue(l).isDefined => "STRING_PATTERN_NOT_REGEX"
          case _ => "UNRESOLVED_PATTERN_IDENTITY"
        }
        emit("REPLACE", c.name, patNodeId, res)
        // the replacement callback identity
        val cb = argAt(c, 2)
        val (kind, cbId, cres) = cb match {
          case Some(mr: nodes.MethodRef) => ("METHOD_REF", mr.id, "RESOLVED")
          case Some(l: nodes.Literal) if stringValue(l).isDefined => ("STRING_LITERAL", l.id, "RESOLVED")
          case Some(i: nodes.Identifier) =>
            val here = fileOf(c)
            val defs = cpg.call.nameExact("<operator>.assignment").l.filter { a =>
              fileOf(a) == here &&
              argAt(a, 1).collect { case x: nodes.Identifier => x.name }.contains(i.name)
            }.flatMap(a => argAt(a, 2)).collect { case mr: nodes.MethodRef => mr }
            if (defs.size == 1) ("METHOD_REF", defs.head.id, "RESOLVED")
            else if (defs.isEmpty) ("IDENTIFIER", i.id, "UNRESOLVED_CALLBACK_IDENTITY")
            else ("IDENTIFIER", i.id, "AMBIGUOUS_CALLBACK_IDENTITY")
          case Some(x) => ("OTHER", x.id, "UNRESOLVED_CALLBACK_IDENTITY")
          case None => ("NONE", -1L, "NO_CALLBACK_ARGUMENT")
        }
        rcb.println(List(fileOf(c), ln(c), c.id, cbId, kind, cres).mkString("\t"))
      }
    }
  } finally { tc.close(); rcb.close() }

  // -------------------------------------------------------------- consumers
  val STRUCTURED_MODULES = Map(
    "yaml" -> Set("parse", "load", "safeLoad"), "js-yaml" -> Set("load", "safeLoad", "parse"),
    "querystring" -> Set("parse"), "node:querystring" -> Set("parse"),
    "csv-parse" -> Set("parse"), "php-unserialize" -> Set("unserialize"),
    "php-serialize" -> Set("unserialize"), "serialize-php" -> Set("unserialize"))
  val LOG_MEMBERS = Set("log", "info", "warn", "error", "debug", "trace")
  val cs = w("consumers.tsv")
  val consumerIds = scala.collection.mutable.Set[Long]()
  val consumerNodes = scala.collection.mutable.ListBuffer[nodes.Call]()
  val loggingNodes = scala.collection.mutable.ListBuffer[nodes.Call]()
  try {
    cpg.call.l.foreach { c =>
      val m = methOf(c)
      def emit(ident: String, mod: String, kind: String, res: String) = {
        cs.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"), ln(c), c.id, ident, mod,
          kind, res).mkString("\t"))
        if (kind == "STRUCTURED_DATA_INTERPRETER" || kind == "DATABASE_IMPORT") {
          consumerIds += c.id; consumerNodes += c
        }
        if (kind == "LOGGING_ONLY") loggingNodes += c
      }
      // JSON.parse
      if (c.methodFullName == "JSON.parse")
        emit("JSON.parse", "", "STRUCTURED_DATA_INTERPRETER", "RESOLVED")
      memberCallParts(c).foreach { case (baseCode, member) =>
        val baseIdent = baseCode.split("\\.").headOption.getOrElse(baseCode)
        val mod = moduleOfIdent.get(baseIdent)
        mod.foreach { mm =>
          STRUCTURED_MODULES.get(mm).foreach { members =>
            if (members.contains(member)) emit(s"$mm.$member", mm, "STRUCTURED_DATA_INTERPRETER", "RESOLVED")
          }
          if (DB_MODULES.contains(mm) && DB_MEMBERS.contains(member))
            emit(s"$mm.$member", mm, "DATABASE_IMPORT", "RESOLVED")
        }
        if (baseIdent == "console" && LOG_MEMBERS.contains(member))
          emit(s"console.$member", "", "LOGGING_ONLY", "RESOLVED")
        if (mod.isEmpty && DB_MEMBERS.contains(member) && member == "query")
          emit(s"$baseIdent.$member", "", "DATABASE_IMPORT", "UNRESOLVED_CONSUMER_IDENTITY")
      }
    }
  } finally cs.close()

  // ------------------------------------------------------------ chain edges
  // Real dataflow, computed by the engine -- never assumed from ordering in the file.
  val ce = w("chain_edges.tsv")
  try {
    val srcNodes: List[nodes.Expression] = delayedSourceNodes.toList
    val repNodes: List[nodes.Expression] =
      transformIds.filter(_._2 == "REPLACE").keys.toList.flatMap(transformNodes.get)
    val encNodes: List[nodes.Expression] =
      transformIds.filter(_._2 == "ENCODE").keys.toList.flatMap(transformNodes.get)
    val conNodes: List[nodes.Expression] = consumerNodes.toList
    val logNodes: List[nodes.Expression] = loggingNodes.toList

    def edges(from: List[nodes.Expression], to: List[nodes.Expression], kind: String): Unit = {
      if (from.nonEmpty && to.nonEmpty) {
        to.foreach { t =>
          val flows = Iterator(t).reachableByFlows(from.iterator).l
          flows.foreach { f =>
            f.elements.headOption.foreach { origin =>
              ce.println(List(kind.split("2")(0), origin.id, kind.split("2")(1), t.id, kind).mkString("\t"))
            }
          }
        }
      }
    }
    edges(srcNodes, repNodes, "DELAYED_SOURCE2REPLACE")
    edges(repNodes, encNodes, "REPLACE2ENCODE")
    edges(repNodes, conNodes, "REPLACE2CONSUMER")
    edges(encNodes, conNodes, "ENCODE2CONSUMER")
    edges(srcNodes, conNodes, "DELAYED_SOURCE2CONSUMER")
    // logging destinations are recorded so that "the result only reached logging" is
    // positive evidence rather than the mere absence of a structured consumer.
    edges(repNodes, logNodes, "REPLACE2LOGGING")
    edges(encNodes, logNodes, "ENCODE2LOGGING")
  } finally ce.close()

  // -------------------------------------------- execution timing (EVIDENCE ONLY)
  // Recorded so the record is complete. This is NEVER treated as a guard: an
  // administrative, scheduled or otherwise delayed execution context neither
  // establishes nor removes a parser-correctness finding.
  val et = w("execution_timing.tsv")
  try {
    cpg.call.l.foreach { c =>
      val m = methOf(c)
      def emit(k: String) = et.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"), ln(c), c.id, k).mkString("\t"))
      if (c.name == "setInterval") emit("SCHEDULED_INTERVAL")
      if (c.name == "setTimeout") emit("DEFERRED_TIMEOUT")
      memberCallParts(c).foreach { case (b, member) =>
        val mod = moduleOfIdent.get(b.split("\\.").headOption.getOrElse(b))
        if (mod.exists(x => x == "node-cron" || x == "cron" || x == "node-schedule") && member == "schedule")
          emit("CRON_REGISTRATION")
      }
    }
  } finally et.close()

  val nRegex = scala.io.Source.fromFile(s"$rawDir/regex_sites.tsv").getLines().size
  val nChecks = scala.io.Source.fromFile(s"$rawDir/parser_index_checks.tsv").getLines().size
  val nParity = scala.io.Source.fromFile(s"$rawDir/parity_mechanisms.tsv").getLines().size
  val nSrc = scala.io.Source.fromFile(s"$rawDir/delayed_sources.tsv").getLines().size
  val nCons = scala.io.Source.fromFile(s"$rawDir/consumers.tsv").getLines().size
  val nEdge = scala.io.Source.fromFile(s"$rawDir/chain_edges.tsv").getLines().size
  println(s"ESCAPE_PARITY_FACTS ok: regex_sites=$nRegex index_checks=$nChecks " +
    s"parity_mechanisms=$nParity delayed_sources=$nSrc consumers=$nCons chain_edges=$nEdge")
}
