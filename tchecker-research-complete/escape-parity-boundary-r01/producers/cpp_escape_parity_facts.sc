// ESCAPE-PARITY-BOUNDARY -- C/C++ quote-boundary rule fact producer.
//
// Same property, same shared parity rule, different LANGUAGE ADAPTER. The defect shape
// is language-independent:
//
//     A quote is escaped when preceded by an ODD-length consecutive escape run.
//     A quote terminates the string when preceded by an EVEN-length escape run.
//
// A boundary rule that inspects a fixed single preceding position cannot establish that
// parity, whether it is written as s[i-1], *(p-1) or s.at(i-1).
//
// This producer emits the SAME fact schema as the JavaScript producer, so both feed one
// reducer and one verdict vocabulary. Two things genuinely differ in C/C++ and are
// handled here rather than papered over:
//
//   1. Character literals keep their SOURCE escaping ('\\' , '\'' , '"'), unlike the
//      JS frontend which stores an already-unescaped value. A C-escape decoder is
//      applied before any character comparison.
//   2. Character access has three forms, not one: subscript (indexAccess /
//      indirectIndexAccess, the latter for an overloaded operator[]), pointer
//      dereference (*(p - 1)), and a member call (s.at(i - 1)).
//
// std::regex patterns are emitted as regex sites. std::regex's DEFAULT grammar is
// ECMAScript, so downstream they are classified by the ECMAScript adapter -- never by
// the PCRE one.
//
// Fact files (identical schema to the JS producer):
//   regex_sites.tsv          file, method, method_id, line, node_id, resolution,
//                            pattern_body, flags, detail
//   parser_quote_sites.tsv   file, method, method_id, line, cmp_id, other_id,
//                            access_kind, delimiter_resolution
//   parser_index_checks.tsv  file, method, method_id, line, check_id, quote_cmp_id,
//                            esc_cmp_id, index_expr_id, offset, base_name, index_name
//   parity_mechanisms.tsv    file, method, method_id, line, node_id, mechanism
//   language.tsv             language, frontend
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, rawDir: String) = {
  importCpg(cpgFile)
  new java.io.File(rawDir).mkdirs()

  def cl(s: String): String =
    Option(s).getOrElse("").replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "")
      .replace("\t", "\\t").take(400)
  def w(n: String) = new java.io.PrintWriter(new java.io.File(s"$rawDir/$n"), "UTF-8")
  def ln(n: nodes.AstNode): Int = n.lineNumber.map(_.toInt).getOrElse(-1)

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

  // ------------------------------------------------------- C escape decoding
  /** Decode a C/C++ character literal such as '\\' , '\'' , 'a' to its real value. */
  def charLiteralValue(n: nodes.AstNode): Option[String] = n match {
    case l: nodes.Literal =>
      val c = Option(l.code).getOrElse("")
      if (c.length >= 3 && c.head == '\'' && c.last == '\'') {
        val body = c.substring(1, c.length - 1)
        if (body.length == 1) Some(body)
        else if (body.length == 2 && body.head == '\\') body(1) match {
          case '\\' => Some("\\"); case '\'' => Some("'"); case '"' => Some("\"")
          case 'n' => Some("\n"); case 't' => Some("\t"); case 'r' => Some("\r")
          case '0' => Some("\u0000"); case other => Some(other.toString)
        }
        else None
      } else None
    case _ => None
  }
  /** Decode a C/C++ string literal, resolving its escape sequences. */
  def stringLiteralValue(n: nodes.AstNode): Option[String] = n match {
    case l: nodes.Literal =>
      val c = Option(l.code).getOrElse("")
      if (c.length >= 2 && c.head == '"' && c.last == '"') {
        val body = c.substring(1, c.length - 1)
        val sb = new StringBuilder
        var i = 0
        while (i < body.length) {
          if (body(i) == '\\' && i + 1 < body.length) {
            body(i + 1) match {
              case '\\' => sb.append('\\'); case '"' => sb.append('"')
              case '\'' => sb.append('\''); case 'n' => sb.append('\n')
              case 't' => sb.append('\t'); case 'r' => sb.append('\r')
              case other => sb.append(other)
            }
            i += 2
          } else { sb.append(body(i)); i += 1 }
        }
        Some(sb.toString)
      } else None
    case _ => None
  }
  def intValue(n: nodes.AstNode): Option[Int] = n match {
    case l: nodes.Literal => scala.util.Try(Option(l.code).getOrElse("").trim.toInt).toOption
    case _ => None
  }

  val QUOTE_CHARS = Set("'", "\"", "`")
  def isQuoteLiteral(n: nodes.AstNode): Boolean = charLiteralValue(n).exists(QUOTE_CHARS.contains)
  def isEscapeLiteral(n: nodes.AstNode): Boolean = charLiteralValue(n).contains("\\")

  // ---------------------------------------------------- delimiter identity
  // C parsers parameterise their delimiters too -- `const char q = cfg.quote;`
  // then `s[i] == q`. Requiring a character literal on one side made every such
  // site invisible. Resolution is all-or-nothing: a name counts as a delimiter
  // only when EVERY assignment or initialiser reaching it in the file is a
  // character literal. Anything else leaves the identity unresolved, and an
  // unresolved delimiter abstains rather than guessing.
  val LITERAL = "LITERAL"; val RESOLVED = "RESOLVED"; val UNRESOLVED = "UNRESOLVED"
  val ROLE_QUOTE = "QUOTE"; val ROLE_ESCAPE = "ESCAPE"; val ROLE_OTHER = "OTHER"

  val assignedValues = scala.collection.mutable.Map[(String, String), List[Option[String]]]()
  var aliasEdges = List.empty[((String, String), (String, String))]
  cpg.call.nameExact("<operator>.assignment").l.foreach { a =>
    for {
      nm <- argAt(a, 1).collect { case i: nodes.Identifier => i.name }
      rhs <- argAt(a, 2)
    } {
      val k = (fileOf(a), nm)
      assignedValues(k) = assignedValues.getOrElse(k, Nil) :+ charLiteralValue(rhs)
      rhs match {
        case i: nodes.Identifier => aliasEdges = aliasEdges :+ (k, (fileOf(a), i.name))
        case _ => ()
      }
    }
  }

  def resolveIdent(file: String, name: String): Option[Set[String]] =
    assignedValues.get((file, name)) match {
      case Some(vs) if vs.nonEmpty && vs.forall(_.isDefined) => Some(vs.flatten.toSet)
      case _ => None
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

  def delimRole(n: nodes.AstNode): Option[(String, String)] = charLiteralValue(n) match {
    case Some(v) =>
      val r = if (QUOTE_CHARS.contains(v)) ROLE_QUOTE
              else if (v == "\\") ROLE_ESCAPE else ROLE_OTHER
      Some((r, LITERAL))
    case None => n match {
      case i: nodes.Identifier =>
        resolveIdent(fileOf(i), i.name) match {
          case Some(vs) => Some((roleOfValues(vs), RESOLVED))
          case None =>
            if (DELIMITER_LIKE.contains((fileOf(i), i.name))) Some((ROLE_QUOTE, UNRESOLVED))
            else None
        }
      case _ => None
    }
  }

  def isQuoteDelim(n: nodes.AstNode): Boolean =
    delimRole(n).exists { case (r, res) => r == ROLE_QUOTE && res != UNRESOLVED }
  def isEscapeDelim(n: nodes.AstNode): Boolean =
    delimRole(n).exists { case (r, res) => r == ROLE_ESCAPE && res != UNRESOLVED }
  def isUnresolvedDelim(n: nodes.AstNode): Boolean =
    delimRole(n).exists { case (_, res) => res == UNRESOLVED }

  def args(c: nodes.Call): List[nodes.Expression] = c.argument.l.sortBy(_.argumentIndex)
  def argAt(c: nodes.Call, i: Int): Option[nodes.Expression] = c.argument.l.find(_.argumentIndex == i)

  // ------------------------------------------- character-access adapters (C/C++)
  // Subscript s[i] (plain or overloaded), pointer deref *(p - 1), member call s.at(i).
  // All three reduce to (base identity, index expression) so the shared shape model
  // does not need to know which spelling was used.
  def indexParts(n: nodes.AstNode): Option[(String, nodes.Expression)] = n match {
    case c: nodes.Call if c.name == "<operator>.indexAccess" ||
                          c.name == "<operator>.indirectIndexAccess" =>
      for { b <- argAt(c, 1); i <- argAt(c, 2) } yield (Option(b.code).getOrElse(""), i)
    case c: nodes.Call if c.name == "at" =>
      // a member call: the receiver is argumentIndex 0 and the index argumentIndex 1,
      // unlike the operator forms which use 1 and 2.
      for { b <- argAt(c, 0); i <- argAt(c, 1) } yield (Option(b.code).getOrElse(""), i)
    case c: nodes.Call if c.name == "<operator>.indirection" =>
      // *(p - 1): the pointer itself carries the offset, so the deref is the "base"
      argAt(c, 1).map(inner => ("<deref>", inner))
    case _ => None
  }
  /** `IDX - <int>` -> (name, offset); bare `IDX` -> (name, 0). */
  def offsetParts(n: nodes.AstNode): Option[(String, Int)] = n match {
    case i: nodes.Identifier => Some((i.name, 0))
    case c: nodes.Call if c.name == "<operator>.subtraction" =>
      for {
        a <- argAt(c, 1).collect { case i: nodes.Identifier => i.name }
        k <- argAt(c, 2).flatMap(intValue)
      } yield (a, k)
    case c: nodes.Call if c.name == "<operator>.addition" =>
      for {
        a <- argAt(c, 1).collect { case i: nodes.Identifier => i.name }
        k <- argAt(c, 2).flatMap(intValue)
      } yield (a, -k)
    case c: nodes.Call if c.name == "<operator>.cast" =>
      argAt(c, 2).flatMap(offsetParts)
    case _ => None
  }

  val comparisonOps = Set("<operator>.equals", "<operator>.notEquals")

  def indexedCharCmp(c: nodes.Call, lit: nodes.AstNode => Boolean)
      : Option[(String, String, Int, Long)] = {
    if (!comparisonOps.contains(c.name)) return None
    val as = args(c)
    List((as.lift(0), as.lift(1)), (as.lift(1), as.lift(0))).flatMap {
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

  // ------------------------------------------- search-established positions
  // A scanner often establishes "position p holds a quote" with a SEARCH rather
  // than a comparison: `p = s.find(quote, cursor)` or `q = strchr(s, quote)`.
  // The pairing below looked only for comparisons, so the quote half of a
  // one-position rule written this way was never found.
  //
  // Only BACKWARD offsets pair (`s[p - 1]`). A forward look (`s[p + 1]`) is the
  // doubled-delimiter idiom, which consumes the pair and is parity-correct, so
  // it must never feed the candidate path. offsetParts recognises subtraction
  // only, which is what keeps that true.
  val MEMBER_SEARCH = Set("find", "find_first_of", "rfind")
  val FREE_SEARCH = Set("strchr", "strrchr", "memchr")
  case class SearchPos(callId: Long, base: String, posVar: String, methodId: Long,
                       resolution: String, line: Int, file: String, method: String)
  val searchPositions = cpg.call.nameExact("<operator>.assignment").l.flatMap { a =>
    val posVar = argAt(a, 1).collect { case i: nodes.Identifier => i.name }
    val call = argAt(a, 2).collect { case c: nodes.Call => c }
    val found = for {
      pv <- posVar
      c <- call
      (baseNode, needle) <-
        if (MEMBER_SEARCH.contains(c.name))
          for { r <- c.receiver.headOption; n <- argAt(c, 1) } yield (r, n)
        else if (FREE_SEARCH.contains(c.name))
          for { b <- argAt(c, 1); n <- argAt(c, 2) } yield (b, n)
        else None
      (role, res) <- delimRole(needle)
      if role == ROLE_QUOTE
    } yield SearchPos(c.id,
                      Option(baseNode.code).getOrElse(""),
                      pv, methOf(a).map(_.id).getOrElse(-1L), res, ln(a),
                      fileOf(a), methOf(a).map(_.fullName).getOrElse("?"))
    found
  }

  // ------------------------------------------------------- quote scanner sites
  val pqs = w("parser_quote_sites.tsv")
  try {
    val methodsWithAccess = cpg.call.l.filter { c =>
      c.name == "<operator>.indexAccess" || c.name == "<operator>.indirectIndexAccess" ||
      c.name == "<operator>.indirection" || c.name == "at"
    }.flatMap(methOf).map(_.id).toSet
    cpg.call.l.foreach { c =>
      if (comparisonOps.contains(c.name)) {
        val as = args(c)
        val q = as.find(isQuoteDelim)
        val other = q.flatMap(qq => as.find(_.id != qq.id))
        // An accessed character compared against a delimiter whose identity is
        // unresolved is still a quote-boundary site. Recording it as such makes
        // it an abstention downstream instead of disappearing entirely.
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
        val chosen: Option[(nodes.Expression, String)] = (q, other) match {
          case (Some(qq), Some(o)) => Some((o, delimRole(qq).map(_._2).getOrElse(LITERAL)))
          case _ => unresolvedPair.map(x => (x, UNRESOLVED))
        }
        chosen.foreach { case (o, resolution) =>
          val m = methOf(c)
          val mId = m.map(_.id).getOrElse(-1L)
          if (methodsWithAccess.contains(mId)) {
            val direct = indexParts(o).isDefined
            pqs.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"), mId, ln(c), c.id,
              o.id, if (direct) "ACCESSED_CHAR" else "EXTRACTED_CHAR",
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

  // ---------------------------------------------------- one-position index checks

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

  // Two comparisons belong to the SAME boundary rule only when one is reachable
  // from the other's nearest enclosing control structure: either they sit in the
  // very same condition (a flat `a && b` or `a || b`), or one is nested inside a
  // branch guarded by the other (`if (a) { if (b) {...} }`, in either order).
  // Matching on method + base-expression + index-variable alone (as before) pairs
  // an escape check with EVERY quote comparison anywhere in a function that shares
  // its buffer and loop index -- including unrelated sibling branches. That
  // produced a real false positive: SourceMod's ParseStream_SMC has one genuine
  // one-position rule on its CLOSING-quote branch and a wholly separate OPENING-
  // quote branch with no escape check of its own, and the old same-method-only
  // join borrowed the closing branch's check as "evidence" for the opening one.
  // nearestControlId is scoped to IF-shaped control structures only: a loop
  // (while/for/do) is not a decision -- its body runs every iteration, so
  // treating a loop as the "nearest control" would make every statement in
  // the loop body count as guarded by it.
  //
  // isWithinControl climbs through ANY ancestor -- including other, unrelated
  // `if` nodes -- EXCEPT a loop, which stops the climb. Nested ifs must still
  // pair (`if (a) { if (b) {...} }` is one boundary rule split across two
  // guards), so climbing must not stop at the first if that is not the
  // target. But a loop is not a guard at all: an escape check nested inside
  // one `if` branch of a loop body and an unrelated statement in a SIBLING
  // branch of the SAME loop both have the loop as a common ancestor without
  // sharing a decision, and reachability confirmed as a real false positive:
  // SourceMod's ParseStream_SMC has both branches inside one `for` loop, and
  // an earlier version of this fix (with no loop check at all) paired them
  // through the shared loop ancestor.
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
    val escCmps = cpg.call.l.flatMap(c => indexedCharCmp(c, isEscapeDelim).map(r => (c, r)))
    // A resolved search position stands in for a quote comparison at offset 0.
    // An unresolved delimiter does not: the method abstains on identity and must
    // not reach a verdict here.
    val searchQuotePos = searchPositions.filter(_.resolution != UNRESOLVED)
    val callById = cpg.call.l.map(c => c.id -> c).toMap
    escCmps.foreach { case (ec, (eBase, eIdx, eOff, eIdxExprId)) =>
      if (eOff != 0) {
        val em = methOf(ec)
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
          val check = ec.astParent match {
            case p: nodes.Call if p.name == "<operator>.logicalAnd" ||
                                  p.name == "<operator>.logicalOr" => p.id
            case _ => ec.id
          }
          pic.println(List(fileOf(ec), em.map(_.fullName).getOrElse("?"),
            em.map(_.id).getOrElse(-1L), ln(ec), check, qcId, ec.id, eIdxExprId, eOff,
            eBase, eIdx).mkString("\t"))
        }
      }
    }
  } finally pic.close()

  // ------------------------------------------------------- parity mechanisms
  val pm = w("parity_mechanisms.tsv")
  try {
    cpg.call.nameExact("<operator>.modulo").l.foreach { c =>
      if (argAt(c, 2).flatMap(intValue).contains(2)) {
        val m = methOf(c)
        pm.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"), m.map(_.id).getOrElse(-1L),
          ln(c), c.id, "MODULO_TWO").mkString("\t"))
      }
    }
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
    // a backwards walk over the escape run: an escape-char comparison whose index
    // variable is decremented in the same method
    val decremented = scala.collection.mutable.Map[Long, scala.collection.mutable.Set[String]]()
    def noteDec(mId: Long, nm: String) =
      decremented.getOrElseUpdate(mId, scala.collection.mutable.Set[String]()) += nm
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
        if (decremented.get(mId).exists(_.contains(idxName)))
          pm.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"), mId, ln(c), c.id,
            "ESCAPE_RUN_COUNT_LOOP").mkString("\t"))
      }
    }
  } finally pm.close()

  // --------------------------------------------------------- std::regex sites
  // std::regex's default grammar is ECMAScript; these are tagged as ECMAScript
  // patterns downstream and are never handed to the PCRE adapter.
  val rs = w("regex_sites.tsv")
  try {
    cpg.call.l.foreach { c =>
      val nm = c.name
      if (nm == "std.regex" || nm == "regex" || nm == "basic_regex" || nm.endsWith(".regex")) {
        val pat = args(c).flatMap(a => stringLiteralValue(a).map(v => (a, v))).headOption
        val m = methOf(c)
        pat match {
          case Some((node, body)) =>
            rs.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"),
              m.map(_.id).getOrElse(-1L), ln(c), node.id, "RESOLVED_LITERAL", cl(body), "",
              s"ctor=${c.id}").mkString("\t"))
          case None =>
            rs.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"),
              m.map(_.id).getOrElse(-1L), ln(c), c.id, "UNRESOLVED_DYNAMIC", "", "",
              "no_string_literal_argument").mkString("\t"))
        }
      }
    }
  } finally rs.close()

  val lg = w("language.tsv")
  try lg.println(List("C_CPP", "c2cpg").mkString("\t")) finally lg.close()

  def count(f: String) = scala.io.Source.fromFile(s"$rawDir/$f").getLines().size
  println(s"CPP_ESCAPE_PARITY_FACTS ok: quote_sites=${count("parser_quote_sites.tsv")} " +
    s"index_checks=${count("parser_index_checks.tsv")} " +
    s"parity_mechanisms=${count("parity_mechanisms.tsv")} " +
    s"regex_sites=${count("regex_sites.tsv")}")
}
