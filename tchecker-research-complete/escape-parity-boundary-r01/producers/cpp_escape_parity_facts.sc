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
//   parser_quote_sites.tsv   file, method, method_id, line, cmp_id, other_id, access_kind
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
        val q = as.find(isQuoteLiteral)
        val other = as.find(a => !isQuoteLiteral(a))
        (q, other) match {
          case (Some(_), Some(o)) =>
            val m = methOf(c)
            val mId = m.map(_.id).getOrElse(-1L)
            if (methodsWithAccess.contains(mId)) {
              val direct = indexParts(o).isDefined
              pqs.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"), mId, ln(c), c.id,
                o.id, if (direct) "ACCESSED_CHAR" else "EXTRACTED_CHAR").mkString("\t"))
            }
          case _ => ()
        }
      }
    }
  } finally pqs.close()

  // ---------------------------------------------------- one-position index checks
  val pic = w("parser_index_checks.tsv")
  try {
    val quoteCmps = cpg.call.l.flatMap(c => indexedCharCmp(c, isQuoteLiteral).map(r => (c, r)))
    val escCmps = cpg.call.l.flatMap(c => indexedCharCmp(c, isEscapeLiteral).map(r => (c, r)))
    escCmps.foreach { case (ec, (eBase, eIdx, eOff, eIdxExprId)) =>
      if (eOff != 0) {
        val em = methOf(ec)
        quoteCmps.filter { case (qc, (qBase, qIdx, qOff, _)) =>
          qBase == eBase && qIdx == eIdx && qOff == 0 && methOf(qc).map(_.id) == em.map(_.id)
        }.foreach { case (qc, _) =>
          val check = ec.astParent match {
            case p: nodes.Call if p.name == "<operator>.logicalAnd" ||
                                  p.name == "<operator>.logicalOr" => p.id
            case _ => ec.id
          }
          pic.println(List(fileOf(ec), em.map(_.fullName).getOrElse("?"),
            em.map(_.id).getOrElse(-1L), ln(ec), check, qc.id, ec.id, eIdxExprId, eOff,
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
    cpg.call.nameExact("<operator>.assignment").l.foreach { a =>
      val lhs = argAt(a, 1).collect { case i: nodes.Identifier => i.name }
      val rhsNeg = argAt(a, 2).collect {
        case c: nodes.Call if c.name == "<operator>.logicalNot" =>
          argAt(c, 1).collect { case i: nodes.Identifier => i.name }
      }.flatten
      if (lhs.isDefined && lhs == rhsNeg) {
        val m = methOf(a)
        pm.println(List(fileOf(a), m.map(_.fullName).getOrElse("?"), m.map(_.id).getOrElse(-1L),
          ln(a), a.id, "BOOLEAN_TOGGLE").mkString("\t"))
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
