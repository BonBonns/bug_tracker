// ESCAPE-PARITY-BOUNDARY -- JavaScript delayed-source -> transform -> consumer reachability.
//
// The JavaScript counterpart of cpp_reachability_facts.sc, emitting the SAME fact schema
// so one reducer serves both languages. Runs alongside the frozen parser-layer producer.
//
// ANCHORING. Two parser shapes exist in JS and both are anchored:
//   * a hand-written character scanner  -> anchored on the parser METHOD's call sites
//   * a regex applied via .replace()    -> anchored on the replace call itself
//
// NAME DISCIPLINE. An API is identified through a RESOLVED IMPORT (require/import), never
// through the spelling of a bare identifier. A receiver that never resolves to an import
// is recorded as UNRESOLVED_SOURCE_IDENTITY / UNRESOLVED_CONSUMER_IDENTITY, not guessed.
//
// EXECUTION TIMING is recorded as EVIDENCE ONLY and never changes a verdict.
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, rawDir: String, parserMethodIds: String = "") = {
  importCpg(cpgFile)
  new java.io.File(rawDir).mkdirs()
  def w(n: String) = new java.io.PrintWriter(new java.io.File(s"$rawDir/$n"), "UTF-8")
  def ln(n: nodes.AstNode): Int = n.lineNumber.map(_.toInt).getOrElse(-1)
  def methOf(n: nodes.AstNode): Option[nodes.Method] = {
    var cur: Option[nodes.AstNode] = Some(n); var res: Option[nodes.Method] = None; var g = 0
    while (cur.isDefined && res.isEmpty && g < 500) {
      cur.get match {
        case m: nodes.Method => res = Some(m)
        case o => cur = o._astIn.collectFirst { case a: nodes.AstNode => a }
      }
      g += 1
    }
    res
  }
  def fileOf(n: nodes.AstNode): String = methOf(n).map(_.filename).getOrElse("?")
  def argAt(c: nodes.Call, i: Int): Option[nodes.Expression] = c.argument.l.find(_.argumentIndex == i)
  def stringValue(n: nodes.AstNode): Option[String] = n match {
    case l: nodes.Literal =>
      val c = Option(l.code).getOrElse("")
      if (c.length >= 2 && ((c.head == '"' && c.last == '"') || (c.head == '\'' && c.last == '\'')))
        Some(c.substring(1, c.length - 1)) else None
    case _ => None
  }
  def fieldParts(n: nodes.AstNode): Option[(String, String)] = n match {
    case c: nodes.Call if c.name == "<operator>.fieldAccess" =>
      for {
        b <- argAt(c, 1)
        f <- argAt(c, 2).collect { case fi: nodes.FieldIdentifier => fi.canonicalName }
      } yield (Option(b.code).getOrElse(""), f)
    case _ => None
  }
  def memberCall(c: nodes.Call): Option[(String, String)] =
    c.receiver.headOption.flatMap(fieldParts)

  // module identity from require()/import
  val moduleOfIdent = scala.collection.mutable.Map[String, String]()
  cpg.call.nameExact("<operator>.assignment").l.foreach { a =>
    (argAt(a, 1), argAt(a, 2)) match {
      case (Some(i: nodes.Identifier), Some(r: nodes.Call)) if r.name == "require" =>
        argAt(r, 1).flatMap(stringValue).foreach(m => moduleOfIdent(i.name) = m)
      case _ => ()
    }
  }
  cpg.imports.l.foreach { im =>
    val spec = im.importedEntity.getOrElse("")
    im.importedAs.foreach(as => if (spec.nonEmpty) moduleOfIdent(as) = spec)
  }

  val FS_MODULES = Set("fs", "node:fs", "fs/promises", "node:fs/promises")
  val FS_READ = Set("readFile", "readFileSync", "createReadStream", "read")
  val ARCHIVE_MODULES = Set("yauzl", "unzipper", "adm-zip", "tar", "tar-stream",
    "node-stream-zip", "jszip", "archiver", "zlib", "node:zlib")
  val DB_MODULES = Set("mysql", "mysql2", "pg", "sqlite3", "better-sqlite3", "mssql",
    "mariadb", "knex", "sequelize")
  val DB_MEMBERS = Set("query", "execute", "all", "get", "each", "exec", "run")
  val STRUCT_MODULES = Map("yaml" -> Set("parse", "load", "safeLoad"),
    "js-yaml" -> Set("load", "safeLoad", "parse"),
    "querystring" -> Set("parse"), "node:querystring" -> Set("parse"),
    "csv-parse" -> Set("parse"), "php-unserialize" -> Set("unserialize"))
  val LOG_MEMBERS = Set("log", "info", "warn", "error", "debug", "trace")
  val DEC_ENC = Set("base64", "base64url", "hex")
  val DEC_TEXT = Set("utf8", "utf-8", "ascii", "latin1", "binary", "ucs2", "utf16le")

  val ds = w("delayed_sources.tsv")
  val srcNodes = scala.collection.mutable.ListBuffer[nodes.Expression]()
  try cpg.call.l.foreach { c =>
    memberCall(c).foreach { case (baseCode, member) =>
      val baseIdent = baseCode.split("\\.").headOption.getOrElse(baseCode)
      val mod = moduleOfIdent.get(baseIdent)
      val m = methOf(c)
      val isFs = mod.exists(FS_MODULES.contains) && FS_READ.contains(member)
      val isArch = mod.exists(ARCHIVE_MODULES.contains) && !isFs
      val isDb = mod.exists(DB_MODULES.contains) && DB_MEMBERS.contains(member)
      if (isFs || isArch || isDb) {
        val kind = if (isFs) "STORED_FILE_READ" else if (isArch) "ARCHIVE_READ" else "DATABASE_ROW_READ"
        ds.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"), ln(c), c.id,
          s"${mod.get}.$member", "RESOLVED_IMPORT", kind).mkString("\t"))
        srcNodes += c
      } else if (mod.isEmpty && (FS_READ.contains(member) || DB_MEMBERS.contains(member))) {
        ds.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"), ln(c), c.id,
          s"$baseIdent.$member", "UNRESOLVED_SOURCE_IDENTITY", "").mkString("\t"))
      }
    }
  } finally ds.close()

  // regex literal / RegExp sites, so a replace call can be linked back to the exact
  // boundary rule it applies (file-scoped, never by bare name)
  val regexLiteralRe = """^/(.*)/([dgimsuvy]*)$""".r
  val regexSiteIds = scala.collection.mutable.Set[Long]()
  cpg.literal.l.foreach { l =>
    Option(l.code).getOrElse("") match {
      case regexLiteralRe(b, _) if b.nonEmpty => regexSiteIds += l.id
      case _ => ()
    }
  }
  cpg.call.nameExact("<operator>.new").l.foreach { c =>
    if (c.astChildren.l.headOption.collect { case i: nodes.Identifier => i.name }.contains("RegExp"))
      c.astChildren.l.drop(2).headOption.foreach(p => if (stringValue(p).isDefined) regexSiteIds += p.id)
  }
  /** the boundary-rule site a replace call applies, or -1 when it cannot be resolved */
  def replaceRegexSite(c: nodes.Call): Long = argAt(c, 1) match {
    case Some(l: nodes.Literal) if regexSiteIds.contains(l.id) => l.id
    case Some(i: nodes.Identifier) =>
      val here = fileOf(c)
      val defs = cpg.call.nameExact("<operator>.assignment").l.filter { a =>
        fileOf(a) == here &&
        argAt(a, 1).collect { case x: nodes.Identifier => x.name }.contains(i.name)
      }.flatMap(a => argAt(a, 2)).filter(x => regexSiteIds.contains(x.id))
      if (defs.size == 1) defs.head.id else -1L
    case Some(x) if regexSiteIds.contains(x.id) => x.id
    case _ => -1L
  }

  val tc = w("transform_calls.tsv")
  val encNodes = scala.collection.mutable.ListBuffer[nodes.Expression]()
  val replaceNodes = scala.collection.mutable.ListBuffer[nodes.Expression]()
  try cpg.call.l.foreach { c =>
    val m = methOf(c)
    def emit(fam: String, ident: String, res: String) = {
      tc.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"), ln(c), c.id, fam, ident,
        res).mkString("\t"))
      if (fam == "ENCODE") encNodes += c
      if (fam == "REPLACE") replaceNodes += c
    }
    if (c.name == "from" && c.methodFullName == "Buffer.from")
      argAt(c, 2).flatMap(stringValue).map(_.toLowerCase) match {
        case Some(e) if DEC_ENC.contains(e) => emit("DECODE", s"Buffer.from:$e", "RESOLVED")
        case Some(e) if DEC_TEXT.contains(e) => emit("ENCODE_INPUT", s"Buffer.from:$e", "RESOLVED")
        case _ => emit("DECODE", "Buffer.from", "UNRESOLVED_ENCODING")
      }
    if (c.name == "toString")
      argAt(c, 1).flatMap(stringValue).map(_.toLowerCase) match {
        case Some(e) if DEC_ENC.contains(e) => emit("ENCODE", s"toString:$e", "RESOLVED")
        case Some(e) if DEC_TEXT.contains(e) => emit("DECODE", s"toString:$e", "RESOLVED")
        case _ => ()
      }
    if (c.name == "atob") emit("DECODE", "atob", "RESOLVED")
    if (c.name == "btoa") emit("ENCODE", "btoa", "RESOLVED")
    if (c.name == "decodeURIComponent" || c.name == "unescape") emit("DECODE", c.name, "RESOLVED")
    if (c.name == "encodeURIComponent") emit("ENCODE", c.name, "RESOLVED")
    if (c.methodFullName == "JSON.stringify") emit("ENCODE", "JSON.stringify", "RESOLVED")
    if (c.name == "replace" || c.name == "replaceAll") {
      val cb = argAt(c, 2)
      val res = cb match {
        case Some(_: nodes.MethodRef) => "RESOLVED"
        case Some(l: nodes.Literal) if stringValue(l).isDefined => "RESOLVED"
        case Some(i: nodes.Identifier) =>
          // an identifier callback resolves when exactly one function of that name is
          // bound in the SAME FILE; otherwise the transformation identity is unknown
          val here = fileOf(c)
          val defs = cpg.call.nameExact("<operator>.assignment").l.filter { a =>
            fileOf(a) == here &&
            argAt(a, 1).collect { case x: nodes.Identifier => x.name }.contains(i.name)
          }.flatMap(a => argAt(a, 2)).collect { case mr: nodes.MethodRef => mr }
          if (defs.size == 1) "RESOLVED"
          else if (defs.isEmpty) "UNRESOLVED_CALLBACK_IDENTITY"
          else "AMBIGUOUS_CALLBACK_IDENTITY"
        case Some(_) => "UNRESOLVED_CALLBACK_IDENTITY"
        case None => "NO_CALLBACK_ARGUMENT"
      }
      emit("REPLACE", c.name, res)
    }
  } finally tc.close()

  val cs = w("consumers.tsv")
  val conNodes = scala.collection.mutable.ListBuffer[nodes.Expression]()
  val logNodes = scala.collection.mutable.ListBuffer[nodes.Expression]()
  try cpg.call.l.foreach { c =>
    val m = methOf(c)
    def emit(ident: String, kind: String, res: String) = {
      cs.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"), ln(c), c.id, ident, kind,
        res).mkString("\t"))
      if (res.startsWith("RESOLVED")) { if (kind == "LOGGING_ONLY") logNodes += c else conNodes += c }
    }
    if (c.methodFullName == "JSON.parse") emit("JSON.parse", "STRUCTURED_DATA_INTERPRETER", "RESOLVED")
    memberCall(c).foreach { case (baseCode, member) =>
      val baseIdent = baseCode.split("\\.").headOption.getOrElse(baseCode)
      val mod = moduleOfIdent.get(baseIdent)
      mod.foreach { mm =>
        STRUCT_MODULES.get(mm).foreach(ms =>
          if (ms.contains(member)) emit(s"$mm.$member", "STRUCTURED_DATA_INTERPRETER", "RESOLVED"))
        if (DB_MODULES.contains(mm) && DB_MEMBERS.contains(member))
          emit(s"$mm.$member", "DATABASE_IMPORT", "RESOLVED")
      }
      if (baseIdent == "console" && LOG_MEMBERS.contains(member))
        emit(s"console.$member", "LOGGING_ONLY", "RESOLVED")
      if (mod.isEmpty && member == "query")
        emit(s"$baseIdent.$member", "DATABASE_IMPORT", "UNRESOLVED_CONSUMER_IDENTITY")
    }
  } finally cs.close()

  // parser anchors: the scanner method's call sites, plus replace calls as their own anchor
  // Anchors are keyed by the boundary-rule SITE, not by the method the rule was declared
  // in: a regex constant is often declared at module scope while the replace call that
  // applies it lives in another function.
  val wantIds = parserMethodIds.split(",").map(_.trim).filter(_.nonEmpty).map(_.toLong).toSet
  val pa = w("parser_anchors.tsv")
  val parserCalls = scala.collection.mutable.ListBuffer[nodes.Expression]()
  try {
    // (a) a regex site is anchored on every replace call that applies it
    replaceNodes.foreach { r =>
      val rc = r.asInstanceOf[nodes.Call]
      val siteId = replaceRegexSite(rc)
      if (siteId >= 0 && (wantIds.isEmpty || wantIds.contains(siteId))) {
        pa.println(List(fileOf(r), methOf(r).map(_.fullName).getOrElse("?"), siteId,
          "REGEX_SITE", r.id, ln(r), "RESOLVED_PATTERN_IDENTITY").mkString("\t"))
        parserCalls += r
      } else if (siteId < 0) {
        pa.println(List(fileOf(r), methOf(r).map(_.fullName).getOrElse("?"), -1L,
          "REGEX_SITE", r.id, ln(r), "UNRESOLVED_PATTERN_IDENTITY").mkString("\t"))
      }
    }
    // (b) a hand-written scanner is anchored on its own call sites
    val byName = cpg.method.isExternal(false).l.groupBy(_.name)
    cpg.method.isExternal(false).l.filter(m => wantIds.isEmpty || wantIds.contains(m.id))
      .foreach { m =>
        val sameFile = byName.getOrElse(m.name, Nil).filter(_.filename == m.filename)
        val direct = m.callIn.l
        val calls = if (direct.nonEmpty) direct
                    else cpg.call.nameExact(m.name).l.filter(c => fileOf(c) == m.filename)
        calls.foreach { c =>
          val res = if (sameFile.size <= 1) "RESOLVED_SAME_FILE" else "AMBIGUOUS_PARSER_LINKAGE"
          pa.println(List(m.filename, m.fullName, m.id, "PARSER_METHOD", c.id, ln(c), res).mkString("\t"))
          if (res == "RESOLVED_SAME_FILE") parserCalls += c
        }
      }
  } finally pa.close()

  val ce = w("chain_edges.tsv")
  try {
    def edges(from: List[nodes.Expression], to: List[nodes.Expression], kind: String): Unit =
      if (from.nonEmpty && to.nonEmpty) to.foreach { t =>
        Iterator(t).reachableByFlows(from.iterator).l.foreach { f =>
          f.elements.headOption.foreach { o =>
            val p = kind.split("2"); ce.println(List(p(0), o.id, p(1), t.id, kind).mkString("\t"))
          }
        }
      }
    val srcs = srcNodes.toList; val pcs = parserCalls.toList.distinctBy(_.id)
    edges(srcs, pcs, "DELAYED_SOURCE2PARSER")
    edges(pcs, encNodes.toList, "PARSER2ENCODE")
    edges(pcs, conNodes.toList, "PARSER2CONSUMER")
    edges(encNodes.toList, conNodes.toList, "ENCODE2CONSUMER")
    edges(pcs, logNodes.toList, "PARSER2LOGGING")
    edges(srcs, conNodes.toList, "DELAYED_SOURCE2CONSUMER")
  } finally ce.close()

  val et = w("execution_timing.tsv")
  try cpg.call.l.foreach { c =>
    val m = methOf(c)
    def emit(k: String) = et.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"), ln(c), c.id, k).mkString("\t"))
    if (c.name == "setInterval") emit("SCHEDULED_INTERVAL")
    if (c.name == "setTimeout") emit("DEFERRED_TIMEOUT")
    memberCall(c).foreach { case (b, member) =>
      val mod = moduleOfIdent.get(b.split("\\.").headOption.getOrElse(b))
      if (mod.exists(x => x == "node-cron" || x == "cron" || x == "node-schedule") && member == "schedule")
        emit("CRON_REGISTRATION")
    }
  } finally et.close()

  def cnt(f: String) = scala.io.Source.fromFile(s"$rawDir/$f").getLines().size
  println(s"JS_REACHABILITY_FACTS ok: delayed_sources=${cnt("delayed_sources.tsv")} " +
    s"transforms=${cnt("transform_calls.tsv")} consumers=${cnt("consumers.tsv")} " +
    s"parser_anchors=${cnt("parser_anchors.tsv")} chain_edges=${cnt("chain_edges.tsv")} " +
    s"timing=${cnt("execution_timing.tsv")}")
}
