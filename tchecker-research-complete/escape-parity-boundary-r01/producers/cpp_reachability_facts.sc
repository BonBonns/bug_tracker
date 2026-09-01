// ESCAPE-PARITY-BOUNDARY -- C/C++ delayed-source -> transform -> consumer reachability.
//
// Runs ALONGSIDE the frozen parser-layer producer and emits only the chain facts. The
// parser layer decides whether a quote-boundary rule can establish escape-run parity;
// this layer decides whether such a parser sits on a proven second-order path:
//
//   stored file / archive / dump / database row
//        -> the quoted-value parser
//        -> decode / replace / re-encode
//        -> a structured-data interpreter or database import routine
//
// ANCHORING. In C/C++ the parser is almost always a hand-written scanning FUNCTION, not
// a library replace call, so the chain is anchored on the parser METHOD: a delayed source
// must reach a call to that method, and that call's result must reach a consumer. All
// edges are real dataflow computed by the engine, never adjacency in the file.
//
// NAME DISCIPLINE. C has no import statement, so an API is identified by its callee
// identity AND by the requirement that the callee is EXTERNAL to the analysed source.
// If the analysed code also defines a function of the same name, the call is ambiguous
// and is recorded as an abstention rather than resolved to the library API.
//
// EXECUTION TIMING (sleep/alarm/timer registration) is recorded as EVIDENCE ONLY. It is
// never a guard and never changes a verdict.
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

  val SRC_FILE = Set("fopen", "fread", "fgets", "read", "pread", "getline", "fscanf",
    "mmap", "open", "readsome")
  val SRC_ARCHIVE = Set("zip_fread", "unzReadCurrentFile", "archive_read_data", "gzread",
    "BZ2_bzRead")
  val SRC_DB = Set("sqlite3_column_text", "sqlite3_column_blob", "mysql_fetch_row",
    "PQgetvalue", "OCIStmtFetch")
  val DECODE = Set("base64_decode", "EVP_DecodeBlock", "uncompress", "inflate",
    "b64_decode", "unescape")
  val ENCODE = Set("base64_encode", "EVP_EncodeBlock", "compress", "deflate", "b64_encode")
  val REPLACE = Set("regex_replace", "std.regex_replace")
  val CONSUMER_DB = Set("sqlite3_exec", "sqlite3_prepare", "sqlite3_prepare_v2",
    "mysql_query", "mysql_real_query", "PQexec", "PQexecParams", "OCIStmtExecute")
  val CONSUMER_STRUCT = Set("json_tokener_parse", "cJSON_Parse", "yaml_parser_load",
    "xmlReadMemory", "xmlParseMemory")
  val LOGGING = Set("printf", "fprintf", "puts", "fputs", "syslog", "perror", "vfprintf")
  val TIMING = Set("sleep", "usleep", "nanosleep", "alarm", "setitimer", "timer_create")

  val locallyDefined = cpg.method.isExternal(false).name.toSet
  def resolutionFor(name: String): String =
    if (locallyDefined.contains(name)) "AMBIGUOUS_LOCAL_DEFINITION" else "RESOLVED_EXTERNAL"

  val ds = w("delayed_sources.tsv")
  val srcNodes = scala.collection.mutable.ListBuffer[nodes.Expression]()
  try cpg.call.l.foreach { c =>
    val n = c.name
    val kind = if (SRC_FILE.contains(n)) "STORED_FILE_READ"
      else if (SRC_ARCHIVE.contains(n)) "ARCHIVE_READ"
      else if (SRC_DB.contains(n)) "DATABASE_ROW_READ" else ""
    if (kind.nonEmpty) {
      val res = resolutionFor(n); val m = methOf(c)
      ds.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"), ln(c), c.id, n, res, kind).mkString("\t"))
      if (res == "RESOLVED_EXTERNAL") srcNodes += c
    }
  } finally ds.close()

  val tc = w("transform_calls.tsv")
  val encNodes = scala.collection.mutable.ListBuffer[nodes.Expression]()
  try cpg.call.l.foreach { c =>
    val n = c.name
    val fam = if (DECODE.contains(n)) "DECODE" else if (ENCODE.contains(n)) "ENCODE"
      else if (REPLACE.contains(n)) "REPLACE" else ""
    if (fam.nonEmpty) {
      val res = resolutionFor(n); val m = methOf(c)
      tc.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"), ln(c), c.id, fam, n, res).mkString("\t"))
      if (fam == "ENCODE") encNodes += c
    }
  } finally tc.close()

  val cs = w("consumers.tsv")
  val conNodes = scala.collection.mutable.ListBuffer[nodes.Expression]()
  val logNodes = scala.collection.mutable.ListBuffer[nodes.Expression]()
  try cpg.call.l.foreach { c =>
    val n = c.name
    val kind = if (CONSUMER_DB.contains(n)) "DATABASE_IMPORT"
      else if (CONSUMER_STRUCT.contains(n)) "STRUCTURED_DATA_INTERPRETER"
      else if (LOGGING.contains(n)) "LOGGING_ONLY" else ""
    if (kind.nonEmpty) {
      val res = resolutionFor(n); val m = methOf(c)
      cs.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"), ln(c), c.id, n, kind, res).mkString("\t"))
      if (res == "RESOLVED_EXTERNAL") { if (kind == "LOGGING_ONLY") logNodes += c else conNodes += c }
    }
  } finally cs.close()

  val wantIds = parserMethodIds.split(",").map(_.trim).filter(_.nonEmpty).map(_.toLong).toSet
  val pa = w("parser_anchors.tsv")
  val parserCalls = scala.collection.mutable.ListBuffer[nodes.Expression]()
  try {
    // c2cpg gives a call site the signature `name:ANY(ANY)` while the definition carries
    // a resolved signature, so callIn is empty for ordinary C/C++ functions. Link a call
    // to a parser definition by NAME WITHIN THE SAME FILE, and record the resolution
    // explicitly: if the name is defined more than once in that file, or the call site
    // could match definitions in several files, the linkage is ambiguous and is recorded
    // as an abstention rather than guessed.
    val parsers = cpg.method.isExternal(false).l
      .filter(m => wantIds.isEmpty || wantIds.contains(m.id))
    val byName = cpg.method.isExternal(false).l.groupBy(_.name)
    parsers.foreach { m =>
      val sameFileDefs = byName.getOrElse(m.name, Nil).filter(_.filename == m.filename)
      cpg.call.nameExact(m.name).l.foreach { c =>
        val cf = methOf(c).map(_.filename).getOrElse("?")
        if (cf == m.filename) {
          val res = if (sameFileDefs.size == 1) "RESOLVED_SAME_FILE"
                    else "AMBIGUOUS_PARSER_LINKAGE"
          pa.println(List(m.filename, m.fullName, m.id, "PARSER_METHOD", c.id, ln(c), res).mkString("\t"))
          if (res == "RESOLVED_SAME_FILE") parserCalls += c
        }
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
    val srcs = srcNodes.toList; val pcs = parserCalls.toList
    edges(srcs, pcs, "DELAYED_SOURCE2PARSER")
    edges(pcs, encNodes.toList, "PARSER2ENCODE")
    edges(pcs, conNodes.toList, "PARSER2CONSUMER")
    edges(encNodes.toList, conNodes.toList, "ENCODE2CONSUMER")
    edges(pcs, logNodes.toList, "PARSER2LOGGING")
    edges(srcs, conNodes.toList, "DELAYED_SOURCE2CONSUMER")
  } finally ce.close()

  val et = w("execution_timing.tsv")
  try cpg.call.l.foreach { c =>
    if (TIMING.contains(c.name)) {
      val m = methOf(c)
      et.println(List(fileOf(c), m.map(_.fullName).getOrElse("?"), ln(c), c.id,
        "SCHEDULED_OR_DEFERRED").mkString("\t"))
    }
  } finally et.close()

  def cnt(f: String) = scala.io.Source.fromFile(s"$rawDir/$f").getLines().size
  println(s"CPP_REACHABILITY_FACTS ok: delayed_sources=${cnt("delayed_sources.tsv")} " +
    s"transforms=${cnt("transform_calls.tsv")} consumers=${cnt("consumers.tsv")} " +
    s"parser_anchors=${cnt("parser_anchors.tsv")} chain_edges=${cnt("chain_edges.tsv")} " +
    s"timing=${cnt("execution_timing.tsv")}")
}
