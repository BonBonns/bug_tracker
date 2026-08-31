import java.io.{File, PrintWriter}
import java.nio.charset.StandardCharsets
import java.util.Base64

// Gate 24: export a small, language-neutral fact set from a REAL Joern CPG.
// Strings are base64-encoded so tabs/newlines in source code cannot corrupt TSV.

def b64(s: String): String = Base64.getEncoder.encodeToString(Option(s).getOrElse("").getBytes(StandardCharsets.UTF_8))
def optInt(v: Option[Int]): String = v.map(_.toString).getOrElse("")
def ids(xs: Iterable[Long]): String = xs.mkString(",")
def ensureDir(p: String): Unit = new File(p).mkdirs()

def writer(path: String): PrintWriter = new PrintWriter(new File(path), "UTF-8")

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile)
  ensureDir(outDir)

  val meta = writer(s"$outDir/meta.tsv")
  try {
    cpg.metaData.l.foreach { m =>
      meta.println(Seq(b64(m.language), b64(m.version), b64(m.root)).mkString("\t"))
    }
  } finally meta.close()

  val methods = writer(s"$outDir/methods.tsv")
  try {
    cpg.method.l.foreach { m =>
      methods.println(Seq(
        m.id.toString,
        b64(m.name), b64(m.fullName), b64(m.signature), b64(m.filename),
        optInt(m.lineNumber), optInt(m.lineNumberEnd),
        b64(m.astParentType), b64(m.astParentFullName),
        m.isExternal.toString
      ).mkString("\t"))
    }
  } finally methods.close()

  val params = writer(s"$outDir/parameters.tsv")
  try {
    cpg.method.l.foreach { m =>
      m.parameter.l.foreach { p =>
        params.println(Seq(
          p.id.toString, m.id.toString, p.index.toString,
          b64(p.name), b64(p.code), b64(p.typeFullName), optInt(p.lineNumber)
        ).mkString("\t"))
      }
    }
  } finally params.close()

  val calls = writer(s"$outDir/calls.tsv")
  try {
    cpg.method.l.foreach { owner =>
      owner.call.l.foreach { c =>
        val calleeIds = c.callee.id.l.map(_.toLong)
        calls.println(Seq(
          c.id.toString, owner.id.toString,
          b64(c.name), b64(c.methodFullName), b64(c.dispatchType),
          b64(c.typeFullName), b64(c.code), b64(owner.filename), optInt(c.lineNumber),
          ids(calleeIds)
        ).mkString("\t"))
      }
    }
  } finally calls.close()

  val args = writer(s"$outDir/arguments.tsv")
  try {
    cpg.call.l.foreach { c =>
      c.argument.l.foreach { a =>
        val nm = a match {
          case x: io.shiftleft.codepropertygraph.generated.nodes.Identifier => x.name
          case _ => ""
        }
        val tfn = a match {
          case x: io.shiftleft.codepropertygraph.generated.nodes.Identifier => x.typeFullName
          case x: io.shiftleft.codepropertygraph.generated.nodes.Call => x.typeFullName
          case x: io.shiftleft.codepropertygraph.generated.nodes.Literal => x.typeFullName
          case x: io.shiftleft.codepropertygraph.generated.nodes.MethodRef => x.typeFullName
          case x: io.shiftleft.codepropertygraph.generated.nodes.TypeRef => x.typeFullName
          case _ => ""
        }
        args.println(Seq(
          a.id.toString, c.id.toString, a.argumentIndex.toString,
          b64(a.label), b64(a.code), b64(nm), b64(tfn), optInt(a.lineNumber)
        ).mkString("\t"))
      }
    }
  } finally args.close()

  val returns = writer(s"$outDir/returns.tsv")
  try {
    cpg.method.l.foreach { owner =>
      owner.ast.isReturn.l.foreach { r =>
        val returned = r.astChildren.id.l.map(_.toLong)
        returns.println(Seq(
          r.id.toString, owner.id.toString, b64(r.code), optInt(r.lineNumber), ids(returned)
        ).mkString("\t"))
      }
    }
  } finally returns.close()

  val identifiers = writer(s"$outDir/identifiers.tsv")
  try {
    cpg.method.l.foreach { owner =>
      owner.ast.isIdentifier.l.foreach { i =>
        val refs = i.refsTo.id.l.map(_.toLong)
        identifiers.println(Seq(
          i.id.toString, owner.id.toString,
          b64(i.name), b64(i.code), b64(i.typeFullName), optInt(i.lineNumber), ids(refs)
        ).mkString("\t"))
      }
    }
  } finally identifiers.close()

  // CROSSLANG-LINK-FIX01H: real LOCAL declarations, INCLUDING Joern's own real
  // closure-binding evidence (`closureBindingId`), for the cross-function
  // "immutable captured const" proof in link_napi_facts.py -- confirmed real via direct
  // Joern-REPL query on a dedicated closure fixture: a nested function that reads an
  // outer `const`/`let`/`var` gets its OWN LOCAL (owned by the NESTED function itself,
  // not the outer one) whose `closureBindingId` is `Some("<outer-scope-file-qualified-
  // full-name>:<captured-var-name>")`, and every real IDENTIFIER use of that name INSIDE
  // the nested function `refsTo` THIS inner closure-binding LOCAL, not the outer LOCAL
  // directly -- i.e. Joern itself already proves the capture structurally; this export
  // just surfaces that fact rather than the Python side re-deriving it heuristically
  // from lexical-ancestry name lookup alone (which is NOT the same claim -- see
  // CHARACTERIZATION.md). `locals.tsv` was previously never exported for the JS/TS side
  // at all (`normalize_joern_facts.py`'s own doc hardcoded `"locals":[]`).
  val locals = writer(s"$outDir/locals.tsv")
  try {
    cpg.method.l.foreach { m =>
      m.local.l.foreach { l =>
        locals.println(Seq(
          l.id.toString, m.id.toString, b64(l.name), b64(l.closureBindingId.getOrElse(""))
        ).mkString("\t"))
      }
    }
  } finally locals.close()

  // CROSSLANG-LINK-FIX01G: real CFG edges, for downstream reaching-definition/dominance
  // proof in link_napi_facts.py -- mirrors the C/C++ side's own export_c_cpp_facts_v03.sc
  // `cfg_edges.tsv` exactly (owner method id, from node id, to node id), confirmed real
  // and populated by direct Joern-REPL query before adding this (jssrc2cpg DOES build
  // real CFG structure; the exporter simply never surfaced it before this fix). Joern's
  // DDG is deliberately NOT consumed here either, same discipline as the C/C++ side.
  //
  // Two boundary hops are added EXPLICITLY, found missing by direct Joern-REPL query
  // (confirmed real, not a guess): `method.cfgNode` -- the set this loop walks --
  // excludes BOTH the Method node itself and its own MethodReturn node (both are real
  // CFG participants, confirmed via `inE("CFG")`/`outE("CFG")`, just not members of
  // `cfgNode`). Concretely: `RETURN.cfgNext` (successor) returns EMPTY even though a
  // real raw CFG edge into MethodReturn exists (`methodReturn.inE("CFG").size == 1`,
  // `methodReturn.cfgIn` correctly returns the real predecessor) -- an intentional,
  // direction-asymmetric filter in Joern's own semantic CFG steps, not a bug in this
  // exporter. Without these two hops, `method_cfg_endpoints.tsv`'s own entry/exit ids
  // below would be real but UNREACHABLE from inside the walked edge set, silently
  // breaking every dominance computation downstream (caught by re-deriving a real
  // adversarial fixture's own facts and finding entry/exit disconnected from the rest
  // of the graph, not assumed).
  val cfgw = writer(s"$outDir/cfg_edges.tsv")
  try {
    cpg.method.isExternal(false).l.foreach { m =>
      m.cfgNode.l.foreach { n =>
        n.cfgNext.l.foreach { x => cfgw.println(Seq(m.id, n.id, x.id).mkString("\t")) }
      }
      m.start.cfgNext.l.foreach { first => cfgw.println(Seq(m.id, m.id, first.id).mkString("\t")) }
      m.methodReturn.cfgIn.l.foreach { last => cfgw.println(Seq(m.id, last.id, m.methodReturn.id).mkString("\t")) }
    }
  } finally cfgw.close()

  // CROSSLANG-LINK-FIX01G addendum: real ids of every CALL nested (at any depth) inside
  // a `try` block. Confirmed real and NECESSARY via direct Joern-REPL testing on a
  // dedicated try/catch-only adversarial fixture: jssrc2cpg's own CFG does NOT model an
  // implicit exceptional edge from an arbitrary statement into its `catch` handler
  // (only a real, explicit `throw` statement would create one, and this fixture has
  // none) -- so a `require(...)` assignment positioned inside a `try` block with an
  // EMPTY (or any) `catch` can pass CFG-dominance-of-exit even though, at real runtime,
  // an exception during `require(...)` would leave the assignment's target unset. CFG
  // dominance alone is therefore NOT SOUND for a try-nested assignment; this fact lets
  // `link_napi_facts.py` apply an explicit, disclosed, conservative override for
  // exactly this case, rather than trusting a CFG that cannot represent it.
  val tryw = writer(s"$outDir/try_nested_calls.tsv")
  try {
    cpg.controlStructure.controlStructureType("TRY").ast.isCall.id.l.foreach { id => tryw.println(id.toString) }
  } finally tryw.close()

  // Each real (non-external) method's own CFG entry/exit node ids -- the Method node
  // itself is Joern's own real CFG entry convention; MethodReturn is the real, single
  // normal-exit convention (confirmed: both participate in the same `cfgNode`/`cfgNext`
  // edges walked above, not a separate/parallel graph). Lets the Python side compute
  // real dominance-of-exit without having to rediscover this convention itself.
  val cfgEndpoints = writer(s"$outDir/method_cfg_endpoints.tsv")
  try {
    cpg.method.isExternal(false).l.foreach { m =>
      cfgEndpoints.println(Seq(m.id.toString, m.id.toString, m.methodReturn.id.toString).mkString("\t"))
    }
  } finally cfgEndpoints.close()
}
