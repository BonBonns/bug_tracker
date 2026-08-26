import java.io.{File, PrintWriter}
import java.nio.charset.StandardCharsets
import java.util.Base64

// Gate 24-TS: inspect TypeScript facts produced by the REAL Joern jssrc2cpg frontend.
// Only standard CPG fields/traversals are used here so this is a characterization
// of Joern's output rather than another language adapter.

def b64(s: String): String = Base64.getEncoder.encodeToString(Option(s).getOrElse("").getBytes(StandardCharsets.UTF_8))
def optInt(v: Option[Int]): String = v.map(_.toString).getOrElse("")
def ids(xs: Iterable[Long]): String = xs.mkString(",")
def strs(xs: Iterable[String]): String = xs.map(b64).mkString(",")
def ensureDir(p: String): Unit = new File(p).mkdirs()
def writer(path: String): PrintWriter = new PrintWriter(new File(path), "UTF-8")

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile)
  ensureDir(outDir)

  val meta = writer(s"$outDir/meta.tsv")
  try cpg.metaData.l.foreach { m => meta.println(Seq(b64(m.language), b64(m.version), b64(m.root)).mkString("\t")) }
  finally meta.close()

  val types = writer(s"$outDir/type_decls.tsv")
  try cpg.typeDecl.l.foreach { t =>
    types.println(Seq(t.id.toString,b64(t.name),b64(t.fullName),b64(t.filename),optInt(t.lineNumber),t.isExternal.toString,strs(t.inheritsFromTypeFullName)).mkString("\t"))
  } finally types.close()

  val members = writer(s"$outDir/members.tsv")
  try cpg.typeDecl.l.foreach { t => t.member.l.foreach { m =>
    members.println(Seq(m.id.toString,t.id.toString,b64(m.name),b64(m.code),b64(m.typeFullName),optInt(m.lineNumber)).mkString("\t"))
  }} finally members.close()

  val methods = writer(s"$outDir/methods.tsv")
  try cpg.method.l.foreach { m =>
    methods.println(Seq(m.id.toString,b64(m.name),b64(m.fullName),b64(m.signature),b64(m.filename),optInt(m.lineNumber),optInt(m.lineNumberEnd),b64(m.astParentType),b64(m.astParentFullName),m.isExternal.toString).mkString("\t"))
  } finally methods.close()

  val params = writer(s"$outDir/parameters.tsv")
  try cpg.method.l.foreach { m => m.parameter.l.foreach { p =>
    params.println(Seq(p.id.toString,m.id.toString,p.index.toString,b64(p.name),b64(p.code),b64(p.typeFullName),optInt(p.lineNumber)).mkString("\t"))
  }} finally params.close()

  val rets = writer(s"$outDir/method_returns.tsv")
  try cpg.method.l.foreach { m => val r = m.methodReturn
    rets.println(Seq(r.id.toString,m.id.toString,b64(r.code),b64(r.typeFullName),optInt(r.lineNumber)).mkString("\t"))
  } finally rets.close()

  val locals = writer(s"$outDir/locals.tsv")
  try cpg.method.l.foreach { m => m.local.l.foreach { l =>
    locals.println(Seq(l.id.toString,m.id.toString,b64(l.name),b64(l.code),b64(l.typeFullName),optInt(l.lineNumber)).mkString("\t"))
  }} finally locals.close()

  val calls = writer(s"$outDir/calls.tsv")
  try cpg.method.l.foreach { owner => owner.call.l.foreach { c =>
    val calleeIds = c.callee.id.l.map(_.toLong)
    val calleeNames = c.callee.fullName.l
    calls.println(Seq(c.id.toString,owner.id.toString,b64(c.name),b64(c.methodFullName),b64(c.dispatchType),b64(c.typeFullName),b64(c.code),b64(owner.filename),optInt(c.lineNumber),ids(calleeIds),strs(calleeNames)).mkString("\t"))
  }} finally calls.close()

  val args = writer(s"$outDir/arguments.tsv")
  try cpg.call.l.foreach { c => c.argument.l.foreach { a =>
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
    args.println(Seq(a.id.toString,c.id.toString,a.argumentIndex.toString,b64(a.label),b64(a.code),b64(nm),b64(tfn),optInt(a.lineNumber)).mkString("\t"))
  }} finally args.close()

  val returns = writer(s"$outDir/returns.tsv")
  try cpg.method.l.foreach { owner =>
    owner.ast.isReturn.l.foreach { r =>
      val returned = r.astChildren.id.l.map(_.toLong)
      returns.println(Seq(r.id.toString, owner.id.toString, b64(r.code), optInt(r.lineNumber), ids(returned)).mkString("\t"))
    }
  } finally returns.close()

  val lits = writer(s"$outDir/literals.tsv")
  try cpg.literal.l.foreach { l =>
    lits.println(Seq(l.id.toString, b64(l.code), b64(l.typeFullName), optInt(l.lineNumber)).mkString("\t"))
  } finally lits.close()

  // Closure capture linkage: inner materialized LOCAL --closureBindingId--> CLOSURE_BINDING --REF--> outer LOCAL/PARAM
  val cbs = writer(s"$outDir/closure_bindings.tsv")
  try {
    cpg.all.collectAll[io.shiftleft.codepropertygraph.generated.nodes.ClosureBinding].foreach { cb =>
      val refs = cb._refOut.map(_.id).l.mkString(",")
      // NOTE (Gate 24-TS real-frontend run): ClosureBinding.closureOriginalName was
      // removed from the installed Joern CPG schema (codepropertygraph 1.7.70) --
      // only closureBindingId and evaluationStrategy remain on this node type.
      // The original-name column is kept as an empty placeholder to preserve the
      // downstream TSV column layout; capture_facts.py never reads this column
      // (it only reads closureBindingId at index 1 and refs at index 3), so this
      // is a safe compatibility fix, not a semantic change.
      cbs.println(Seq(cb.id.toString, b64(cb.closureBindingId.getOrElse("")), b64(""), refs).mkString("\t"))
    }
  } finally cbs.close()

  val lcb = writer(s"$outDir/local_closure.tsv")
  try {
    cpg.local.l.foreach { l =>
      l.closureBindingId.foreach { cbid =>
        lcb.println(Seq(l.id.toString, b64(cbid)).mkString("\t"))
      }
    }
  } finally lcb.close()

  // Block membership: enclosing BLOCK node ids per call (innermost-first), for
  // frontend composition of object-literal/spread lowerings (tmp-collapse).
  val cbl = writer(s"$outDir/call_blocks.tsv")
  try cpg.call.l.foreach { c =>
    val blocks = c.inAst.collectAll[io.shiftleft.codepropertygraph.generated.nodes.Block].id.l.map(_.toLong)
    if (blocks.nonEmpty) cbl.println(Seq(c.id.toString, ids(blocks)).mkString("\t"))
  } finally cbl.close()

  // Union-recovery experiment: dynamic type hints on parameters and identifiers.
  // jssrc2cpg collapses union DECLARED types to ANY / first-member ctor (measured on
  // gate4); dynamicTypeHintFullName may retain the members. Export and measure.
  val hints = writer(s"$outDir/type_hints.tsv")
  try {
    cpg.parameter.l.foreach { pr =>
      val h = pr.dynamicTypeHintFullName.l
      if (h.nonEmpty) hints.println(Seq("PARAM", pr.id.toString, b64(h.mkString("|||"))).mkString("\t"))
    }
    cpg.identifier.l.foreach { i =>
      val h = i.dynamicTypeHintFullName.l
      if (h.nonEmpty) hints.println(Seq("IDENT", i.id.toString, b64(h.mkString("|||"))).mkString("\t"))
    }
  } finally hints.close()

  val identifiers = writer(s"$outDir/identifiers.tsv")
  try cpg.method.l.foreach { owner => owner.ast.isIdentifier.l.foreach { i =>
    identifiers.println(Seq(i.id.toString,owner.id.toString,b64(i.name),b64(i.code),b64(i.typeFullName),optInt(i.lineNumber),ids(i.refsTo.id.l.map(_.toLong))).mkString("\t"))
  }} finally identifiers.close()

  // JSTS-R08: METHOD REFERENCES. A lambda used as a VALUE was previously exported
  // as an untyped node, so the normalizer emitted value_ref{kind: UNKNOWN,
  // code: "<lambda>N"} — Joern had the identity and the pipeline threw it away.
  val mrw = writer(s"$outDir/method_refs.tsv")
  try cpg.methodRef.l.foreach { m =>
    mrw.println(Seq(m.id.toString, b64(m.methodFullName), b64(m.code)).mkString("\t"))
  } finally mrw.close()

  // JS-STATE-R02: CONTROL_STRUCTURE (if/while/etc.) export, promoted from the
  // JS-STATE-R01 characterization query. Guard/branch reasoning (e.g. "does this
  // check target the original callee result or a transformed derivative?") needs
  // the condition subtree, which nothing upstream of this gate ever exported.
  val controlStructs = writer(s"$outDir/control_structures.tsv")
  try cpg.controlStructure.l.foreach { cs =>
    val condId = cs.condition.id.headOption.map(_.toString).getOrElse("")
    controlStructs.println(Seq(cs.id.toString, cs.method.id.toString, b64(cs.controlStructureType), condId, b64(cs.condition.code.headOption.getOrElse("")), optInt(cs.lineNumber)).mkString("\t"))
  } finally controlStructs.close()

  // JS-STATE-R02: every identifier inside a condition's FULL subtree (all AST
  // descendants, not just direct children -- JS-STATE-R01 found that a shallow
  // walk silently misses checks like `!r.ok`, which nests the checked identifier
  // two levels down through <operator>.logicalNot -> <operator>.fieldAccess),
  // resolved to its LOCAL/PARAMETER via REF. This is the name-independent
  // mechanism JS-STATE-R01 used to distinguish "guard checks the original
  // value" from "guard checks a transformed value" -- promoted here so it is a
  // real, reusable export instead of a one-off characterization query.
  val condIdents = writer(s"$outDir/condition_identifiers.tsv")
  try cpg.controlStructure.l.foreach { cs =>
    cs.condition.headOption.foreach { cond =>
      cond.ast.isIdentifier.l.foreach { ident =>
        val refLocalIds = ident.refOut.id.l.map(_.toLong)
        if (refLocalIds.nonEmpty) {
          condIdents.println(Seq(cs.id.toString, cond.id.toString, ident.id.toString, ids(refLocalIds)).mkString("\t"))
        }
      }
    }
  } finally condIdents.close()

  // JS-STATE-R04: which nodes are inside the guard's "condition-true" branch
  // (e.g. the `if (cond) { ... }` body). Needed to tell "this call only runs
  // when the guard fired" apart from "this call runs on the continue path" --
  // same-function argument matching alone (JS-STATE-R03) cannot make that
  // distinction and can misclassify a call that is lexically/structurally
  // inside the guard's own true-branch as reachable on the safe path.
  val guardThen = writer(s"$outDir/guard_then_branch_members.tsv")
  try cpg.controlStructure.l.foreach { cs =>
    val thenIds = cs.whenTrue.ast.id.l.map(_.toLong)
    thenIds.foreach { nid => guardThen.println(Seq(cs.id.toString, nid.toString).mkString("\t")) }
  } finally guardThen.close()

  // JS-STATE-R04: every identifier inside the FULL AST subtree of each CALL's
  // arguments (not just bare-identifier arguments), resolved to its
  // LOCAL/PARAMETER via REF. A same-function reachability check that only
  // matches when an argument IS an identifier misses the common case where the
  // argument is a small expression wrapping one (e.g. `f(x as number)`,
  // `f(x!)`, `f(x || y)`) -- exactly the same shallow-walk mistake
  // condition_identifiers.tsv was added to fix for guard conditions, now fixed
  // the same way for call arguments generally.
  val callArgIdents = writer(s"$outDir/call_argument_identifiers.tsv")
  try cpg.call.l.foreach { c =>
    c.argument.l.foreach { a =>
      a.ast.isIdentifier.l.foreach { ident =>
        val refLocalIds = ident.refOut.id.l.map(_.toLong)
        if (refLocalIds.nonEmpty) {
          callArgIdents.println(Seq(c.id.toString, a.id.toString, ident.id.toString, ids(refLocalIds)).mkString("\t"))
        }
      }
    }
  } finally callArgIdents.close()
}
