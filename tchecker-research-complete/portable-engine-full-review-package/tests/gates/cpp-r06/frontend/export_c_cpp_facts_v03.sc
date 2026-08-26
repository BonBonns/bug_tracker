import java.io.{File, PrintWriter}
import java.nio.charset.StandardCharsets
import java.util.Base64

// CPP-R09/R10 frontend exporter.
// Goal: emit the SAME raw fact families consumed by Fable's portable-program-facts/0.3
// normalizer/loader boundary. C/C++ interpretation remains here/upstream, never in Java.

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

  val identifiers = writer(s"$outDir/identifiers.tsv")
  try cpg.method.l.foreach { owner => owner.ast.isIdentifier.l.foreach { i =>
    identifiers.println(Seq(i.id.toString,owner.id.toString,b64(i.name),b64(i.code),b64(i.typeFullName),optInt(i.lineNumber),ids(i.refsTo.id.l.map(_.toLong))).mkString("\t"))
  }} finally identifiers.close()

  // CFG edges (for frontend-side reaching-definition analysis). Joern's own DDG is
  // deliberately NOT consumed as fact — a separate probe exports it as a
  // diagnostic oracle only, so engine guarantees stay attributable to our logic.
  val cfgw = writer(s"$outDir/cfg_edges.tsv")
  try {
    cpg.method.isExternal(false).l.foreach { m =>
      m.cfgNode.l.foreach { n =>
        n.cfgNext.l.foreach { x => cfgw.println(Seq(m.id, n.id, x.id).mkString("\t")) }
      }
    }
  } finally cfgw.close()
}
