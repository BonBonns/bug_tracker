import java.io.{File, PrintWriter}
import java.nio.charset.StandardCharsets
import java.util.Base64

// JS-STATE-R01: pure observation queries. This script asserts nothing and
// implements no detector logic -- it only dumps what the real Joern CPG
// already contains for facts JS-STATE-R01 needs to characterize, using
// standard CPG traversals (methodReturn types, <operator>.instanceOf calls,
// CONTROL_STRUCTURE conditions, and REF-based dataflow from a guard condition
// back to the value that was checked).

def b64(s: String): String = Base64.getEncoder.encodeToString(Option(s).getOrElse("").getBytes(StandardCharsets.UTF_8))
def writer(path: String): PrintWriter = new PrintWriter(new File(path), "UTF-8")

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile)
  new File(outDir).mkdirs()

  // 1) Method return type facts, keyed by enclosing method name+full_name.
  val retTypes = writer(s"$outDir/method_return_types.tsv")
  try cpg.method.l.foreach { m =>
    retTypes.println(Seq(m.id.toString, b64(m.name), b64(m.fullName), b64(m.methodReturn.typeFullName)).mkString("\t"))
  } finally retTypes.close()

  // 2) instanceof checks: how jssrc2cpg represents `x instanceof Error`.
  val instanceOfCalls = writer(s"$outDir/instanceof_calls.tsv")
  try cpg.call.l.filter(_.name.contains("instanceOf")).foreach { c =>
    val args = c.argument.l.sortBy(_.argumentIndex)
    val argDump = args.map(a => s"${a.argumentIndex}:${a.label}:${b64(a.code)}").mkString("|")
    instanceOfCalls.println(Seq(c.id.toString, c.method.id.toString, b64(c.name), b64(c.methodFullName), b64(c.code), argDump).mkString("\t"))
  } finally instanceOfCalls.close()

  // 3) All CONTROL_STRUCTURE (if/etc.) nodes with their condition subtree code,
  //    and the enclosing method, so we can see what each guard actually tests.
  val controlStructs = writer(s"$outDir/control_structures.tsv")
  try cpg.controlStructure.l.foreach { cs =>
    val cond = cs.condition.code.l.mkString(" && ")
    controlStructs.println(Seq(cs.id.toString, cs.method.id.toString, b64(cs.controlStructureType), b64(cond), cs.lineNumber.map(_.toString).getOrElse("")).mkString("\t"))
  } finally controlStructs.close()

  // 4) Coercion-shaped calls: Number/String/Boolean/parseInt calls and unary
  //    operators, with callee identity (external vs resolved) and argument.
  val coercions = writer(s"$outDir/coercion_calls.tsv")
  try cpg.call.l.filter(c => Set("Number","String","Boolean","parseInt","parseFloat","<operator>.plus","<operator>.or","<operator>.cast").contains(c.name)).foreach { c =>
    val args = c.argument.l.sortBy(_.argumentIndex)
    val argDump = args.map(a => s"${a.argumentIndex}:${b64(a.code)}").mkString("|")
    coercions.println(Seq(c.id.toString, c.method.id.toString, b64(c.name), b64(c.methodFullName), b64(c.dispatchType), b64(c.code), argDump).mkString("\t"))
  } finally coercions.close()

  // 5) REACHING DEF / dataflow: for each instanceof/comparison call inside a
  //    control-structure condition, does the checked identifier's REF/reaching
  //    definition trace to the raw callee-call result (create(...)) directly,
  //    or through an intermediate coercion call? Use identifier.refsTo plus a
  //    simple "reachableBy" data-flow query (joern's built-in dataflow engine,
  //    already computed by ReachingDefPass) to see what the checked value's
  //    provenance is, without asserting any verdict.
  val guardSubjectFlow = writer(s"$outDir/guard_subject_flow.tsv")
  try {
    val checkedIdentifiers = cpg.controlStructure.condition.isIdentifier.l ++
      cpg.call.filter(_.name.contains("instanceOf")).argument(1).isIdentifier.l ++
      cpg.call.nameExact("<operator>.equals","<operator>.notEquals").argument(1).isIdentifier.l ++
      cpg.controlStructure.condition.astChildren.isIdentifier.l
    checkedIdentifiers.distinct.foreach { ident =>
      val m = ident.method
      // Trace this identifier backward through reaching-definitions to any CALL
      // it was assigned from (the frontend-computed dataflow, not a new engine).
      val defs = ident.reachingDefIn.l
      val callSources = ident.inCall.l // enclosing call using this identifier as arg
      guardSubjectFlow.println(Seq(
        ident.id.toString, m.id.toString, b64(m.name), b64(ident.name), b64(ident.code),
        ident.lineNumber.map(_.toString).getOrElse(""),
        b64(defs.map(_.code).mkString("|")),
        b64(callSources.map(c => s"${c.name}(${c.code})").mkString("|"))
      ).mkString("\t"))
    }
  } finally guardSubjectFlow.close()

  // 6) Assignment chain per local: name -> the CALL/expression it was assigned
  //    from, so we can manually reconstruct "id2 = Number(r2)" style chains.
  val assigns = writer(s"$outDir/assignments.tsv")
  try cpg.call.nameExact("<operator>.assignment").l.foreach { c =>
    val lhs = c.argument(1)
    val rhs = c.argument(2)
    assigns.println(Seq(c.id.toString, c.method.id.toString, b64(c.method.name), b64(lhs.code), b64(rhs.label), b64(rhs.code)).mkString("\t"))
  } finally assigns.close()
}
