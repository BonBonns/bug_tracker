// JS-IDENTITY-GAP — characterization only (no guard change).
// For every user-defined transform call (non-operator, non-builtin, with >=1 argument) in a CPG,
// records the attributes that determine whether the adjudicator's subject_transform could be
// established, and buckets them:
//   A  resolver identifies the transform (definition_resolution ESTABLISHED)      -> no identity gap
//   B  resolver UNKNOWN + a UNIQUE local callee body exists (trace-backed)        -> bridge candidate
//   C  resolver UNKNOWN + MULTIPLE local bodies share the name (ambiguous)        -> must stay unresolved
//   D  resolver UNKNOWN + NO local body (external/unresolved import)              -> must stay unresolved
// Emits identity_gap.tsv: cpg, call_id, callee_name, call_form, has_local_body, unique_body,
//                         resolver_resolved, bucket, code
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import scala.io.Source

@main def exec(cpgFile: String, rawDir: String, cpgName: String) = {
  importCpg(cpgFile)
  val SIZE_INFLUENCING = Set("toLowerCase","toUpperCase","trim","trimStart","trimEnd","normalize",
    "concat","padStart","padEnd","replace","replaceAll")
  val BOUNDING = Set("slice","substring","substr","charAt","at")
  val BUILTIN = SIZE_INFLUENCING ++ BOUNDING ++ Set("stringify","parse","keys","values","map",
    "filter","forEach","join","split","push","test","then","catch")
  def rd(f: String): List[Array[String]] = {
    val p = new java.io.File(s"$rawDir/$f"); if (!p.exists) return Nil
    val s = Source.fromFile(p); try s.getLines().map(_.split("\t", -1)).toList finally s.close()
  }
  val resolved = rd("definition_resolution.tsv").filter(r => r.length >= 3 && r(2) == "ESTABLISHED").map(_(0)).toSet

  def callForm(c: nodes.Call): String = {
    val code = c.code.trim
    if (code.startsWith("this.")) "this_method"
    else if (code.matches("^[A-Za-z_$][\\w$]*\\.[A-Za-z_$][\\w$]*\\(.*")) "obj_method"
    else if (code.matches("^[A-Za-z_$][\\w$]*\\(.*")) "bare_or_imported"
    else "other"
  }

  val w = new java.io.PrintWriter(new java.io.File(s"$rawDir/identity_gap.tsv"), "UTF-8")
  w.println(Seq("cpg","call_id","callee_name","call_form","has_local_body","unique_body",
                "resolver_resolved","bucket","code").mkString("\t"))
  val calls = cpg.call
    .filterNot(_.name.startsWith("<operator>"))
    .filterNot(c => BUILTIN.contains(c.name))
    .filter(_.argument.size > 1)   // receiver/args present (a real call with an argument)
    .l
  var counts = scala.collection.mutable.Map[String,Int]().withDefaultValue(0)
  calls.foreach { c =>
    val form = callForm(c)
    val bodies = cpg.method.nameExact(c.name).l
    val hasBody = bodies.nonEmpty
    val unique = bodies.size == 1
    val resolverResolved = resolved.contains(c.id.toString)
    val bucket =
      if (resolverResolved) "A"
      else if (hasBody && unique) "B"
      else if (hasBody && !unique) "C"
      else "D"
    counts(bucket) += 1
    counts("form:" + form) += 1
    w.println(Seq(cpgName, c.id.toString, c.name, form, hasBody.toString, unique.toString,
                  resolverResolved.toString, bucket,
                  c.code.replace("\t"," ").replace("\n"," ").take(60)).mkString("\t"))
  }
  w.close()
  println(s"IDENTITY_GAP $cpgName: total=${calls.size} " +
          s"A=${counts("A")} B=${counts("B")} C=${counts("C")} D=${counts("D")} | " +
          s"this=${counts("form:this_method")} obj=${counts("form:obj_method")} " +
          s"bare=${counts("form:bare_or_imported")}")
}
