// JS-PROV-GS2 — base binding classification for global-mutation (aliasing scope).
// The raw detector's base_is_import conflates LOCAL_OBJECT with PARAM and IMPORT_ALIAS
// (all is_import=false). Aliasing scope needs them separated:
//   LOCAL_OBJECT : base = {...} literal            -> not shared
//   IMPORT       : base = require()/import          -> shared singleton
//   IMPORT_ALIAS : base = <importName>              -> shared singleton (aliased)
//   PARAM        : base is a function parameter     -> UNKNOWN (caller may pass shared)
//   UNKNOWN      : anything unresolved
//
// base_bindings.tsv:  file, method, name, binding_kind
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s: String) = Option(s).getOrElse("").replace("\n", " ").replace("\t", " ").take(80)
  val w = new java.io.PrintWriter(new java.io.File(s"$outDir/base_bindings.tsv"), "UTF-8")

  // names bound to an import (require/import) anywhere in the CPG
  val importNames = scala.collection.mutable.Set[String]()
  cpg.assignment.l.foreach { a =>
    val lhs = a.argument.headOption.map(x => Option(x.code).getOrElse("")).getOrElse("").trim
    val rhs = a.argument.l.lift(1).map(x => Option(x.code).getOrElse("")).getOrElse("")
    if (rhs.matches("""(?s).*\brequire\s*\(.*""") || rhs.matches("""(?s).*\bimport\b.*"""))
      importNames += lhs
  }
  try {
    cpg.method.isExternal(false).l.foreach { m =>
      val seen = scala.collection.mutable.Set[String]()
      // parameters
      m.parameter.name.l.foreach { p =>
        if (seen.add(p)) w.println(Seq(cl(m.filename), cl(m.fullName), cl(p), "PARAM").mkString("\t"))
      }
      // local assignments in this method
      m.ast.isCall.name("<operator>.assignment").l.foreach { a =>
        val lhs = a.argument.headOption.map(x => Option(x.code).getOrElse("")).getOrElse("").trim
        val rhs = a.argument.l.lift(1).map(x => Option(x.code).getOrElse("")).getOrElse("").trim
        if (!lhs.contains(".") && seen.add(lhs)) {
          val kind =
            if (rhs.matches("""(?s).*\brequire\s*\(.*""") || rhs.matches("""(?s).*\bimport\b.*""")) "IMPORT"
            else if (rhs.startsWith("{")) "LOCAL_OBJECT"
            else if (importNames.contains(rhs)) "IMPORT_ALIAS"
            else "UNKNOWN"
          w.println(Seq(cl(m.filename), cl(m.fullName), cl(lhs), kind).mkString("\t"))
        }
      }
      // module-scope import names visible to this method
      importNames.foreach { n =>
        if (seen.add(n)) w.println(Seq(cl(m.filename), cl(m.fullName), cl(n), "IMPORT").mkString("\t"))
      }
    }
  } finally w.close()
  println(s"BASE_BINDINGS_COMPLETE: $outDir")
}
