// JS-PROV-R23b — ESM import bindings from IMPORT nodes (not the lowered
// `local = require(spec).member` form). Emits the semantic tuple directly:
//   module specifier + imported member + local binding
@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s:String)=Option(s).getOrElse("").replace("\n"," ").replace("\t"," ").take(90)
  val w=new java.io.PrintWriter(new java.io.File(s"$outDir/import_bindings.tsv"),"UTF-8")
  try cpg.imports.l.foreach{ i =>
    val ent = i.importedEntity.getOrElse("")
    val as  = i.importedAs.getOrElse("")
    val spec = if (ent.contains(":")) ent.substring(0, ent.lastIndexOf(':')) else ent
    val member = if (ent.contains(":")) ent.substring(ent.lastIndexOf(':')+1) else ""
    val file = i.call.l.headOption.map(_.method.filename).getOrElse("")
    w.println(Seq(cl(file), cl(spec), cl(member), cl(as), cl(i.code),
                  i.isExplicit.getOrElse(false), i.isWildcard.getOrElse(false)).mkString("\t"))
  } finally w.close()
}
