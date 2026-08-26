// JS-PROV-DEFRES — identity-safe definition resolver (separately gated).
// Input: an ESTABLISHED semantic identity (spec#member) for a path-member call.
// Chain: call -> import binding (spec, member) -> module file -> unique exported
// definition -> definition node. A definition is ESTABLISHED only when the chain
// resolves to EXACTLY ONE definition. Any ambiguity/unavailability -> UNKNOWN.
// NEVER repository name-search: the module is resolved FIRST (from the import spec),
// then the export member is matched WITHIN that uniquely resolved module.
//
// definition_resolution.tsv:
//   call_node_id, semantic_identity, definition_status(ESTABLISHED|UNKNOWN),
//   definition_node_id, definition_file, definition_line, definition_provenance
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s: String) = Option(s).getOrElse("").replace("\n", " ").replace("\t", " ").take(120)
  val w = new java.io.PrintWriter(new java.io.File(s"$outDir/definition_resolution.tsv"), "UTF-8")

  // import bindings: (file, localName) -> (spec, member). Alias `{member: local}` is
  // modeled by Joern as importedAs="member: local"; parse it so member != local.
  case class Imp(spec: String, member: String)
  val imports = scala.collection.mutable.Map[(String, String), Imp]()
  cpg.imports.l.foreach { i =>
    val spec = i.importedEntity.getOrElse("")
    val asRaw = i.importedAs.getOrElse("")
    val file = i.call.file.name.headOption.getOrElse("")
    val (member, local) =
      if (asRaw.contains(":")) (asRaw.split(":")(0).trim, asRaw.split(":")(1).trim)
      else (asRaw, asRaw)
    if (local.nonEmpty && spec.nonEmpty && !local.startsWith("_tmp")) imports((file, local)) = Imp(spec, member)
  }

  // resolve a module spec to CPG file(s): relative path -> one file; bare package name P
  // -> the set of files under a ".../P/" directory (workspace package). Uniqueness of the
  // export is enforced afterwards, so a package that exports the member more than once
  // still yields UNKNOWN.
  def resolveModuleFiles(callerFile: String, spec: String): List[String] = {
    if (spec.startsWith(".")) {
      val base = callerFile.split("/").dropRight(1).mkString("/")
      val joined = (base.split("/") ++ spec.split("/")).foldLeft(List[String]()) {
        case (acc, "..") => acc.dropRight(1)
        case (acc, ".")  => acc
        case (acc, seg)  => acc :+ seg
      }.mkString("/").stripPrefix("/")
      val cands = List(joined + ".js", joined + ".ts", joined + "/index.js", joined + "/index.ts")
      val primary = cpg.file.name.l.filter(f => cands.exists(c => f == c || f.endsWith("/" + c) || f.endsWith(c)))
      if (primary.nonEmpty) primary
      else cpg.file.name.l.filter(_.endsWith(spec.stripPrefix("./") + ".js"))
    } else {
      // workspace package: files under a directory segment equal to the package name
      cpg.file.name.l.filter(f => f.split("/").contains(spec) || f.contains("/" + spec + "/"))
    }
  }

  // candidate transform calls: path-member calls with an import-established identity.
  // (Here: any call whose name has an import binding in its file.)
  cpg.call.l.filter(c => !c.name.startsWith("<operator>")).foreach { c =>
    val file = c.file.name.headOption.getOrElse("")
    val callee = c.name
    imports.get((file, callee)).foreach { imp =>
      val sem = s"${imp.spec}#${imp.member}"
      // (1) shadowing: a LOCAL (non-external) def of the same name in the caller file
      val localShadow = cpg.method.isExternal(false).nameExact(callee).l.exists { m =>
        m.filename == file
      }
      val (status, dnode, dfile, dline, prov) =
        if (localShadow)
          ("UNKNOWN", "", "", "", "local definition shadows the imported name; call binds locally||")
        else {
          val modFiles = resolveModuleFiles(file, imp.spec)
          if (modFiles.isEmpty)
            ("UNKNOWN", "", "", "", s"module '${imp.spec}' not resolvable to an in-tree file (external/unavailable)||")
          else {
            val defs = cpg.method.isExternal(false).nameExact(imp.member).l.filter(m => modFiles.contains(m.filename))
            defs match {
              case d :: Nil =>
                ("ESTABLISHED", d.id.toString, d.filename, d.lineNumber.map(_.toString).getOrElse(""),
                 s"import ${imp.spec} -> module scope (${modFiles.size} file(s)) -> unique export ${imp.member}||" +
                 cl(d.code))
              case Nil =>
                ("UNKNOWN", "", "", "", s"no unique export '${imp.member}' in resolved module '${imp.spec}'||")
              case many =>
                ("UNKNOWN", "", "", "", s"${many.size} candidate definitions of '${imp.member}'; not selecting one||")
            }
          }
        }
      val provParts = prov.split("\\|\\|", 2); val provTxt = provParts(0); val body = if (provParts.length>1) provParts(1) else ""
      w.println(Seq(c.id.toString, cl(sem), status, dnode, cl(dfile), dline, cl(provTxt), body.replace("\t"," ").replace("\n"," ").take(400)).mkString("\t"))
    }
  }
  w.close()
  println(s"DEFINITION_RESOLUTION_COMPLETE: $outDir")
}
