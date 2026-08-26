// JS-PROV-LV1 — loop-control divergence / validation-bypass fact producer.
//
// Models the class behind the Elementor Pro Upload::validation() bug in JS/TS:
// a per-element validation loop uses `return` where it should use `continue`,
// so the first skippable element aborts validation for every sibling, while a
// paired processing loop uses `continue` and still reaches a sink with the
// unvalidated siblings.
//
// The crispest discriminator (visible in the original code): a per-element
// early `return` that records NO error first is a SILENT abandonment (the bug);
// a `return` preceded by an error-recording call is SAFE (the whole request is
// rejected downstream, so skipping siblings is harmless).
//
// Fact files (separate, opt-in — R33 rule):
//   loop_exits.tsv  file, method, loop_line, exit_kind, exit_line,
//                   guard_code, records_error_first, guard_is_per_element
//       exit_kind in {RETURN, CONTINUE, BREAK}. records_error_first is true iff
//       an error-recording call (addError/add_error/…) executes on the same
//       branch before the exit. guard_is_per_element is true iff the enclosing
//       condition references the loop's element variable.
//   loop_collections.tsv  file, method, loop_line, collection_code, elem_var
//   loop_sink_sites.tsv   file, method, loop_line, sink_kind, code, line
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s: String) = Option(s).getOrElse("").replace("\n", " ").replace("\t", " ").take(160)
  def w(n: String) = new java.io.PrintWriter(new java.io.File(s"$outDir/$n"), "UTF-8")

  val errorRecorders = Set("addError", "add_error", "addAdminErrorMessage",
    "add_admin_error_message", "fail", "reject")
  def isErrorRecorder(c: nodes.Call): Boolean = errorRecorders.contains(c.name)

  // A loop is a FOR/WHILE/DO control structure. for..of/for..in lower to WHILE.
  def loops(m: nodes.Method) =
    m.ast.isControlStructure.l.filter(cs =>
      Set("FOR", "WHILE", "DO").contains(cs.controlStructureType))

  // element variable of a for..of loop: the LOCAL/identifier bound per-iteration.
  def elemVarOf(loop: nodes.ControlStructure): String = {
    // heuristic: first local declared inside the loop header/body whose
    // initializer references an iterator, else the first block-local name.
    val code = Option(loop.code).getOrElse("")
    val m = """for\s*\(\s*(?:const|let|var)?\s*(?:\[[^\]]*\]|([A-Za-z_$][\w$]*))\s+of""".r
    m.findFirstMatchIn(code).flatMap(x => Option(x.group(1))).getOrElse {
      // destructured `[index, file]` -> take the LAST name (the value)
      val md = """for\s*\(\s*(?:const|let|var)?\s*\[\s*[\w$]+\s*,\s*([\w$]+)\s*\]""".r
      md.findFirstMatchIn(code).map(_.group(1)).getOrElse("")
    }
  }

  def collectionOf(loop: nodes.ControlStructure): String = {
    val code = Option(loop.code).getOrElse("")
    val m = """\bof\s+(.+?)\)""".r
    m.findFirstMatchIn(code).map(_.group(1).trim).getOrElse("")
  }

  // ---- loop_collections.tsv ------------------------------------------------
  val lc = w("loop_collections.tsv")
  try cpg.method.isExternal(false).l.foreach { m =>
    loops(m).foreach { loop =>
      lc.println(Seq(cl(m.filename), cl(m.fullName),
        loop.lineNumber.map(_.toString).getOrElse(""),
        cl(collectionOf(loop)), cl(elemVarOf(loop))).mkString("\t"))
    }
  } finally lc.close()

  // ---- loop_exits.tsv ------------------------------------------------------
  val le = w("loop_exits.tsv")
  try cpg.method.isExternal(false).l.foreach { m =>
    loops(m).foreach { loop =>
      val loopLine = loop.lineNumber.map(_.toInt).getOrElse(-1)
      val elem = elemVarOf(loop)
      // all control-flow exits lexically inside this loop's AST subtree
      val exits: List[(String, nodes.AstNode)] =
        loop.ast.isReturn.l.map(r => ("RETURN", r: nodes.AstNode)) ++
        loop.ast.isControlStructure.l.filter(_.controlStructureType == "CONTINUE")
          .map(c => ("CONTINUE", c: nodes.AstNode)) ++
        loop.ast.isControlStructure.l.filter(_.controlStructureType == "BREAK")
          .map(b => ("BREAK", b: nodes.AstNode))

      exits.foreach { case (kind, node) =>
        // skip exits that belong to a NESTED loop inside this one: the nearest
        // ENCLOSING loop (first loop in the ancestor chain) must be this loop.
        val nearestLoop = node.inAst.collectAll[nodes.ControlStructure]
          .l.find(cs => Set("FOR", "WHILE", "DO").contains(cs.controlStructureType))
        if (nearestLoop.map(_.id).contains(loop.id)) {
          val exitLine = node.lineNumber.map(_.toInt).getOrElse(-1)
          // A RETURN that carries a non-empty, non-undefined value is a SEARCH
          // return (found a result), categorically different from the Elementor
          // abandonment shape which returns void. Recorded so the verdict can
          // exclude search-and-return loops.
          val returnsValue = node match {
            case r: nodes.Return =>
              val rc = Option(r.code).getOrElse("").trim
              r.astChildren.l.nonEmpty && rc != "return" && rc != "return;" &&
                !rc.matches("""return\s+(undefined|null|false)\s*;?""")
            case _ => false
          }
          // enclosing IF guard (nearest in the ancestor chain)
          val guard = node.inAst.collectAll[nodes.ControlStructure]
            .l.find(_.controlStructureType == "IF")
          val guardCode = guard.map(g => Option(g.code).getOrElse("")).getOrElse("")
          val guardPerElem = elem.nonEmpty && guardCode.matches(s"""(?s).*\\b${java.util.regex.Pattern.quote(elem)}\\b.*""")
          // records_error_first: an error-recording call on the SAME branch,
          // before this exit (same enclosing IF/block, lower line).
          val branchScope = guard.getOrElse(loop)
          val recordsError = branchScope.ast.isCall.l.exists(c =>
            isErrorRecorder(c) && c.lineNumber.map(_.toInt).getOrElse(Int.MaxValue) <= exitLine)
          le.println(Seq(cl(m.filename), cl(m.fullName), loopLine.toString, kind,
            exitLine.toString, cl(guardCode), recordsError.toString,
            guardPerElem.toString, returnsValue.toString).mkString("\t"))
        }
      }
    }
  } finally le.close()

  // ---- loop_sink_sites.tsv -------------------------------------------------
  val ls = w("loop_sink_sites.tsv")
  def sinkKind(c: nodes.Call): Option[String] = {
    val code = Option(c.code).getOrElse("")
    if (code.matches("""(?s).*\bwriteFile(Sync)?\b.*""")) Some("FS_WRITE")
    else if (code.matches("""(?s).*\bmove_uploaded_file\b.*""") ||
             code.matches("""(?s).*\bmoveUploadedFile\b.*""") ||
             code.matches("""(?s).*\brename(Sync)?\b.*""")) Some("FS_MOVE")
    else if (code.matches("""(?s).*\b(exec|execSync|spawn|eval)\b.*""")) Some("CODE_EXEC")
    else None
  }
  try cpg.method.isExternal(false).l.foreach { m =>
    loops(m).foreach { loop =>
      loop.ast.isCall.l.foreach { c =>
        sinkKind(c).foreach { k =>
          ls.println(Seq(cl(m.filename), cl(m.fullName),
            loop.lineNumber.map(_.toString).getOrElse(""), k, cl(c.code),
            c.lineNumber.map(_.toString).getOrElse("")).mkString("\t"))
        }
      }
    }
  } finally ls.close()

  println(s"LV1_FACTS_COMPLETE: $outDir")
}
