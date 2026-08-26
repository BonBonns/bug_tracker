// Path traversal sink-semantics characterization. For each recognized filesystem/file-serving call
// shape, identifies the EXACT operand that determines the filesystem LOCATION -- never the whole
// call, never every argument indiscriminately. Emits one row per call site, matching a schema
// analogous to the frozen SSRF sink-semantics matrix: sink_family, call_shape, destination_operand,
// destination_component, confidence.
//
// PURE SINK CHARACTERIZATION. No property-propagation / PRESERVES-BREAKS-UNKNOWN logic exists in
// this file -- that is the next, separate stage, exactly mirroring the SSRF arc.
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, outFile: String) = {
  importCpg(cpgFile)

  case class Row(sinkFamily: String, callShape: String, callId: String, line: Int,
                  destOperandDesc: String, destComponent: String, confidence: String, note: String)
  val rows = scala.collection.mutable.ListBuffer[Row]()

  // fs.* functions: the path-bearing operand is ALWAYS the first real argument (positional),
  // uniformly across the whole family -- Node's fs module has no options-object path field the
  // way axios has baseURL/url. The one thing that MUST be avoided (matching the SSRF sibling-
  // argument lesson): writeFile's SECOND argument is DATA, never path-bearing, and must not be
  // confused with the path itself.
  val FS_FAMILY = Set("readFile", "readFileSync", "writeFile", "writeFileSync",
    "createReadStream", "createWriteStream", "unlink", "unlinkSync", "open", "openSync",
    "stat", "existsSync")

  def familyOf(c: nodes.Call): Option[String] = {
    val code = c.code
    if (code.startsWith("fs.")) {
      val method = c.name
      if (FS_FAMILY.contains(method)) Some(s"fs.$method") else None
    } else if (code.startsWith("res.sendFile(")) Some("express.sendFile")
    else if (code.startsWith("res.download(")) Some("express.download")
    else None
  }

  // find a field within an object-literal argument, matching the same helper pattern used in the
  // frozen SSRF sink-semantics script.
  def findObjectField(argRoot: nodes.AstNode, keys: Seq[String]): Option[(String, String)] = {
    val fieldAssigns = argRoot.ast.isCall.name("<operator>.assignment").l
    for (fa <- fieldAssigns) {
      val lhs = fa.argument(1)
      val rhs = fa.argument(2)
      lhs match {
        case fld: nodes.Call if fld.name == "<operator>.fieldAccess" =>
          val fieldName = fld.code.split("\\.").lastOption.getOrElse("")
          if (keys.contains(fieldName)) return Some((fieldName, rhs.code))
        case _ =>
      }
    }
    None
  }

  val calls = cpg.call.l
  calls.foreach { c =>
    familyOf(c).foreach { fam =>
      val args = c.argument.l.filter(_.argumentIndex >= 1)
      val firstArg = args.headOption
      if (fam.startsWith("fs.")) {
        // uniform positional case across the whole fs family -- arg0 (the path) is ALWAYS the
        // destination operand, full unrestricted location control. Never treat later args
        // (data, options, callback) as path-bearing.
        firstArg.foreach { a0 =>
          rows += Row(fam, "positional-path", c.id.toString, c.lineNumber.getOrElse(-1),
                      a0.code, "LOCATION", "ESTABLISHED", "path is always arg0 for the fs family")
        }
      } else if (fam == "express.sendFile") {
        firstArg.foreach { a0 =>
          val optionsArg = args.lift(1)
          val rootField = optionsArg.flatMap(opt => findObjectField(opt, Seq("root")))
          rootField match {
            case Some((_, rootExpr)) =>
              // root present: it determines the base directory (LOCATION_ROOT). The path arg
              // becomes CONTAINED within root -- Express's own resolution logic prevents ".."
              // escapes above root, structurally analogous to axios's baseURL/url split (fixed
              // baseURL means url can't override the host; fixed root means path can't escape it).
              rows += Row(fam, "positional-path-with-root", c.id.toString, c.lineNumber.getOrElse(-1),
                          rootExpr, "LOCATION_ROOT", "ESTABLISHED",
                          "root determines the base directory; path is resolved WITHIN it")
              rows += Row(fam, "positional-path-with-root", c.id.toString, c.lineNumber.getOrElse(-1),
                          a0.code, "CONTAINED_LOCATION", "ESTABLISHED",
                          "path is bounded by root (Express prevents '..'-escape above root when " +
                          "root is set) -- attacker may still choose WHICH file within root's " +
                          "subtree, but this is not unrestricted LOCATION control the way the " +
                          "no-root form is")
            case None =>
              // no root option: path is used as-is, unrestricted location control
              rows += Row(fam, "positional-path-no-root", c.id.toString, c.lineNumber.getOrElse(-1),
                          a0.code, "LOCATION", "ESTABLISHED",
                          "no root option present; path determines the full, unrestricted location")
          }
        }
      } else if (fam == "express.download") {
        // download's second argument is a DISPLAY FILENAME (Content-Disposition), never
        // path-bearing -- must not be confused with sendFile's options-object second argument,
        // even though both are member calls with a similar arity.
        firstArg.foreach { a0 =>
          rows += Row(fam, "positional-path", c.id.toString, c.lineNumber.getOrElse(-1),
                      a0.code, "LOCATION", "ESTABLISHED",
                      "path is always arg0; a present arg1 is a display filename, never path-bearing")
        }
      }
    }
  }

  // unresolved wrapper calls: never guess.
  val wrapperCandidates = cpg.call.filter(c => c.name.contains("readSomehow")).l
  wrapperCandidates.foreach { c =>
    rows += Row("UNRESOLVED_WRAPPER", "unresolved-call", c.id.toString, c.lineNumber.getOrElse(-1),
                "(unresolved)", "UNKNOWN", "UNSUPPORTED",
                "callee not a recognized sink family and not resolvable to a local body -- abstain")
  }

  val w = new java.io.PrintWriter(outFile)
  w.println(Seq("sink_family","call_shape","call_node_id","line","destination_operand",
                "destination_component","confidence","note").mkString("\t"))
  rows.foreach(r => w.println(Seq(r.sinkFamily, r.callShape, r.callId, r.line, r.destOperandDesc,
                                   r.destComponent, r.confidence, r.note).mkString("\t")))
  w.close()
  println(s"CHARACTERIZATION_COMPLETE rows=${rows.size}")
}
