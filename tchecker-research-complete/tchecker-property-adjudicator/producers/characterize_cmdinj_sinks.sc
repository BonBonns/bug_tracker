// Command injection sink-semantics characterization. For each recognized child_process call
// shape, identifies the EXACT operand(s) that determine COMMAND SYNTAX vs. mere ARGUMENT content
// vs. the EXECUTABLE PATH itself -- never the whole call, never every argument indiscriminately.
// Critical distinction, verified against Node's own documented behavior (not assumed): exec/
// execSync ALWAYS run through a shell (the whole command string is COMMAND_SYNTAX); execFile/spawn
// default to NO shell (array args are ARGUMENT_ONLY, no shell metacharacter interpretation); but
// when options.shell is truthy (true or a shell-path string) on execFile/spawn, EVERY argument --
// including each array element -- becomes COMMAND_SYNTAX-relevant too, per Node's own explicit
// warning ("If the shell option is enabled, do not pass unsanitized user input... any input
// containing shell metacharacters may be used to trigger arbitrary command execution").
//
// PURE SINK CHARACTERIZATION. No property-propagation logic exists in this file.
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, outFile: String) = {
  importCpg(cpgFile)

  case class Row(sinkFamily: String, callShape: String, callId: String, line: Int,
                  destOperandDesc: String, destComponent: String, confidence: String, note: String)
  val rows = scala.collection.mutable.ListBuffer[Row]()

  val SHELL_ALWAYS_ON = Set("exec", "execSync")           // always runs through a shell
  val SHELL_OPTIONAL = Set("execFile", "execFileSync", "spawn", "spawnSync")  // shell:false by default

  def findObjectField(argRoot: nodes.AstNode, keys: Seq[String]): Option[(String, nodes.Expression)] = {
    val fieldAssigns = argRoot.ast.isCall.name("<operator>.assignment").l
    for (fa <- fieldAssigns) {
      val lhs = fa.argument(1); val rhs = fa.argument(2)
      lhs match {
        case fld: nodes.Call if fld.name == "<operator>.fieldAccess" =>
          val fieldName = fld.code.split("\\.").lastOption.getOrElse("")
          if (keys.contains(fieldName)) return Some((fieldName, rhs))
        case _ =>
      }
    }
    None
  }
  // array literals lower to a Block containing Array.factory() + .push(element) calls per element
  // (confirmed by direct AST inspection -- the same Block-wrapping pattern as object literals and
  // constructor calls seen throughout this session, just with a different internal shape).
  def findArrayElements(argRoot: nodes.AstNode): List[nodes.Expression] = {
    argRoot.ast.isCall.filter(_.code.matches(".*\\.push\\(.+\\)$")).l
      .flatMap(_.argument.l.find(_.argumentIndex == 1))
  }
  // is the shell option truthy? handles boolean `true` and any string (custom shell path) --
  // both trigger shell mode per Node's docs. `false` and absence do not.
  def isShellEnabled(optionsArg: Option[nodes.AstNode]): Boolean = {
    optionsArg.flatMap(opt => findObjectField(opt, Seq("shell"))).exists { case (_, valueExpr) =>
      valueExpr.code.trim != "false"
    }
  }

  val calls = cpg.call.l
  calls.foreach { c =>
    val fam = c.name
    if (SHELL_ALWAYS_ON.contains(fam)) {
      // command is ALWAYS arg1 (a string), ALWAYS shell-interpreted -- the whole string is the
      // COMMAND_SYNTAX operand, regardless of any options.
      val args = c.argument.l.filter(_.argumentIndex >= 1)
      args.headOption.foreach { cmdArg =>
        rows += Row(fam, "command-string-always-shell", c.id.toString, c.lineNumber.getOrElse(-1),
                    cmdArg.code, "COMMAND_SYNTAX", "ESTABLISHED",
                    s"$fam always runs through a shell; the whole command string is syntax-relevant")
      }
    } else if (SHELL_OPTIONAL.contains(fam)) {
      val args = c.argument.l.filter(_.argumentIndex >= 1)
      val firstArg = args.headOption  // command or file
      val secondArg = args.lift(1)    // could be args-array OR options (if args omitted)
      val secondArgIsArray = secondArg.exists(a => a.ast.isCall.filter(_.code.matches(".*\\.push\\(.+\\)$")).nonEmpty || a.code.trim.startsWith("["))
      val (argsArrayOpt, optionsArgOpt) =
        if (secondArgIsArray) (secondArg, args.lift(2)) else (None, secondArg)
      val shellOn = isShellEnabled(optionsArgOpt)

      firstArg.foreach { cmdOrFile =>
        if (shellOn) {
          // shell mode: the "command/file" position is ALSO shell-interpreted (matches the
          // single-string spawn(command, {shell:true}) form exactly, per Node's docs)
          rows += Row(fam, "command-or-file-shell-enabled", c.id.toString, c.lineNumber.getOrElse(-1),
                      cmdOrFile.code, "COMMAND_SYNTAX", "ESTABLISHED",
                      s"options.shell is enabled -- this operand is shell-interpreted")
        } else {
          rows += Row(fam, "executable-path-no-shell", c.id.toString, c.lineNumber.getOrElse(-1),
                      cmdOrFile.code, "EXECUTABLE_PATH", "ESTABLISHED",
                      "no shell; this is the program to execve(), not shell syntax")
        }
      }
      argsArrayOpt.foreach { argsArray =>
        val elements = findArrayElements(argsArray)
        elements.foreach { elem =>
          if (shellOn) {
            rows += Row(fam, "array-arg-shell-enabled", c.id.toString, c.lineNumber.getOrElse(-1),
                        elem.code, "COMMAND_SYNTAX", "ESTABLISHED",
                        "options.shell is enabled -- per Node's own documented warning, array " +
                        "args elements are ALSO shell-interpreted, not just the command string " +
                        "-- the 'array doesn't save you' case")
          } else {
            rows += Row(fam, "array-arg-no-shell", c.id.toString, c.lineNumber.getOrElse(-1),
                        elem.code, "ARGUMENT_ONLY", "ESTABLISHED",
                        "no shell; passed directly via execve(), no shell metacharacter " +
                        "interpretation of this element")
          }
        }
      }
    }
  }

  val w = new java.io.PrintWriter(outFile)
  w.println(Seq("sink_family","call_shape","call_node_id","line","destination_operand",
                "destination_component","confidence","note").mkString("\t"))
  rows.foreach(r => w.println(Seq(r.sinkFamily, r.callShape, r.callId, r.line, r.destOperandDesc,
                                   r.destComponent, r.confidence, r.note).mkString("\t")))
  w.close()
  println(s"CHARACTERIZATION_COMPLETE rows=${rows.size}")
}
