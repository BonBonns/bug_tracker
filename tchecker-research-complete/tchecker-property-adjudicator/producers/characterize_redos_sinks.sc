// REDOS-SINK-R01: Stage 1 sink-semantics characterization for ATTACKER_CONTROLLED_REGEX_COMPLEXITY.
// For each regex-execution call, identifies the REGEX_INPUT operand (the attacker-influenceable
// matched-against string) and the REGEX_PATTERN operand (traced to its literal source when
// possible). PURE OPERAND IDENTIFICATION ONLY -- no complexity/danger classification here, matching
// the discipline used for every prior Stage 1 in this project (SSRF, path traversal, command
// injection all kept sink-identification separate from property-effect classification).
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes

// RegExp.prototype methods: receiver IS the pattern, arg1 is the input string
val REGEXP_RECEIVER_METHODS = Set("test", "exec")
// String.prototype methods: receiver IS the input string, arg1 is the pattern
val STRING_RECEIVER_METHODS = Set("match", "matchAll", "search", "replace", "replaceAll")

@main def exec(cpgFile: String, outFile: String) = {
  importCpg(cpgFile)

  case class Row(callShape: String, callId: String, line: Int, inputOperand: String,
                  patternOperand: String, patternResolution: String, confidence: String, note: String)
  val rows = scala.collection.mutable.ListBuffer[Row]()

  // resolves a pattern operand to its literal source text, if statically determinable.
  // Returns (resolutionKind, literalTextOrDescription).
  def resolvePattern(operand: nodes.Expression, method: nodes.Method): (String, String) = operand match {
    case lit: nodes.Literal if lit.code.trim.startsWith("/") =>
      ("DIRECT_LITERAL", lit.code)
    case id: nodes.Identifier =>
      // trace back to a defining assignment within the same method
      val assigns = method.ast.isCall.name("<operator>.assignment").l.filter { a =>
        a.argument.l.find(_.argumentIndex == 1).exists(_.code.trim == id.code.trim)
      }
      val resolved = assigns.flatMap { a =>
        a.argument.l.find(_.argumentIndex == 2).flatMap {
          case lit: nodes.Literal if lit.code.trim.startsWith("/") =>
            Some(("VARIABLE_TO_LITERAL", lit.code))
          case block if block.code.trim.startsWith("new RegExp(") =>
            // new RegExp(...) lowers to a Block -- find the <operator>.new call within it and
            // check whether ITS argument is a literal string or a dynamic (non-literal) value
            val newCall = block.ast.isCall.name("<operator>.new").headOption
            newCall.flatMap(_.argument.l.find(_.argumentIndex == 1)) match {
              case Some(patLit: nodes.Literal) => Some(("VARIABLE_TO_NEW_REGEXP_LITERAL", patLit.code))
              case Some(patDynamic) => Some(("VARIABLE_TO_NEW_REGEXP_DYNAMIC", patDynamic.code))
              case None => None
            }
          case _ => None
        }
      }
      resolved.headOption.getOrElse(("UNRESOLVED_IDENTIFIER", id.code))
    case other => ("UNRESOLVED_OTHER", other.code)
  }

  val calls = cpg.call.l
  calls.foreach { c =>
    val method = c.method
    if (REGEXP_RECEIVER_METHODS.contains(c.name)) {
      val receiver = c.argument.l.find(_.argumentIndex == 0)
      val inputArg = c.argument.l.find(_.argumentIndex == 1)
      (receiver, inputArg) match {
        case (Some(recv), Some(input)) =>
          val (resKind, resText) = resolvePattern(recv, method)
          rows += Row(c.name, c.id.toString, c.lineNumber.getOrElse(-1), input.code,
                      resText, resKind, "ESTABLISHED",
                      s"RegExp.prototype.${c.name}(): receiver is the pattern, arg1 is input")
        case _ =>
      }
    } else if (STRING_RECEIVER_METHODS.contains(c.name)) {
      val receiver = c.argument.l.find(_.argumentIndex == 0)
      val patternArg = c.argument.l.find(_.argumentIndex == 1)
      (receiver, patternArg) match {
        case (Some(recv), Some(pat)) =>
          val (resKind, resText) = resolvePattern(pat, method)
          rows += Row(c.name, c.id.toString, c.lineNumber.getOrElse(-1), recv.code,
                      resText, resKind, "ESTABLISHED",
                      s"String.prototype.${c.name}(): receiver is input, arg1 is the pattern")
        case _ =>
      }
    }
  }

  val w = new java.io.PrintWriter(outFile)
  w.println(Seq("call_shape","call_id","line","input_operand","pattern_operand",
                "pattern_resolution","confidence","note").mkString("\t"))
  rows.foreach(r => w.println(Seq(r.callShape, r.callId, r.line, r.inputOperand, r.patternOperand,
                                   r.patternResolution, r.confidence, r.note).mkString("\t")))
  w.close()
  println(s"REDOS_SINK_CHARACTERIZATION_COMPLETE rows=${rows.size}")
}
