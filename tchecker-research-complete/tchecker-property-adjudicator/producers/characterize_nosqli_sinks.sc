// NoSQL injection Stage 1: sink-semantics characterization for
// ATTACKER_CONTROL_OF_QUERY_OPERATOR_STRUCTURE. For each MongoDB/Mongoose query-executing call,
// identifies the SELECTOR argument, then enumerates EACH FIELD within it as its own operand pair
// (field identifier, value expression) -- mirroring the per-operand discipline used throughout
// this project (SSRF's options-object fields, command injection's args-array elements). PURE
// OPERAND IDENTIFICATION ONLY -- no type-guard/property-effect classification here.
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes

val QUERY_METHODS = Set("findOne", "find", "updateOne", "updateMany", "deleteOne", "deleteMany",
  "countDocuments", "findOneAndUpdate", "findOneAndDelete", "findOneAndReplace", "replaceOne")

@main def exec(cpgFile: String, outFile: String) = {
  importCpg(cpgFile)

  case class Row(sinkFamily: String, callId: String, line: Int, fieldKind: String,
                  fieldName: String, valueOperand: String, confidence: String, note: String)
  val rows = scala.collection.mutable.ListBuffer[Row]()

  // enumerates each field:value assignment within a selector-object argument -- reuses the exact
  // Block-wrapped-object-literal lowering already verified across SSRF, path traversal, and
  // command injection (`_tmp.field = value` for literal keys, `_tmp[key] = value` for computed).
  def findQueryFields(argRoot: nodes.AstNode): List[(String, String, nodes.Expression)] = {
    val assigns = argRoot.ast.isCall.name("<operator>.assignment").l
    assigns.flatMap { a =>
      val lhs = a.argument(1)
      val rhs = a.argument(2)
      lhs match {
        case fld: nodes.Call if fld.name == "<operator>.fieldAccess" =>
          // preserve the FULL literal key text -- do NOT split on every '.', since a MongoDB
          // dotted field path like 'services.password.reset.token' is a SINGLE literal object
          // key, not a chained field-access expression; splitting would truncate it to "token".
          // Extract everything after the FIRST '.' following the receiver, preserving any
          // further dots as part of the literal key itself.
          val code = fld.code
          val firstDot = code.indexOf('.')
          val fullFieldName = if (firstDot >= 0) code.substring(firstDot + 1) else code
          Some(("LITERAL_FIELD", fullFieldName, rhs.asInstanceOf[nodes.Expression]))
        case idx: nodes.Call if idx.name == "<operator>.indexAccess" =>
          val keyExpr = idx.argument.l.find(_.argumentIndex == 2).map(_.code).getOrElse("?")
          Some(("COMPUTED_FIELD", keyExpr, rhs.asInstanceOf[nodes.Expression]))
        case _ => None
      }
    }
  }

  cpg.call.l.foreach { c =>
    if (QUERY_METHODS.contains(c.name)) {
      val args = c.argument.l.filter(_.argumentIndex >= 1)
      // the SELECTOR is always the first real argument for every method in QUERY_METHODS,
      // confirmed against real Mongoose/MongoDB driver signatures (findOne(selector), find(selector),
      // updateOne(selector, update), deleteOne(selector), countDocuments(selector) all agree on this)
      args.headOption.foreach { selectorArg =>
        val fields = findQueryFields(selectorArg)
        if (fields.isEmpty) {
          rows += Row(c.name, c.id.toString, c.lineNumber.getOrElse(-1), "NO_FIELDS_FOUND",
                      "?", selectorArg.code.take(60), "UNSUPPORTED",
                      "selector argument present but no field:value structure identified")
        } else {
          fields.foreach { case (kind, fieldName, valueExpr) =>
            rows += Row(c.name, c.id.toString, c.lineNumber.getOrElse(-1), kind, fieldName,
                        valueExpr.code, "ESTABLISHED",
                        s"$kind: query field '$fieldName' <- value operand '${valueExpr.code}'")
          }
        }
      }
    }
  }

  val w = new java.io.PrintWriter(outFile)
  w.println(Seq("sink_family","call_node_id","line","field_kind","field_name","value_operand",
                "confidence","note").mkString("\t"))
  rows.foreach(r => w.println(Seq(r.sinkFamily, r.callId, r.line, r.fieldKind, r.fieldName,
                                   r.valueOperand, r.confidence, r.note).mkString("\t")))
  w.close()
  println(s"NOSQLI_SINK_CHARACTERIZATION_COMPLETE rows=${rows.size}")
}
