import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes

// detects whether a sink's enclosing method is the `action` handler of an API.v1.get/post route
// registration that has a body:/query: schema gate -- returns Some(schemaIdentifierCode) if a gate
// is detected (regardless of whether the schema itself can be resolved further), None otherwise.
// Conservative by design: a detected-but-unresolved gate must be reported as UNKNOWN, never
// silently treated as PRESERVES (the exact mistake that produced four false leads this session).
def detectApiRouteSchemaGate(sinkMethod: nodes.Method): Option[String] = {
  val apiCalls = cpg.call.nameNot("<operator>.*").filter { c =>
    (c.name == "get" || c.name == "post" || c.name == "put" || c.name == "delete") &&
    c.code.startsWith("API.v1.")
  }.l
  apiCalls.flatMap { apiCall =>
    val handlersArg = apiCall.argument.l.find(_.argumentIndex == 3)
    val actionAssign = handlersArg.toList.flatMap(_.ast.isCall.name("<operator>.assignment").l)
      .find(_.code.contains(".action ="))
    val pointsToThisMethod = actionAssign.exists { a =>
      a.argument.l.find(_.argumentIndex == 2).exists {
        case ref: nodes.MethodRef =>
          scala.util.Try(ref.referencedMethod).toOption.exists(_.id == sinkMethod.id)
        case _ => false
      }
    }
    if (pointsToThisMethod) {
      val optionsArg = apiCall.argument.l.find(_.argumentIndex == 2)
      val schemaAssign = optionsArg.toList.flatMap(_.ast.isCall.name("<operator>.assignment").l)
        .find(a => a.code.contains(".body =") || a.code.contains(".query ="))
      schemaAssign.map(a => a.argument.l.find(_.argumentIndex == 2).map(_.code).getOrElse("?"))
    } else None
  }.headOption
}

@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  val cases = Seq("integrations.remove" -> "gated (body)", "emoji-custom.list" -> "gated (query)")
  val findOneCalls = cpg.call.name("findOne|find").l
  findOneCalls.foreach { sink =>
    val gate = detectApiRouteSchemaGate(sink.method)
    println(s"sink=${sink.code.take(50)} method=${sink.method.name} gate=${gate}")
  }
}
