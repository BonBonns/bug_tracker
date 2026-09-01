// Diagnostic ONLY -- manual review of the motifer finding, per instruction NOT to modify
// any frozen analyzer. Inspects: (a) every CALL node whose code is exactly "req.body",
// its id, line, and its immediate parent expression; (b) the JSON.stringify sink call,
// its value argument, and its own id; (c) whether a real Joern dataflow edge exists
// between the ARGUMENT-position req.body specifically (not whichever node
// setup_candidate.sc's .headOption happened to pick) and the sink argument.
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

@main def exec(cpgFile: String) = {
  importCpg(cpgFile)
  implicit val ec: EngineContext = EngineContext()

  println("=== all req.body call nodes ===")
  cpg.call.codeExact("req.body").l.foreach { c =>
    println(s"id=${c.id} line=${c.lineNumber.getOrElse(-1)} parentCode=${c.astParent.code.take(120)}")
  }

  println("=== JSON.stringify sink call ===")
  val sinkCallOpt = cpg.call.name("stringify").headOption
  sinkCallOpt.foreach { sk =>
    println(s"sink call id=${sk.id} code=${sk.code}")
    sk.argument.l.foreach { a =>
      println(s"  arg idx=${a.argumentIndex} id=${a.id} code=${a.code}")
    }
  }

  println("=== dataflow: EACH req.body occurrence -> sink's value argument ===")
  val sinkArgOpt = sinkCallOpt.flatMap(_.argument.argumentIndex(1).headOption)
  (cpg.call.codeExact("req.body").l, sinkArgOpt) match {
    case (srcs, Some(sinkArg)) =>
      srcs.foreach { s =>
        val flows = cpg.all.id(sinkArg.id).collectAll[nodes.Expression]
          .reachableByFlows(cpg.all.id(s.id).collectAll[nodes.Expression]).l
        println(s"src id=${s.id} (line ${s.lineNumber.getOrElse(-1)}) -> sink arg id=${sinkArg.id}: flows=${flows.size}")
      }
    case _ => println("sink argument not found")
  }
}
