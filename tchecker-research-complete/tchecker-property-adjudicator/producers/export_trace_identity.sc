// JS-TRACE-IDENTITY — a SECOND identity-establishment mechanism (Step 4), narrowly scoped.
// Establishes a transform's identity ONLY when the observed transform call is trace-linked to
// EXACTLY ONE callee body (via actual MethodParameterIn entry on the dataflow path), and emits
// that exact body so adjudication is handed the same body the trace identified.
//
// Invariant (enforced here):
//   trace identity is ESTABLISHED iff the call enters exactly one distinct callee METHOD across
//   all observed flows. Ambiguous (multiple bodies) or no-entry calls emit unique=false and are
//   NOT given identity. No same-name inference: the callee is the method that OWNS the entered
//   MethodParameterIn node, not a method looked up by name.
//
// Emits trace_identity.tsv: call_node, callee_method_fullName, callee_method_id, unique, body
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import scala.io.Source

@main def exec(cpgFile: String, rawDir: String) = {
  importCpg(cpgFile)
  implicit val ec: EngineContext = EngineContext()
  def rd(f: String): List[Array[String]] = {
    val p = new java.io.File(s"$rawDir/$f"); if (!p.exists) return Nil
    val s = Source.fromFile(p); try s.getLines().map(_.split("\t", -1)).toList finally s.close()
  }
  val srcf = rd("source_facts.tsv").filter(r => r.length >= 6 && r(4) == "ESTABLISHED")

  // enclosing call of an expression node (walk AST parents until a Call)
  def enclosingCall(n: nodes.AstNode): Option[nodes.Call] = {
    var cur: nodes.AstNode = n
    var out: Option[nodes.Call] = None
    var steps = 0
    while (out.isEmpty && cur != null && steps < 6) {
      cur match { case c: nodes.Call if !c.name.startsWith("<operator>") => out = Some(c); case _ => }
      cur = cur.astParent; steps += 1
    }
    out
  }

  // on-path calls whose argument is carried by the flow, plus the callee bodies actually entered
  val onPath = scala.collection.mutable.Map[String, nodes.Call]()
  val entered = scala.collection.mutable.Map[String, scala.collection.mutable.Set[Long]]()
  srcf.map(r => (r(0), r(2))).distinct.foreach { case (sinkId, srcId) =>
    val flows = cpg.all.id(sinkId.toLong).collectAll[nodes.Expression].reachableByFlows(
                  cpg.all.id(srcId.toLong).collectAll[nodes.Expression]).l.take(12)
    flows.foreach { f =>
      // record every call whose argument is on the path (candidate transform call sites)
      f.elements.foreach { e =>
        enclosingCall(e).foreach { c =>
          if (!c.name.startsWith("<operator>") && c.argument.exists(_.id == e.id))
            onPath.getOrElseUpdate(c.id.toString, c)
        }
      }
      // record callee bodies actually entered (MethodParameterIn immediately after the argument)
      f.elements.sliding(2).foreach {
        case Seq(a, p: nodes.MethodParameterIn) =>
          enclosingCall(a).foreach { c =>
            entered.getOrElseUpdate(c.id.toString, scala.collection.mutable.Set[Long]()) += p.method.id
          }
        case _ =>
      }
    }
  }

  // ambiguity is denied on ANY CPG-visible signal, not just multiple entered bodies:
  //   - union methodFullName (e.g. "A | B:transform") from dynamic dispatch
  //   - call.callee resolving to more than one distinct local (non-external) method
  // This also covers reachableByFlows under-enumerating a polymorphic call (entering one target).
  def isAmbiguous(c: nodes.Call): Boolean = {
    val unionMfn = c.methodFullName.contains(" | ")
    val callees = c.callee(io.shiftleft.semanticcpg.language.NoResolve).l.filterNot(_.isExternal).map(_.fullName).distinct
    unionMfn || callees.size > 1
  }

  val w = new java.io.PrintWriter(new java.io.File(s"$rawDir/trace_identity.tsv"), "UTF-8")
  w.println(Seq("call_node","callee_method_fullName","callee_method_id","unique","body").mkString("\t"))
  onPath.foreach { case (callId, c) =>
    val methodIds = entered.getOrElse(callId, scala.collection.mutable.Set[Long]())
    val ambiguous = isAmbiguous(c)
    val unique = !ambiguous && methodIds.size == 1
    if (unique) {
      val m = cpg.all.id(methodIds.head).collectAll[nodes.Method].head
      val body = m.code.replace("\t", " ").replace("\n", "\\n").take(600)
      w.println(Seq(callId, m.fullName, m.id.toString, "true", body).mkString("\t"))
      println(s"TRACE_IDENTITY call=$callId -> UNIQUE ${m.fullName}")
    } else if (methodIds.nonEmpty || ambiguous) {
      val why = if (ambiguous) s"AMBIGUOUS(${c.methodFullName})" else s"MULTI_ENTER(${methodIds.size})"
      w.println(Seq(callId, "", "", "false", "").mkString("\t"))
      println(s"TRACE_IDENTITY call=$callId -> DENIED $why -> UNKNOWN")
    }
  }
  w.close()
  println(s"TRACE_IDENTITY_COMPLETE: $rawDir/trace_identity.tsv")
}
