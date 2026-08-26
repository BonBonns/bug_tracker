import java.io.{File, PrintWriter}
import java.nio.charset.StandardCharsets
import java.util.Base64

// JS-STATE-R01: does the REF graph (identifier -> LOCAL), independent of any
// name string, let us tell whether a guard checks the SAME local that a
// value-producing call was assigned into, or a DIFFERENT local produced by an
// intermediate transformation call? This directly tests the hard rule: no
// inference from names.

def b64(s: String): String = Base64.getEncoder.encodeToString(Option(s).getOrElse("").getBytes(StandardCharsets.UTF_8))
def writer(path: String): PrintWriter = new PrintWriter(new File(path), "UTF-8")

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile)
  new File(outDir).mkdirs()

  val out = writer(s"$outDir/ref_based_guard_subject.tsv")
  try {
    cpg.method.l.filter(_.name.startsWith("case")).foreach { m =>
      // Every assignment LOCAL <- CALL(...) in this method, keyed by the
      // LOCAL node id the LHS identifier resolves to via REF (not by name).
      val assignedLocals: List[(Long, String, String)] = m.assignment.l.flatMap { a =>
        val lhsIdent: Option[io.shiftleft.codepropertygraph.generated.nodes.Identifier] = a.argument(1) match {
          case i: io.shiftleft.codepropertygraph.generated.nodes.Identifier => Some(i)
          case _ => None
        }
        val rhsCall: Option[io.shiftleft.codepropertygraph.generated.nodes.Call] = a.argument(2) match {
          case c: io.shiftleft.codepropertygraph.generated.nodes.Call => Some(c)
          case _ => None
        }
        for (li <- lhsIdent.toList; ref <- li.refOut.l; rc <- rhsCall.toList)
          yield (ref.id, rc.name, rc.code)
      }
      // The guard condition's checked identifier(s), resolved to LOCAL via REF.
      // FIX (found via case3's `!r3.ok` in JS-STATE-R01): must walk the FULL
      // condition subtree (all AST descendants), not just direct children --
      // `!r3.ok` is <operator>.logicalNot(<operator>.fieldAccess(r3, ok)), so
      // the checked identifier `r3` is two levels down from the condition node.
      val guardChecked = m.controlStructure.condition.l.flatMap { cond =>
        cond.ast.isIdentifier.l
      }.flatMap(i => i.refOut.l.map(ref => (i.id, ref.id)))

      guardChecked.foreach { case (identId, refLocalId) =>
        val producer = assignedLocals.find(_._1 == refLocalId)
        out.println(Seq(
          m.id.toString, b64(m.name), identId.toString, refLocalId.toString,
          b64(producer.map(_._2).getOrElse("<NOT-FOUND-AS-DIRECT-ASSIGNMENT-TARGET>")),
          b64(producer.map(_._3).getOrElse(""))
        ).mkString("\t"))
      }
    }
  } finally out.close()
}
