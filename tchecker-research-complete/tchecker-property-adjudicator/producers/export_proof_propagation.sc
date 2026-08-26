// PROOF — recover the propagation relation the detectors currently discard:
// for each JSON.stringify sink, walk the arg local back to its origin and note
// any intervening transform call + its resolved module identity.
// Emits proof_propagation.tsv: file, sink_line, sink_arg, origin_kind,
//   transform_name, transform_module, source_code
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, outDir: String) = {
  importCpg(cpgFile); new java.io.File(outDir).mkdirs()
  def cl(s: String) = Option(s).getOrElse("").replace("\n", " ").replace("\t", " ").take(120)
  val w = new java.io.PrintWriter(new java.io.File(s"$outDir/proof_propagation.tsv"), "UTF-8")

  def isBody(code: String) =
    code.matches("""(?s).*\breq(uest)?\.(body|payload|query|params)\b.*""")

  try cpg.call.name("stringify").l.foreach { c =>
    val m = c.method
    val arg = c.argument.l.find(_.argumentIndex == 1)
    val argCode = arg.map(a => Option(a.code).getOrElse("")).getOrElse("")
    // Walk the arg local back through a CHAIN of transform calls until we reach a
    // request source (or give up). Emits every transform on the path, source->sink.
    val transforms = scala.collection.mutable.ListBuffer[String]()
    var originKind = "OTHER"; var srcCode = argCode
    def defRhs(localName: String): Option[nodes.Expression] =
      m.assignment.l.find { a =>
        a.argument.l.find(_.argumentIndex == 1).exists(x => Option(x.code).getOrElse("") == localName)
      }.flatMap(_.argument.l.find(_.argumentIndex == 2))

    if (isBody(argCode)) { originKind = "DIRECT_BODY"; srcCode = argCode }
    else {
      var cur = argCode; var hops = 0
      var done = false
      while (!done && hops < 8) {
        hops += 1
        val rhs = defRhs(cur)
        rhs match {
          case Some(call: nodes.Call) if call.name != "<operator>.fieldAccess" =>
            transforms += call.name
            val callArgs = call.argument.l.map(x => Option(x.code).getOrElse("")).mkString(" ")
            if (isBody(callArgs)) { originKind = "VIA_TRANSFORM"; srcCode = callArgs; done = true }
            else {
              // the call's first identifier arg becomes the next local to resolve
              val nextLocal = call.argument.l.find(_.argumentIndex == 1)
                .collect { case i: nodes.Identifier => i.name }
              nextLocal match { case Some(nl) => cur = nl; case None => done = true }
            }
          case Some(e) =>
            val ec = Option(e.code).getOrElse("")
            if (isBody(ec)) { originKind = "VIA_TRANSFORM"; srcCode = ec }
            done = true
          case None => done = true
        }
      }
      if (transforms.isEmpty && isBody(argCode)) originKind = "DIRECT_BODY"
    }
    // transforms were collected sink->source; reverse to source->sink order
    val tchain = transforms.reverse.toList
    w.println(Seq(cl(m.filename), c.lineNumber.map(_.toString).getOrElse(""),
      cl(argCode), originKind, cl(tchain.mkString(",")), "", cl(srcCode)).mkString("\t"))
  } finally w.close()
  println(s"PROOF_PROP_COMPLETE: $outDir")
}
