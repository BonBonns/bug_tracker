// npm_public_export_sources_r04.sc — SERIALIZE-DOS-R04 source-family producer.
//
// NEW producer. Does not modify any frozen file: neither
// tchecker-property-adjudicator/producers/export_redos_npm_integ.sc nor
// export_redos_npm_integ_r02.sc (the ReDoS work this file ports FROM) nor
// serialize-dos-r01/producers/setup_candidate_multisource.sc (R03, this property's own
// prior producer, left byte-for-byte alone -- R04 supersedes it going forward but does
// not edit it).
//
// WHY THIS FILE EXISTS
// ---------------------
// Three real npm packages in a row (mozilla/fxa's customs.js, @sonatel-os/juf-xpress-
// logger, @rasla/logify) exposed the same limitation: the existing size/structure
// engine recognizes APPLICATION-INGRESS sources (req.body, request.payload -- literal
// accessor patterns on a request/message object) but has no model at all for a value
// that arrives as an already-abstracted EXPORTED FUNCTION OR METHOD PARAMETER -- this
// package's own public npm API surface, not a web framework's request object. Per
// instruction, this file does NOT invent a new model for that from scratch: the ReDoS
// property (now finished, merged into develop) already built and real-package-validated
// exactly this recognition -- see export_redos_npm_integ_r02.sc's own docstring and
// study/redos_npm/pilot25/audit/R02_IMPLEMENTATION.md for the full, real-Joern-CPG-
// verified design of each capability below. This file PORTS that model's resolution
// algorithm verbatim (same functions, same structure, same abstention vocabulary),
// re-pointed at THIS property's own sinks (JSON.stringify/util.inspect) instead of
// ReDoS's own sinks (a regex .exec/.test call whose pattern is then complexity-
// classified) -- the source-resolution logic itself is untouched by that difference.
//
// TWO EXPLICITLY SEPARATE SOURCE FAMILIES (never merged into one)
// ------------------------------------------------------------------
//   APPLICATION_INGRESS_INPUT  -- R01-R03's own, already-proven model, carried forward
//     unchanged: every occurrence of the literal ingress accessor pattern (e.g.
//     "req.body"), enumerated in full (R03's own "never .headOption" discipline).
//   PACKAGE_API_INPUT  -- NEW. Ported from export_redos_npm_integ_r02.sc's capabilities
//     1-3 (that file's own capability 4, cross-scope/closure identifier resolution, is
//     specific to ReDoS's own pattern-identifier sink shape and is not needed here --
//     this property's sinks consume VALUES flowing through parameters/fields directly,
//     not a regex-literal identifier resolved by scope-walking):
//       1. Exported class instance-method recognition (module.exports = Class,
//          exports.Name = Class / named ESM export desugaring -- confirmed identical
//          CPG shape for both) -- the class's own constructor is never itself a source
//          (CLASS_CONSTRUCTOR_NOT_PUBLIC_API); its OTHER instance methods are.
//       2. Object-literal shorthand export recognition (module.exports = { foo, bar }).
//       3. Constructor parameter -> exact this.field identity -> method-use
//          propagation, including the real, load-bearing discovery that this Joern
//          version's reachableByFlows does not propagate from a sub-expression to a
//          compound parent expression built on top of it -- collectFieldAccessChain
//          walks the field-access chain (this.req -> this.req.body -> ...) structurally
//          so every level is its own source, the same principle R01 already used for
//          req.body via a fixed regex, applied here with no fixed field-name vocabulary.
//     Plus (5, cross-cutting) the same explicit, distinctly-labeled abstention for every
//     shadowing/reassignment/ambiguity case 1-3 can hit -- never a guess. Also included:
//     CommonJS (module.exports = fn / module.exports.name = fn) and dynamic-key export
//     abstention (DYNAMIC_COMPUTED_EXPORT_KEY) -- both already present, unchanged, in
//     the ported resolveExportRhs/export-assignment loop.
//
// Sink and reachability discipline: identical to R03's setup_candidate_multisource.sc --
// every matching sink is enumerated (never .headOption), and reachability is computed
// per (sink, family) using ONE BATCHED reachableByFlows(sources.iterator) call (ReDoS's
// own proven at-scale technique, confirmed against a real 48,100-call CPG in this
// property's own R03 blind package) rather than one call per individual (sink, source)
// pair -- the batched call's OWN returned flows are inspected to attribute each flow back
// to its real origin source node id, so node identity is still fully preserved (R03's
// own control M6 requirement) without the O(sinks x sources) cost of individual calls.
//
// OUTPUT
// ------
// Legacy-compatible source_facts.tsv/propagation_relations.tsv (same 12/9-column shape
// setup_candidate.sc has always written) so the FROZEN export_property_propagation.sc/
// export_trace_identity.sc/adjudicate_js.py run completely unmodified downstream --
// column 3 (origin_family) now correctly carries "PACKAGE_API_INPUT" or
// "APPLICATION_INGRESS_INPUT" (adjudicate_js.py's own srcf[0][3]/"origin_family" field
// already expects exactly this convention -- R01-R03's setup_candidate_multisource.sc
// wrote a literal source-pattern string there instead, a convention this file corrects
// to match the shared, already-established schema). transform_identity.tsv is left
// empty (export_trace_identity.sc computes its own trace identity independently from
// source_facts.tsv; nothing downstream reads transform_identity.tsv as input -- same as
// R03's own, and the original setup_candidate.sc's, convention).
//
// NEW, node-identity-preserving evidence (this file's own contribution, matching R03's
// multisource_evidence.tsv shape, extended with a family column):
//   npm_public_export_evidence.tsv (8 cols): sink_id, sink_line, source_id, source_line,
//     source_code, family, has_flow, flow_count
//
// Usage: joern --script npm_public_export_sources_r04.sc --param cpgFile=<cpg>
//        --param rawDir=<dir> --param ingressSrcPattern="req.body"
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

@main def exec(cpgFile: String, rawDir: String, ingressSrcPattern: String) = {
  importCpg(cpgFile)
  implicit val ec: EngineContext = EngineContext()
  new java.io.File(rawDir).mkdirs()

  // ===== sink enumeration: every JSON.stringify/util.inspect call, never .headOption.
  // NAME-first, unlike export_serialize_facts.sc's own looser code-regex-first predicate
  // (safe there only because it is applied after `cpg.method...foreach`'s own per-method
  // `m.call` scoping, never against the whole CPG's `cpg.call.l` the way this file must
  // for a correct multi-sink enumeration): a synthetic hoisted-function-declaration Call
  // node's OWN `.code` can embed its entire function body as text, so a bare code-regex
  // match against `cpg.call.l` can false-positive on a node that merely CONTAINS a
  // serializer call inside a larger synthetic wrapper, without itself BEING one --
  // discovered directly against this file's own fixtures (r4-obj-shorthand's hoisted
  // `function foo(...)` declaration node wrongly matched before this fix). Requiring the
  // call's own resolved name first closes that gap. =====
  def isSerializerSink(c: nodes.Call): Boolean = {
    val code = Option(c.code).getOrElse("")
    (c.name == "stringify" && code.matches("""(?s).*\bJSON\.stringify\s*\(.*""")) ||
    (c.name == "inspect" && code.matches("""(?s).*\butil\.inspect\s*\(.*"""))
  }
  val sinks = cpg.call.l.filter(isSerializerSink).distinctBy(_.id)
  System.err.println(s"R04 sinks found: ${sinks.size}")

  // ===== APPLICATION_INGRESS_INPUT: R01-R03's own model, carried forward unchanged
  // (every matching occurrence, never .headOption) =====
  val exactIngressSrcs = cpg.call.codeExact(ingressSrcPattern).l
  val ingressSources: List[nodes.Expression] =
    (if (exactIngressSrcs.nonEmpty) exactIngressSrcs
     else cpg.call.code(".*" + java.util.regex.Pattern.quote(ingressSrcPattern) + ".*").l)
      .map(c => c: nodes.Expression).distinctBy(_.id)
  System.err.println(s"R04 APPLICATION_INGRESS_INPUT source candidates: ${ingressSources.size}")

  // ===== PACKAGE_API_INPUT: ported verbatim from export_redos_npm_integ_r02.sc's
  // capabilities 1-3 (see that file and R02_IMPLEMENTATION.md for the original real-CPG
  // verification this logic rests on) =====
  sealed trait ExportResolution
  case class SingleFunction(m: nodes.Method) extends ExportResolution
  case class ClassExport(td: nodes.TypeDecl) extends ExportResolution

  val exportAbstentions = scala.collection.mutable.ListBuffer[(String, String)]()

  def resolveExportRhs(rhs: nodes.Expression, scopeMethod: nodes.Method): Either[String, ExportResolution] = {
    def methodFromRef(ref: nodes.MethodRef): Either[String, ExportResolution] = {
      val candidates = cpg.method.fullName(ref.methodFullName).l
      candidates match {
        case Nil => Left("METHODREF_TARGET_NOT_FOUND")
        case m :: Nil if m.name == "<init>" =>
          val tds = m.typeDecl.l
          tds match {
            case td :: Nil =>
              if (td.method.name("<init>").l.size > 1) Left("MULTIPLE_CANDIDATE_CONSTRUCTORS")
              else Right(ClassExport(td))
            case Nil => Left("CLASS_CONSTRUCTOR_NOT_PUBLIC_API")
            case _ => Left("MULTIPLE_CANDIDATE_CONSTRUCTORS")
          }
        case m :: Nil => Right(SingleFunction(m))
        case _ => Left("MULTIPLE_CANDIDATE_CONSTRUCTORS")
      }
    }
    rhs match {
      case ref: nodes.MethodRef => methodFromRef(ref)
      case id: nodes.Identifier =>
        val candidateAssigns = scopeMethod.ast.isCall.name("<operator>.assignment").l.filter { a =>
          a.argument.l.find(_.argumentIndex == 1).exists {
            case lhsId: nodes.Identifier => lhsId.code.trim == id.code.trim
            case _ => false
          } && a.argument.l.find(_.argumentIndex == 2).exists(_.isInstanceOf[nodes.MethodRef])
        }
        candidateAssigns.size match {
          case 0 => Left("UNRESOLVED_IDENTIFIER_NO_METHODREF_ASSIGNMENT")
          case 1 =>
            candidateAssigns.head.argument.l.find(_.argumentIndex == 2) match {
              case Some(ref: nodes.MethodRef) => methodFromRef(ref)
              case _ => Left("UNRESOLVED_RHS_SHAPE")
            }
          case _ => Left("AMBIGUOUS_IDENTIFIER_MULTIPLE_METHODREF_ASSIGNMENTS")
        }
      case _: nodes.Block => Left("UNRESOLVED_RHS_SHAPE")  // handled by resolveObjectLiteralExport instead
      case _ => Left("UNRESOLVED_RHS_SHAPE")
    }
  }

  def resolveObjectLiteralExport(blk: nodes.Block, scopeMethod: nodes.Method): List[(String, Either[String, ExportResolution])] = {
    val propAssigns = blk.astChildren.isCall.name("<operator>.assignment").l
    propAssigns.map { pa =>
      val lhs = pa.argument.l.find(_.argumentIndex == 1)
      val rhsOpt = pa.argument.l.find(_.argumentIndex == 2)
      lhs match {
        case Some(c: nodes.Call) if c.name == "<operator>.fieldAccess" =>
          val propName = c.argument.l.find(_.argumentIndex == 2) match {
            case Some(fi: nodes.FieldIdentifier) => fi.canonicalName
            case Some(other) => other.code
            case None => "<unknown-property>"
          }
          rhsOpt match {
            case Some(rhs) => (propName, resolveExportRhs(rhs, scopeMethod))
            case None => (propName, Left("UNRESOLVED_RHS_SHAPE"))
          }
        case Some(c: nodes.Call) if c.name == "<operator>.indexAccess" =>
          ("<computed-property>", Left("COMPUTED_OBJECT_LITERAL_PROPERTY_KEY"))
        case _ =>
          ("<unknown-property>", Left("UNRESOLVED_RHS_SHAPE"))
      }
    }
  }

  case class ExportedFn(method: nodes.Method, exportName: String)
  val exportedFns = scala.collection.mutable.ListBuffer[ExportedFn]()
  val exportedClasses = scala.collection.mutable.ListBuffer[(nodes.TypeDecl, String)]()

  def registerResolution(exportName: String, res: ExportResolution): Unit = res match {
    case SingleFunction(m) => exportedFns += ExportedFn(m, exportName)
    case ClassExport(td) =>
      exportedClasses += ((td, exportName))
      td.method.filterNot(_.name == "<init>").l.foreach { m =>
        exportedFns += ExportedFn(m, s"$exportName.prototype.${m.name}")
      }
  }

  val namedExportLhs = "^(module\\.exports|exports)\\.[A-Za-z_$][A-Za-z0-9_$]*$".r
  val exportAssigns = cpg.call.name("<operator>.assignment").l.filter { a =>
    val lhsCode = a.argument.l.find(_.argumentIndex == 1).map(_.code.trim).getOrElse("")
    lhsCode == "module.exports" || namedExportLhs.matches(lhsCode) ||
    a.argument.l.find(_.argumentIndex == 1).exists {
      case c: nodes.Call => c.name == "<operator>.indexAccess" &&
        c.argument.l.find(_.argumentIndex == 1).exists(b => b.code.trim == "module.exports" || b.code.trim == "exports")
      case _ => false
    }
  }
  exportAssigns.foreach { a =>
    val lhsExpr = a.argument.l.find(_.argumentIndex == 1).get
    val rhsExpr = a.argument.l.find(_.argumentIndex == 2).get
    val lhsCode = lhsExpr.code.trim
    val (exportNameOpt, dynamicKey) = lhsExpr match {
      case c: nodes.Call if c.name == "<operator>.indexAccess" =>
        c.argument.l.find(_.argumentIndex == 2) match {
          case Some(lit: nodes.Literal) =>
            val unquoted = lit.code.trim.stripPrefix("\"").stripPrefix("'").stripSuffix("\"").stripSuffix("'")
            (Some(unquoted), false)
          case _ => (None, true)
        }
      case _ if lhsCode == "module.exports" => (Some("module.exports"), false)
      case _ => (Some(lhsCode.split("\\.").last), false)
    }
    if (dynamicKey) {
      exportAbstentions += ((lhsCode, "DYNAMIC_COMPUTED_EXPORT_KEY"))
    } else {
      val exportName = exportNameOpt.getOrElse("<unknown>")
      rhsExpr match {
        case blk: nodes.Block =>
          val results = resolveObjectLiteralExport(blk, a.method)
          if (results.isEmpty) {
            exportAbstentions += ((lhsCode, "UNRESOLVED_RHS_SHAPE"))
          } else {
            results.foreach {
              case (propName, Right(res)) => registerResolution(propName, res)
              case (propName, Left(reason)) => exportAbstentions += ((s"$lhsCode.$propName", reason))
            }
          }
        case _ =>
          resolveExportRhs(rhsExpr, a.method) match {
            case Right(res) => registerResolution(exportName, res)
            case Left(reason) => exportAbstentions += ((lhsCode, reason))
          }
      }
    }
  }
  val distinctExportedFns = exportedFns.toList.groupBy(_.method.id).values.map(_.head).toList
  System.err.println(s"R04 PACKAGE_API_INPUT exported functions resolved: ${distinctExportedFns.size} " +
    s"(${distinctExportedFns.map(e => s"${e.exportName}@${e.method.name}").mkString(",")})")
  System.err.println(s"R04 PACKAGE_API_INPUT exported classes resolved: ${exportedClasses.size} " +
    s"(${exportedClasses.map { case (td, n) => s"$n=${td.name}" }.mkString(",")})")
  if (exportAbstentions.nonEmpty) {
    System.err.println(s"R04 PACKAGE_API_INPUT export ABSTENTIONS (${exportAbstentions.size}): " +
      exportAbstentions.map { case (lhs, reason) => s"$lhs=$reason" }.mkString(" | "))
  }

  val packageApiParamSources: List[nodes.Expression] = distinctExportedFns.flatMap { e =>
    e.method.parameter.filter(_.name != "this").l.flatMap { p =>
      p.method.ast.isIdentifier.name(p.name).l.map(id => id: nodes.Expression)
    }
  }.distinct

  // ===== Capability 3: constructor parameter -> exact this.field identity -> method-use
  // propagation (verbatim port, see export_redos_npm_integ_r02.sc for the full rationale) =====
  val thisFieldAbstentions = scala.collection.mutable.ListBuffer[(String, String)]()
  val thisFieldSources = scala.collection.mutable.ListBuffer[nodes.Expression]()

  def collectFieldAccessChain(base: nodes.Expression, container: nodes.Method): List[nodes.Expression] = {
    val parents = container.ast.isCall.l.filter { c =>
      (c.name == "<operator>.fieldAccess" || c.name == "<operator>.indexAccess") &&
      c.argument.l.find(_.argumentIndex == 1).exists(_.id == base.id)
    }
    base :: parents.flatMap(p => collectFieldAccessChain(p: nodes.Expression, container))
  }

  def findThisFieldAssigns(td: nodes.TypeDecl): List[(String, nodes.Method, nodes.Call)] = {
    td.method.l.flatMap { m =>
      m.ast.isCall.name("<operator>.assignment").l.flatMap { a =>
        a.argument.l.find(_.argumentIndex == 1) match {
          case Some(fa: nodes.Call) if fa.name == "<operator>.fieldAccess" =>
            val recvIsThis = fa.argument.l.find(_.argumentIndex == 1).exists {
              case idn: nodes.Identifier => idn.code.trim == "this"
              case _ => false
            }
            val fieldNameOpt = fa.argument.l.find(_.argumentIndex == 2) match {
              case Some(fi: nodes.FieldIdentifier) => Some(fi.canonicalName)
              case _ => None
            }
            if (recvIsThis) fieldNameOpt.map(fn => (fn, m, a)) else None
          case _ => None
        }
      }
    }
  }

  exportedClasses.toList.groupBy(_._1.fullName).values.map(_.head).foreach { case (td, exportName) =>
    val ctorOpt = td.method.name("<init>").l match {
      case c :: Nil => Some(c)
      case _ => None
    }
    ctorOpt.foreach { ctor =>
      val ctorParamNames = ctor.parameter.filter(_.name != "this").name.toSet
      val allFieldAssigns = findThisFieldAssigns(td)
      val byField = allFieldAssigns.groupBy(_._1)
      byField.foreach { case (fieldName, sites) =>
        if (sites.size > 1) {
          thisFieldAbstentions += ((s"$exportName.this.$fieldName", "REASSIGNED_THIS_FIELD"))
        } else {
          val (_, ownerMethod, assignCall) = sites.head
          if (ownerMethod.fullName != ctor.fullName) {
            thisFieldAbstentions += ((s"$exportName.this.$fieldName", "NON_CONSTRUCTOR_THIS_FIELD_ASSIGNMENT"))
          } else {
            assignCall.argument.l.find(_.argumentIndex == 2) match {
              case Some(rhsId: nodes.Identifier) if ctorParamNames.contains(rhsId.name) =>
                val paramReassigns = ctor.ast.isCall.name("<operator>.assignment").l.filter { a2 =>
                  a2.method.fullName == ctor.fullName &&
                  a2.argument.l.find(_.argumentIndex == 1).exists {
                    case lhsId: nodes.Identifier => lhsId.name == rhsId.name
                    case _ => false
                  }
                }
                if (paramReassigns.size > 1) {
                  thisFieldAbstentions += ((s"$exportName.this.$fieldName", "MULTIPLE_LIVE_ASSIGNMENTS_TO_IDENTIFIER"))
                } else {
                  td.method.filterNot(m => m.name == "<init>").l.foreach { otherM =>
                    otherM.ast.isCall.name("<operator>.fieldAccess").l.foreach { fa =>
                      val recvIsThis = fa.argument.l.find(_.argumentIndex == 1).exists {
                        case idn: nodes.Identifier => idn.code.trim == "this"
                        case _ => false
                      }
                      val isField = fa.argument.l.find(_.argumentIndex == 2).exists {
                        case fi: nodes.FieldIdentifier => fi.canonicalName == fieldName
                        case _ => false
                      }
                      if (recvIsThis && isField) thisFieldSources ++= collectFieldAccessChain(fa: nodes.Expression, otherM)
                    }
                  }
                }
              case Some(_) =>
                thisFieldAbstentions += ((s"$exportName.this.$fieldName", "COMPUTED_THIS_FIELD_ASSIGNMENT"))
              case None =>
                thisFieldAbstentions += ((s"$exportName.this.$fieldName", "UNRESOLVED_RHS_SHAPE"))
            }
          }
        }
      }
    }
  }
  val distinctThisFieldSources = thisFieldSources.toList.distinct
  if (thisFieldAbstentions.nonEmpty) {
    System.err.println(s"R04 this-field ABSTENTIONS (${thisFieldAbstentions.size}): " +
      thisFieldAbstentions.map { case (name, reason) => s"$name=$reason" }.mkString(" | "))
  }

  val packageApiSources: List[nodes.Expression] =
    (packageApiParamSources ++ distinctThisFieldSources).distinct
  System.err.println(s"R04 PACKAGE_API_INPUT source candidates (total, params + this-fields): ${packageApiSources.size}")

  // ===== combine: batched reachability per sink per family (ReDoS's own proven at-scale
  // technique -- one reachableByFlows(sources.iterator) call per sink, not one call per
  // individual (sink, source) pair), never .headOption anywhere =====
  case class Considered(sinkId: String, sinkLine: String, srcId: String, srcLine: String,
                        srcCode: String, family: String, hasFlow: Boolean, flowCount: Int)
  val considered = scala.collection.mutable.ListBuffer[Considered]()

  def runFamily(family: String, sources: List[nodes.Expression]): Unit = {
    if (sources.isEmpty) return
    sinks.foreach { sk =>
      val flows = scala.util.Try {
        cpg.all.id(sk.id).collectAll[nodes.Expression].reachableByFlows(sources.iterator).l
      }.getOrElse(Nil)
      val flowCountBySrc = scala.collection.mutable.Map[String, Int]().withDefaultValue(0)
      flows.foreach { f => f.elements.headOption.foreach(o => flowCountBySrc(o.id.toString) += 1) }
      val sinkLine = sk.lineNumber.map(_.toString).getOrElse("0")
      sources.foreach { s =>
        val cnt = flowCountBySrc(s.id.toString)
        considered += Considered(sk.id.toString, sinkLine, s.id.toString,
          s.lineNumber.map(_.toString).getOrElse("0"), Option(s.code).getOrElse(""),
          family, cnt > 0, cnt)
      }
    }
  }
  runFamily("PACKAGE_API_INPUT", packageApiSources)
  runFamily("APPLICATION_INGRESS_INPUT", ingressSources)

  // ===== write output =====
  val sf = new java.io.PrintWriter(new java.io.File(s"$rawDir/source_facts.tsv"), "UTF-8")
  val pr = new java.io.PrintWriter(new java.io.File(s"$rawDir/propagation_relations.tsv"), "UTF-8")
  val ev = new java.io.PrintWriter(new java.io.File(s"$rawDir/npm_public_export_evidence.tsv"), "UTF-8")
  considered.foreach { c =>
    ev.println(Seq(c.sinkId, c.sinkLine, c.srcId, c.srcLine, c.srcCode, c.family,
      c.hasFlow.toString, c.flowCount.toString).mkString("\t"))
    if (c.hasFlow) {
      // source_facts (12 cols): sink, sink_line, source, origin_family, status, +7 pad --
      // origin_family in column 3, matching adjudicate_js.py's own established
      // srcf[0][3]/"origin_family" convention (the shared schema ReDoS's own producers use).
      sf.println((Seq(c.sinkId, c.sinkLine, c.srcId, c.family, "ESTABLISHED") ++ Seq.fill(7)("")).mkString("\t"))
      pr.println(Seq(c.sinkId, "", "", c.srcId, c.srcLine, c.srcCode, "", "", "").mkString("\t"))
    }
  }
  sf.close(); pr.close(); ev.close()
  new java.io.PrintWriter(new java.io.File(s"$rawDir/transform_identity.tsv"), "UTF-8").close()
  new java.io.PrintWriter(new java.io.File(s"$rawDir/definition_resolution.tsv"), "UTF-8").close()

  val flowingRows = considered.count(_.hasFlow)
  System.err.println(s"NPM_PUBLIC_EXPORT_SOURCES_R04 ok: sinks=${sinks.size} " +
    s"package_api_sources=${packageApiSources.size} ingress_sources=${ingressSources.size} " +
    s"considered=${considered.size} flowing=$flowingRows " +
    s"(package_api=${considered.count(c => c.hasFlow && c.family == "PACKAGE_API_INPUT")}, " +
    s"ingress=${considered.count(c => c.hasFlow && c.family == "APPLICATION_INGRESS_INPUT")})")
}
