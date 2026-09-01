// NPM-SOURCE-IDENTITY-R01 — property-neutral shared "npm source identity" infrastructure.
//
// This producer is NOT a vulnerability detector for any specific property (no regex/fs/serialize
// vocabulary anywhere in this file). It answers three property-neutral questions any future
// property reducer can build on by reading its OWN output facts (never by importing this file's
// own logic):
//   1. What does this package's own source actually EXPOSE as public API (export surface)?
//   2. For a given identifier reference, what is its REAL resolved variable identity (a direct
//      local, a value captured from an outer lexical scope, or genuinely ambiguous)?
//   3. For a given candidate "value came from here" site, which property-neutral origin
//      family/families reach it (never collapsed to one when more than one really applies)?
//
// Grounding (read, never modified, per direct instruction):
//   - export_redos_npm_integ.sc's `resolveExportRhs` (CommonJS + ESM named/default export
//     resolution via MethodRef/single-prior-assignment identity) and its req/request
//     APPLICATION_INGRESS literal-pattern source model -- both semantics are RE-DERIVED here
//     (not imported), generalized to be sink-vocabulary-free.
//   - export_redos_npm_integ_r02.sc's class-export (capability 1), object-literal-shorthand
//     export (capability 2) resolution shapes are reused conceptually. R02's own `resolvePatternR02`
//     lexical walk (a `Method.astParent` name-matching approximation) is explicitly NOT reused --
//     this file's own `resolveClosureIdentity` (below) replaces that approach with the real
//     `refsTo`/`closureBindingId`/`ClosureBinding` primitives, generalized from
//     export_fail_open_candidates.sc's own `exactHandlerDefinition`, in two real ways confirmed by
//     direct CPG inspection before this code was written (see
//     docs/milestones/NPM_SOURCE_IDENTITY_R01_IMPLEMENTATION.md for the real, quoted probe output):
//       (a) `exactHandlerDefinition` follows exactly ONE `closureBindingId` hop. A real CPG of
//           motifer-26.1.1 (a genuine 2-level-nested closure) and of this file's own
//           `cap1_two_level_nested_capture.js`/`ambiguous_closure_reassignment.js` fixtures
//           (a real 3-level and 2-level chain respectively) confirmed a captured Local's own
//           `closureBindingId` can point to ANOTHER proxy Local (itself still carrying its own
//           `closureBindingId`), not directly to the true origin -- so this resolver walks the
//           chain RECURSIVELY until `closureBindingId` is `None`, never stopping after one hop.
//       (b) `exactHandlerDefinition`'s own `_refOut.collect { case l: nodes.Local => l }` only
//           ever considers a `Local` as a capture target. A real CPG confirmed a captured
//           FUNCTION PARAMETER (not just a `let`/`const`/`var`) also participates in closure
//           capture, and its own `ClosureBinding._refOut` resolves DIRECTLY to a
//           `MethodParameterIn` node, never a proxy `Local` -- confirmed via a direct probe
//           against a minimal `function handler(req) { return function inner(){ return
//           req.body; }; }` fixture (`cb closureBindingId=...req refOut=List((...,
//           METHOD_PARAMETER_IN))`). This resolver's own root type is therefore `Local` OR
//           `MethodParameterIn`, never `Local` only.
//   - export_sourcefact.sc's `multi_origin`/`origin_count` denormalized-column precedent for
//     "more than one reaching origin family -> emit one row per family, never collapse."
//
// ============================== OUTPUT SCHEMAS (rawDir) ==============================
//
// export_surface.tsv (10 columns) -- every `module.exports`/`exports` assignment target this
// producer inspected, resolved or honestly abstained:
//   export_id       -- "<assignCallId>#<subIndex>", stable and unique per (assignment, sub-export)
//   file            -- real source file path (Joern's own `.filename`, never a synthetic path)
//   line            -- line number of the assignment
//   export_lhs      -- the assignment's own LHS source text (e.g. "module.exports", "exports.foo")
//   export_name     -- the resolved export NAME (property name; ".prototype.NAME" for a class's
//                       own instance method; ".<init>" for an abstained constructor row)
//   rhs_kind        -- MODULE_EXPORTS_ASSIGN | NAMED_EXPORT_ASSIGN | OBJECT_LITERAL_PROPERTY |
//                       CLASS_INSTANCE_METHOD | CLASS_CONSTRUCTOR
//   resolution_status -- RESOLVED | ABSTAINED
//   target_method_id       -- resolved Method node id, or empty if ABSTAINED
//   target_method_full_name -- resolved Method's own fullName, or empty if ABSTAINED
//   abstain_reason  -- one of: CLASS_CONSTRUCTOR_NOT_PUBLIC_API, METHODREF_TARGET_NOT_FOUND,
//                       MULTIPLE_CANDIDATE_CONSTRUCTORS, AMBIGUOUS_METHODREF_TARGET_MULTIPLE_METHODS,
//                       DYNAMIC_COMPUTED_EXPORT_KEY,
//                       COMPUTED_OBJECT_LITERAL_PROPERTY_KEY, REEXPORT_UNRESOLVED,
//                       UNRESOLVED_IDENTIFIER_NO_METHODREF_ASSIGNMENT,
//                       AMBIGUOUS_IDENTIFIER_MULTIPLE_METHODREF_ASSIGNMENTS,
//                       AMBIGUOUS_EXPORT_IDENTIFIER_BINDING:<note>,
//                       UNRESOLVED_EXPORT_IDENTIFIER_BINDING:<note>, UNRESOLVED_RHS_SHAPE
//                       (empty when RESOLVED)
//
// closure_identity.tsv (10 columns) -- the REAL resolved identity of every identifier reference
// that refs a Local or a MethodParameterIn (i.e. every real variable/parameter read or write):
//   identifier_id, file, line, method_full_name, identifier_code,
//   resolution_kind   -- DIRECT | CAPTURED | AMBIGUOUS | UNRESOLVED
//   resolved_root_id, resolved_root_name, resolved_root_kind (LOCAL|METHOD_PARAMETER_IN, or empty),
//   capture_depth     -- number of closureBindingId hops walked to reach the root (0 for DIRECT)
//   note              -- abstain/diagnostic detail (empty when cleanly resolved)
//
// source_origin_facts.tsv (9 columns) -- one row per (candidate source site, origin_family) pair,
// NEVER collapsed when more than one family reaches the same site:
//   site_id           -- the source CPG node's own id (an Identifier or a fieldAccess Call)
//   file, line, site_code
//   origin_family     -- PACKAGE_API_INPUT | APPLICATION_INGRESS_INPUT
//   family_detail     -- e.g. "exported_param handleRequest.req" or "req/request field-access"
//   multi_origin      -- true|false -- denormalized onto EVERY row for this site (never requires
//                         a second pass to discover)
//   origin_count      -- total distinct origin_family values reaching this exact site
//
// All three files are written SORTED (by a stable, id-derived key -- never by Scala Set/Map
// iteration order), so rerunning this producer on the SAME cpg file byte-for-byte reproduces the
// same output. Verified directly (see the milestone doc's "Determinism" section): two independent
// runs against the same real fixture CPG, diffed byte-for-byte, zero differences.
//
// APPLICATION_INGRESS_INPUT source model (re-derived, not imported, from
// export_redos_npm_integ.sc's own `SOURCE_PATTERN` -- the `(message|item)` Meteor/RocketChat-
// specific half of that file's own model is deliberately NOT re-derived here, since it is
// sink-adjacent application vocabulary out of this property-neutral producer's own scope):
//   (a) any `<operator>.fieldAccess` Call whose own code matches
//       `(req|request)\.(body|query|params|headers|payload|url)(\..*)?`
//   (b) any BARE `req`/`request` Identifier reference (this is what makes MULTIPLE_ORIGINS a real,
//       observable outcome: an exported function whose own parameter happens to be named `req` and
//       is used directly -- e.g. `function h(req) { return req; }` -- has that one Identifier node
//       simultaneously satisfy PACKAGE_API_INPUT (a reference to this package's own exported-
//       function parameter) AND APPLICATION_INGRESS_INPUT (the bare-name convention above); see
//       `fixtures/npm_source_identity_r01/src/cap4_multiple_origins.js`).
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes

@main def exec(cpgFile: String, rawDir: String, srcLabel: String) = {
  importCpg(cpgFile)
  new java.io.File(rawDir).mkdirs()

  def cl(s: String): String = Option(s).getOrElse("").replace("\t", " ").replace("\n", " ").take(500)
  def fileOf(n: nodes.AstNode): String = cl(Option(n.file.name.headOption.getOrElse("")).getOrElse(""))
  def lineOf(n: nodes.AstNode): String = n match {
    case c: nodes.CfgNode => c.lineNumber.map(_.toString).getOrElse("")
    case _ => ""
  }

  val SOURCE_PATTERN = "(req|request)\\.(body|query|params|headers|payload|url)(\\..*)?"

  // ============================== closure identity resolution ==============================
  // Generalizes export_fail_open_candidates.sc's own `exactHandlerDefinition` -- see this file's
  // own header comment for the two real, CPG-confirmed generalizations (recursive chain-walk;
  // MethodParameterIn as a valid capture root, not only Local).
  case class ClosureIdentity(kind: String, rootId: String, rootName: String, rootKind: String,
                              captureDepth: Int, note: String)

  def isDeclNode(n: nodes.StoredNode): Boolean = n.isInstanceOf[nodes.Local] || n.isInstanceOf[nodes.MethodParameterIn]

  def closureBindingRoot(local: nodes.Local, depth: Int, seen: Set[Long]): Either[String, (nodes.StoredNode, Int)] = {
    if (depth > 64) Left("CLOSURE_CHAIN_DEPTH_EXCEEDED")
    else if (seen.contains(local.id)) Left("CLOSURE_CHAIN_CYCLE_DETECTED")
    else local.closureBindingId match {
      case None => Right((local, depth))
      case Some(cbid) =>
        val refOutTargets = cpg.all.collectAll[nodes.ClosureBinding].l
          .filter(_.closureBindingId.contains(cbid))
          .flatMap(_._refOut.l)
          .distinctBy(_.id)
        refOutTargets match {
          case Nil => Left("CLOSURE_BINDING_TARGET_NOT_FOUND")
          case (nextLocal: nodes.Local) :: Nil => closureBindingRoot(nextLocal, depth + 1, seen + local.id)
          case (p: nodes.MethodParameterIn) :: Nil => Right((p, depth + 1))
          case single :: Nil => Left(s"CLOSURE_BINDING_TARGET_UNSUPPORTED_TYPE:${single.label}")
          case _ => Left("AMBIGUOUS_CLOSURE_BINDING_MULTIPLE_TARGETS")
        }
    }
  }

  def rootKindOf(n: nodes.StoredNode): String = n match {
    case _: nodes.Local => "LOCAL"
    case _: nodes.MethodParameterIn => "METHOD_PARAMETER_IN"
    case _ => "UNKNOWN"
  }
  def rootNameOf(n: nodes.StoredNode): String = n match {
    case l: nodes.Local => l.name
    case p: nodes.MethodParameterIn => p.name
    case _ => ""
  }

  def resolveClosureIdentity(identifier: nodes.Identifier): ClosureIdentity = {
    val targets = identifier.refsTo.l.distinctBy(_.id).filter(isDeclNode)
    targets match {
      case Nil => ClosureIdentity("UNRESOLVED", "", "", "", -1, "NO_REF_TARGET")
      case _ :: _ :: _ => ClosureIdentity("AMBIGUOUS", "", "", "", -1, "MULTIPLE_REFS_TO_DISTINCT_DECLARATIONS")
      case (p: nodes.MethodParameterIn) :: Nil =>
        ClosureIdentity("DIRECT", p.id.toString, p.name, "METHOD_PARAMETER_IN", 0, "")
      case (l: nodes.Local) :: Nil =>
        closureBindingRoot(l, 0, Set.empty) match {
          case Left(reason) => ClosureIdentity("AMBIGUOUS", "", "", "", -1, reason)
          case Right((root, depth)) =>
            val kind = if (depth == 0) "DIRECT" else "CAPTURED"
            ClosureIdentity(kind, root.id.toString, rootNameOf(root), rootKindOf(root), depth, "")
        }
      case _ => ClosureIdentity("UNRESOLVED", "", "", "", -1, "UNSUPPORTED_REF_TARGET_TYPE")
    }
  }

  // Real, identity-based (never text/name-matching) reassignment-ambiguity check: more than one
  // assignment call whose LHS identifier's own `refsTo` resolves to this EXACT resolved Local
  // (never a same-named but structurally different Local elsewhere) means more than one live
  // candidate binding -- abstain, never guess which one is "the real" value. Scoped to assignments
  // made directly in the root's own declaring method (an assignment made INSIDE a nested closure
  // targets that closure's own captured proxy Local, a different id, and is correctly not counted
  // here -- a disclosed, real scope boundary, not a silent gap: see the milestone doc).
  def multipleLiveAssignments(rootId: Long, declaringMethod: nodes.Method): Boolean = {
    val assigns = declaringMethod.ast.isCall.name("<operator>.assignment").l.filter { a =>
      a.argument.l.find(_.argumentIndex == 1).exists {
        case li: nodes.Identifier => li.refsTo.id.l.contains(rootId)
        case _ => false
      }
    }
    assigns.size > 1
  }

  // Re-derive the closure identity, additionally folding in the reassignment-ambiguity check
  // above -- used by BOTH the closure_identity.tsv emission and export-identifier resolution, so
  // the two tables never disagree about the same identifier's own identity.
  def resolveIdentity(identifier: nodes.Identifier): ClosureIdentity = {
    val base = resolveClosureIdentity(identifier)
    if (base.kind != "DIRECT" && base.kind != "CAPTURED") base
    else if (base.rootKind != "LOCAL") base
    else {
      val rootId = base.rootId.toLong
      val declaringMethod: Option[nodes.Method] = cpg.local.id(rootId).method.headOption
      declaringMethod match {
        case Some(dm) if multipleLiveAssignments(rootId, dm) =>
          ClosureIdentity("AMBIGUOUS", "", "", "", -1, "MULTIPLE_LIVE_ASSIGNMENTS_TO_RESOLVED_LOCAL")
        case _ => base
      }
    }
  }

  // ============================== export-surface resolution ==============================
  def isRequireLikeExpr(e: nodes.Expression): Boolean = e match {
    case c: nodes.Call => c.name == "require" || c.code.trim.startsWith("require(")
    case _ => false
  }

  def resolveMethodRefTarget(ref: nodes.MethodRef, fallbackName: String): List[(String, String, Either[String, nodes.Method])] = {
    cpg.method.fullName(ref.methodFullName).l match {
      case Nil => List((fallbackName, "MODULE_EXPORTS_ASSIGN", Left("METHODREF_TARGET_NOT_FOUND")))
      case m :: Nil if m.name == "<init>" =>
        m.typeDecl.l match {
          case td :: Nil =>
            if (td.method.name("<init>").l.size > 1) {
              List((fallbackName, "CLASS_CONSTRUCTOR", Left("MULTIPLE_CANDIDATE_CONSTRUCTORS")))
            } else {
              val ctorRow = (s"$fallbackName.<init>", "CLASS_CONSTRUCTOR", Left("CLASS_CONSTRUCTOR_NOT_PUBLIC_API"))
              val methodRows = td.method.filterNot(_.name == "<init>").l.sortBy(_.name).map { mm =>
                (s"$fallbackName.prototype.${mm.name}", "CLASS_INSTANCE_METHOD", Right(mm))
              }
              ctorRow :: methodRows
            }
          case Nil => List((fallbackName, "CLASS_CONSTRUCTOR", Left("CLASS_CONSTRUCTOR_NOT_PUBLIC_API")))
          case _ => List((fallbackName, "CLASS_CONSTRUCTOR", Left("MULTIPLE_CANDIDATE_CONSTRUCTORS")))
        }
      case m :: Nil => List((fallbackName, "MODULE_EXPORTS_ASSIGN", Right(m)))
      // NOT a constructor case (that's handled above) -- more than one Method shares this exact
      // methodFullName, an unrelated ambiguity. Own distinct reason code: reusing
      // MULTIPLE_CANDIDATE_CONSTRUCTORS here would mislead a future consumer grepping abstain
      // reasons into thinking every such row is a real constructor ambiguity (pre-merge polish,
      // never reachable as RESOLVED either way -- always an abstain, so purely a labeling fix).
      case _ => List((fallbackName, "MODULE_EXPORTS_ASSIGN", Left("AMBIGUOUS_METHODREF_TARGET_MULTIPLE_METHODS")))
    }
  }

  def resolveIdentifierTarget(id: nodes.Identifier, fallbackName: String): List[(String, String, Either[String, nodes.Method])] = {
    val identity = resolveIdentity(id)
    identity.kind match {
      case "AMBIGUOUS" => List((fallbackName, "NAMED_EXPORT_ASSIGN", Left(s"AMBIGUOUS_EXPORT_IDENTIFIER_BINDING:${identity.note}")))
      case "UNRESOLVED" => List((fallbackName, "NAMED_EXPORT_ASSIGN", Left(s"UNRESOLVED_EXPORT_IDENTIFIER_BINDING:${identity.note}")))
      case _ =>
        val rootId = identity.rootId.toLong
        val assignsToRoot = cpg.call.name("<operator>.assignment").l.filter { a =>
          a.argument.l.find(_.argumentIndex == 1).exists {
            case li: nodes.Identifier => li.refsTo.id.l.contains(rootId)
            case _ => false
          }
        }
        val methodRefAssigns = assignsToRoot.filter(a => a.argument.l.find(_.argumentIndex == 2).exists(_.isInstanceOf[nodes.MethodRef]))
        val requireAssigns = assignsToRoot.filter(a => a.argument.l.find(_.argumentIndex == 2).exists(isRequireLikeExpr))
        methodRefAssigns.size match {
          case 1 =>
            val ref = methodRefAssigns.head.argument.l.find(_.argumentIndex == 2).get.asInstanceOf[nodes.MethodRef]
            resolveMethodRefTarget(ref, fallbackName)
          case 0 =>
            if (requireAssigns.nonEmpty) List((fallbackName, "NAMED_EXPORT_ASSIGN", Left("REEXPORT_UNRESOLVED")))
            else if (assignsToRoot.isEmpty) List((fallbackName, "NAMED_EXPORT_ASSIGN", Left("UNRESOLVED_IDENTIFIER_NO_METHODREF_ASSIGNMENT")))
            else List((fallbackName, "NAMED_EXPORT_ASSIGN", Left("UNRESOLVED_RHS_SHAPE")))
          case _ => List((fallbackName, "NAMED_EXPORT_ASSIGN", Left("AMBIGUOUS_IDENTIFIER_MULTIPLE_METHODREF_ASSIGNMENTS")))
        }
    }
  }

  def resolveObjectLiteralExport(blk: nodes.Block, fallbackName: String): List[(String, String, Either[String, nodes.Method])] = {
    val propAssigns = blk.astChildren.isCall.name("<operator>.assignment").l
    propAssigns.flatMap { pa =>
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
            case Some(rhs) => resolveExportRhs(rhs, propName)
            case None => List((propName, "OBJECT_LITERAL_PROPERTY", Left("UNRESOLVED_RHS_SHAPE")))
          }
        case Some(c: nodes.Call) if c.name == "<operator>.indexAccess" =>
          List((s"$fallbackName.<computed-property>", "OBJECT_LITERAL_PROPERTY", Left("COMPUTED_OBJECT_LITERAL_PROPERTY_KEY")))
        case _ => List((s"$fallbackName.<unknown-property>", "OBJECT_LITERAL_PROPERTY", Left("UNRESOLVED_RHS_SHAPE")))
      }
    }
  }

  def resolveExportRhs(rhs: nodes.Expression, fallbackName: String): List[(String, String, Either[String, nodes.Method])] = rhs match {
    case ref: nodes.MethodRef => resolveMethodRefTarget(ref, fallbackName)
    case id: nodes.Identifier => resolveIdentifierTarget(id, fallbackName)
    case blk: nodes.Block => resolveObjectLiteralExport(blk, fallbackName)
    case c: nodes.Call if isRequireLikeExpr(c) => List((fallbackName, "NAMED_EXPORT_ASSIGN", Left("REEXPORT_UNRESOLVED")))
    case _ => List((fallbackName, "NAMED_EXPORT_ASSIGN", Left("UNRESOLVED_RHS_SHAPE")))
  }

  case class ExportRow(exportId: String, file: String, line: String, exportLhs: String, exportName: String,
                        rhsKind: String, status: String, methodId: String, methodFullName: String, abstainReason: String)
  val exportRows = scala.collection.mutable.ListBuffer[ExportRow]()
  val exportedFns = scala.collection.mutable.ListBuffer[(String, nodes.Method)]()

  val exportAssigns = cpg.call.name("<operator>.assignment").l.filter { a =>
    a.argument.l.find(_.argumentIndex == 1).exists {
      case c: nodes.Call if c.code.trim == "module.exports" => true
      case c: nodes.Call if c.name == "<operator>.fieldAccess" || c.name == "<operator>.indexAccess" =>
        c.argument.l.find(_.argumentIndex == 1).exists(r => r.code.trim == "module.exports" || r.code.trim == "exports")
      case other => other.code.trim == "module.exports"
    }
  }
  exportAssigns.foreach { a =>
    val lhsExpr = a.argument.l.find(_.argumentIndex == 1).get
    val rhsExpr = a.argument.l.find(_.argumentIndex == 2).get
    val lhsCode = lhsExpr.code.trim
    val (exportNameOpt, dynamicKey) = lhsExpr match {
      case c: nodes.Call if c.code.trim == "module.exports" => (Some("module.exports"), false)
      case c: nodes.Call if c.name == "<operator>.indexAccess" =>
        c.argument.l.find(_.argumentIndex == 2) match {
          case Some(lit: nodes.Literal) =>
            (Some(lit.code.trim.stripPrefix("\"").stripPrefix("'").stripSuffix("\"").stripSuffix("'")), false)
          case _ => (None, true)
        }
      case c: nodes.Call if c.name == "<operator>.fieldAccess" =>
        c.argument.l.find(_.argumentIndex == 2) match {
          case Some(fi: nodes.FieldIdentifier) => (Some(fi.canonicalName), false)
          case Some(other) => (Some(other.code), false)
          case None => (Some("<unknown>"), false)
        }
      case _ => (Some("module.exports"), false)
    }
    val results: List[(String, String, Either[String, nodes.Method])] =
      if (dynamicKey) List(("<dynamic>", "NAMED_EXPORT_ASSIGN", Left("DYNAMIC_COMPUTED_EXPORT_KEY")))
      else resolveExportRhs(rhsExpr, exportNameOpt.getOrElse("<unknown>"))
    results.zipWithIndex.foreach { case ((exportName, rhsKind, res), idx) =>
      res match {
        case Right(m) =>
          exportedFns += ((exportName, m))
          exportRows += ExportRow(s"${a.id}#$idx", fileOf(a), lineOf(a), lhsCode, exportName, rhsKind,
            "RESOLVED", m.id.toString, cl(m.fullName), "")
        case Left(reason) =>
          exportRows += ExportRow(s"${a.id}#$idx", fileOf(a), lineOf(a), lhsCode, exportName, rhsKind,
            "ABSTAINED", "", "", reason)
      }
    }
  }
  val distinctExportedFns = exportedFns.toList.groupBy { case (n, m) => (n, m.id) }.values.map(_.head).toList

  System.err.println(s"[$srcLabel] export_surface rows: ${exportRows.size} " +
    s"(resolved=${exportRows.count(_.status == "RESOLVED")}, abstained=${exportRows.count(_.status == "ABSTAINED")})")

  // ============================== closure_identity.tsv ==============================
  case class IdentityRow(identifierId: String, file: String, line: String, methodFullName: String,
                          identifierCode: String, kind: String, rootId: String, rootName: String,
                          rootKind: String, captureDepth: String, note: String)
  val identityRows = scala.collection.mutable.ListBuffer[IdentityRow]()
  val allIdentifiers = cpg.identifier.l
  allIdentifiers.foreach { i =>
    val refTargets = i.refsTo.l.filter(isDeclNode)
    if (refTargets.nonEmpty) {
      val res = resolveIdentity(i)
      identityRows += IdentityRow(i.id.toString, fileOf(i), lineOf(i), cl(i.method.fullName), cl(i.code),
        res.kind, res.rootId, cl(res.rootName), res.rootKind,
        if (res.captureDepth >= 0) res.captureDepth.toString else "", res.note)
    }
  }
  System.err.println(s"[$srcLabel] closure_identity rows: ${identityRows.size} " +
    s"(DIRECT=${identityRows.count(_.kind == "DIRECT")}, CAPTURED=${identityRows.count(_.kind == "CAPTURED")}, " +
    s"AMBIGUOUS=${identityRows.count(_.kind == "AMBIGUOUS")}, UNRESOLVED=${identityRows.count(_.kind == "UNRESOLVED")})")

  // ============================== source_origin_facts.tsv ==============================
  case class SiteHit(family: String, detail: String)
  val siteHits = scala.collection.mutable.LinkedHashMap[String, scala.collection.mutable.ListBuffer[SiteHit]]()
  val siteMeta = scala.collection.mutable.LinkedHashMap[String, (String, String, String)]() // file, line, code

  def addHit(siteId: String, meta: (String, String, String), family: String, detail: String): Unit = {
    siteMeta.getOrElseUpdate(siteId, meta)
    val buf = siteHits.getOrElseUpdate(siteId, scala.collection.mutable.ListBuffer.empty)
    if (!buf.exists(_.family == family)) buf += SiteHit(family, detail)
  }

  // PACKAGE_API_INPUT: every identifier reference whose REAL resolved identity root is exactly
  // one of a resolved exported function/method's own (non-`this`) parameters.
  distinctExportedFns.foreach { case (exportName, m) =>
    m.parameter.filter(_.name != "this").l.foreach { p =>
      cpg.identifier.name(p.name).l.foreach { i =>
        val res = resolveIdentity(i)
        if ((res.kind == "DIRECT" || res.kind == "CAPTURED") && res.rootKind == "METHOD_PARAMETER_IN" && res.rootId == p.id.toString) {
          addHit(i.id.toString, (fileOf(i), lineOf(i), cl(i.code)), "PACKAGE_API_INPUT",
            s"exported_param $exportName.${p.name}")
        }
      }
    }
  }

  // APPLICATION_INGRESS_INPUT: req/request field-access shape (property-neutral re-derivation of
  // export_redos_npm_integ.sc's own SOURCE_PATTERN) plus bare req/request identifier references.
  cpg.call.name("<operator>.fieldAccess").code(SOURCE_PATTERN).l.foreach { c =>
    addHit(c.id.toString, (fileOf(c), lineOf(c), cl(c.code)), "APPLICATION_INGRESS_INPUT",
      "req/request field-access pattern")
  }
  cpg.identifier.l.filter(i => i.name == "req" || i.name == "request").foreach { i =>
    addHit(i.id.toString, (fileOf(i), lineOf(i), cl(i.code)), "APPLICATION_INGRESS_INPUT",
      "bare req/request identifier reference")
  }

  case class OriginRow(siteId: String, file: String, line: String, siteCode: String, family: String,
                        detail: String, multiOrigin: Boolean, originCount: Int)
  val originRows = scala.collection.mutable.ListBuffer[OriginRow]()
  siteHits.foreach { case (siteId, hits) =>
    val (file, line, code) = siteMeta(siteId)
    val distinctFamilies = hits.toList.distinctBy(_.family)
    val count = distinctFamilies.size
    distinctFamilies.foreach { h =>
      originRows += OriginRow(siteId, file, line, code, h.family, h.detail, count > 1, count)
    }
  }
  System.err.println(s"[$srcLabel] source_origin_facts rows: ${originRows.size} " +
    s"(sites=${siteHits.size}, multi_origin_sites=${siteHits.count(_._2.distinctBy(_.family).size > 1)})")

  // ============================== deterministic, sorted output ==============================
  val esOut = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/export_surface.tsv", true))
  try {
    exportRows.toList.sortBy(r => (r.file, r.line.toIntOption.getOrElse(-1), r.exportId)).foreach { r =>
      esOut.println(Seq(r.exportId, r.file, r.line, r.exportLhs, r.exportName, r.rhsKind, r.status,
        r.methodId, r.methodFullName, r.abstainReason).mkString("\t"))
    }
  } finally esOut.close()

  val ciOut = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/closure_identity.tsv", true))
  try {
    identityRows.toList.sortBy(r => r.identifierId.toLong).foreach { r =>
      ciOut.println(Seq(r.identifierId, r.file, r.line, r.methodFullName, r.identifierCode, r.kind,
        r.rootId, r.rootName, r.rootKind, r.captureDepth, r.note).mkString("\t"))
    }
  } finally ciOut.close()

  val sofOut = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/source_origin_facts.tsv", true))
  try {
    originRows.toList.sortBy(r => (r.siteId.toLong, r.family)).foreach { r =>
      sofOut.println(Seq(r.siteId, r.file, r.line, r.siteCode, r.family, r.detail,
        r.multiOrigin.toString, r.originCount.toString).mkString("\t"))
    }
  } finally sofOut.close()

  System.err.println(s"[$srcLabel] NPM_SOURCE_IDENTITY_COMPLETE export_rows=${exportRows.size} " +
    s"identity_rows=${identityRows.size} origin_rows=${originRows.size}")
}
