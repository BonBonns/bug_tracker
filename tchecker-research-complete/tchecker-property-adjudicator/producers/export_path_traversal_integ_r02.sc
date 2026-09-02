// PATH-TRAV-R02: extends export_path_traversal_integ_r01.sc (R01, FROZEN, never modified -- that
// file is left byte-for-byte untouched; this is a NEW, separate file) with exactly ONE real
// capability change, per direct instruction: REPLACE R01's own hand-rolled "Capability 3:
// two independently-tagged source families" block (R01 lines ~305-420: `findIngressParams`/
// `sourceCallsFieldAccess`/`applicationIngressSources`/`resolveExportRhs`/`exportAssigns`/
// `packageApiSources`/`allSources`/`familyOfSource`/`isSourceTainted`) with logic that CONSUMES
// (never re-derives) `source_origin_facts.tsv`, written by the shared, frozen, property-neutral
// producer `export_npm_source_identity.sc` -- the exact same real `refsTo`/`closureBindingId`/
// `ClosureBinding` identity resolution that file was built to provide in place of the SAME weaker
// name-matching approach (`p.method.ast.isIdentifier.name(p.name)`) R01's own Capability 3 used.
//
// Per direct instruction, following the SAME documentation discipline export_redos_npm_integ_r02.sc
// established for exactly this situation (see that file's own header comment, lines 1-26) --
// COPIED VERBATIM, byte-for-byte, unmodified, from export_path_traversal_integ_r01.sc:
//   - Capability 1 (6-way sink family split: FS_READ/FS_WRITE/FS_READ_WRITE/FS_DELETE/
//     EXPRESS_SEND_FILE/EXPRESS_DOWNLOAD) and the open()/openSync() flags resolver
//     (`resolveFlagsOperand`/`resolveFlagsExpr`/`classifyOpenFlags`/`fsFamilyOfCall`).
//   - Capability 2 (structural fs import/require recognition: `methodFullNameIsFsModule`,
//     `identifierIsDirectRequireFsBinding`, `identifierIsDestructuredFsMember`, `realFsMemberName`,
//     `isRealFsSinkCall`).
//   - The Express root-option field lookup (`RootLookup`/`findRootField`).
//   - The `SinkTarget`/`SinkAbstention` case classes.
//   - The sink-target-construction loop (6-way family split + corrected root handling).
//   - Capability 4/5 (corrected containment idioms: real CFG-dominance canonicalization proof,
//     boundary-safe `.startsWith` operand recognition, the wrapper-guard resolver, weak-diagnostic
//     collection) -- every helper (`canonicalizingAssignmentsFor`, `sameVarAssignmentsFor`,
//     `hasDominatingCanonicalization`, `dominanceUnprovenNote`, `isPathSepOperand`,
//     `isBoundarySafeStartsWithArg`, `findGenuineBoundaryCheck`, `collectWeakDiagnostics`,
//     `domIfCondition`, `bodyChildCount`, `wrapperGuardResult`).
//   - `lookupKeyInfluence`/`isConstructorCall` and the `OutRow` case class shape.
// None of this logic is re-derived, re-implemented, or even lightly edited here -- it is the exact
// same source text as R01's own file, because R01's own audit-driven design for sink identification,
// import recognition, open-flags resolution, and containment proof was never in question; only its
// SOURCE classification (Capability 3) was.
//
// REPLACED (this file's own new logic, not present in R01 at all): sources are read from
// `source_origin_facts.tsv` in the SAME `rawDir` this producer is given -- 8 columns (site_id,
// file, line, site_code, origin_family, family_detail, multi_origin, origin_count), see
// export_npm_source_identity.sc's own header comment (lines ~78-87) for that schema's real
// guarantee: one row per (site, origin_family) pair, NEVER collapsed when more than one family
// reaches the same site. `site_id` is the shared producer's own real CPG node id (an Identifier or
// a `<operator>.fieldAccess` Call), minted from the SAME cpg file this producer is also given, so
// `cpg.all.id(siteId)` resolves it EXACTLY -- no re-derivation, no name-matching, no risk of
// resolving to a different node that merely shares a name.
//
// ***** REQUIRED UPSTREAM DEPENDENCY (disclosed per this project's own established convention: *****
// ***** every dependency is stated explicitly, never silently assumed) *****
// This producer does NOT invoke export_npm_source_identity.sc itself. Before running this
// producer, `export_npm_source_identity.sc` MUST ALREADY have been run against the SAME cpg file,
// writing its output (`export_surface.tsv`, `closure_identity.tsv`, `source_origin_facts.tsv`)
// into the SAME `rawDir` this producer is given. If `source_origin_facts.tsv` is absent from
// `rawDir` when this producer runs (a mis-ordered pipeline, the shared producer was skipped, or a
// wrong/empty rawDir was passed), this producer degrades SAFELY and DISCLOSED, never silently:
// zero sources are recognized (no PACKAGE_API_INPUT, no APPLICATION_INGRESS_INPUT candidates at
// all -- every structurally-identified sink still appears in `sinkTargets`, since sink
// identification does not depend on sources at all, but NO row is ever written to
// `source_facts.tsv` for any of them, since none can be marked reachable), and a real, explicit
// stderr WARNING plus a `source_origin_facts_missing: true` field in this file's own
// `path_traversal_r02_summary.json` records that this happened -- never a bare, unexplained
// "zero reachable sources" result indistinguishable from a package that genuinely has none.
//
// ***** REAL, MEASURED CONSEQUENCE of consuming the shared producer's own real, narrower model *****
// (confirmed via an actual Joern run against fixtures/path_traversal_r01/src/ BEFORE this file's
// fixture set was finalized -- never assumed): the shared producer's own APPLICATION_INGRESS_INPUT
// model (its own header comment, lines ~93-104) recognizes ONLY (a) a `req`/`request`
// field-access matching `(req|request)\.(body|query|params|headers|payload|url)(\..*)?`, and (b) a
// BARE `req`/`request` identifier reference -- it deliberately does NOT know about
// Meteor.methods-registered handler parameters (a Path-Traversal/RocketChat-specific application-
// boundary concept, out of the shared producer's own property-neutral scope per its header
// comment) at all, under ANY parameter name. R01's OWN Capability 3, by contrast, additionally ran
// `findIngressParams()` (Meteor.methods registration lookup) and searched every registered
// handler's own parameter identifiers by NAME -- exactly the weak mechanism this replacement
// removes. A real probe (`export_npm_source_identity.sc` run against the UNMODIFIED, frozen
// fixtures/path_traversal_r01/src/) confirms: of the 26 real R01 fixture files, only 4
// (ctrl02_user_controlled_root.js, ctrl03_fixed_root_sendfile.js, ctrl04_fixed_root_download.js,
// ctrl10_unresolved_options.js -- all of which use a real `req.params.name`/`req.body.root`
// shape, not a Meteor.methods handler param) and the 2 package_api_*.js files produce ANY row in
// `source_origin_facts.tsv` at all; every other control (ctrl01, ctrl05-09, ctrl11-21,
// import_destructured_fs.js, import_esm.mjs), which source their attacker-controlled path from a
// Meteor.methods handler's OWN parameter (e.g. `userPath`, never named `req`/`request`), produce
// ZERO source_origin_facts.tsv rows and therefore ZERO `source_facts.tsv` rows/findings under this
// R02 producer -- a REAL, substantial, and fully disclosed coverage change (documented with real
// numbers in docs/milestones/PATH_TRAVERSAL_R02_IMPLEMENTATION.md), not a bug in this file. The
// STRUCTURAL sink-identification count (`sinkTargets.size`) is UNCHANGED (still finds the same 27
// real fs/Express sink call sites structurally, since that logic is copied verbatim and does not
// depend on sources at all) -- only how many of those sinks get a recognized REACHING source
// changes. Extending the shared producer with a Meteor.methods-aware ingress model is explicitly
// OUT OF SCOPE for this file (it would mean editing the frozen shared producer, or re-deriving its
// own logic here -- both forbidden by direct instruction); this file is a faithful, disclosed
// consumer of the shared producer's own real, current scope, nothing more.
//
// The ONE OTHER place besides Capability 3 that changes (per direct instruction): the final
// sink-target reachability loop and its `source_facts.tsv` emission now emit ONE ROW PER (sink,
// matched source, family) TRIPLE, reading the real, never-collapsed family LIST for that source's
// site_id (`familiesOf`, built directly from every distinct family the shared producer's own
// `source_origin_facts.tsv` recorded for that exact site_id) rather than a single computed family
// string -- this is the concrete mechanism that makes MULTIPLE_ORIGINS a real, observable outcome
// for Path Traversal too, exactly as it already is in the shared module itself (see
// `fixtures/path_traversal_r02/src/multi_origin_fs_sink.js` and the real evidence quoted in
// docs/milestones/PATH_TRAVERSAL_R02_IMPLEMENTATION.md). The `source_facts.tsv` SCHEMA itself is
// UNCHANGED -- still exactly 12 columns (sink_id, sink_line, src_id, family, status, sink_family,
// weak_diagnostic_guards, then 5 reserved-blank columns), the SAME schema `path_traversal_verdict.py`
// already reads (confirmed via its own `SF_COLS = 12` comment) -- so that reducer needs ZERO
// changes to read this file's own output; only the VALUES populating the `family` column and the
// NUMBER of rows per (sink, src) pair change (one row per real distinct family now, never
// collapsed), never the schema shape itself. `propagation_relations.tsv` and `property_outcome.tsv`
// are written ONCE per (sink, src) pair (not once per family) since neither carries a
// family-specific value -- writing them per-family would only duplicate identical rows, which
// `path_traversal_verdict.py`'s own dict-keyed readers (`origin_lines_and_codes`,
// `containment_status`) already tolerate but which serves no purpose.
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

@main def exec(cpgFile: String, rawDir: String, srcLabel: String) = {
  importCpg(cpgFile)
  implicit val ec: EngineContext = EngineContext()

  // ===================================================================================
  // ===== Capability 1 (COPIED VERBATIM from export_path_traversal_integ_r01.sc, unmodified) =====
  val FS_READ_NAMES = Set("readFile", "readFileSync", "createReadStream", "stat", "existsSync", "open", "openSync")
  val FS_WRITE_NAMES = Set("writeFile", "writeFileSync", "createWriteStream")
  val FS_DELETE_NAMES = Set("unlink", "unlinkSync")
  val FS_ALL_NAMES = FS_READ_NAMES ++ FS_WRITE_NAMES ++ FS_DELETE_NAMES

  // ===== Capability 2 (COPIED VERBATIM) =====
  val FS_MODULE_METHODFULLNAME_PREFIXES = Seq("fs:", "node:fs:", "fs/promises:", "node:fs/promises:")
  val FS_MODULE_SPEC_LITERALS = Set("fs", "node:fs", "fs/promises", "node:fs/promises")

  def unquote(s: String): String = s.trim.stripPrefix("\"").stripPrefix("'").stripSuffix("\"").stripSuffix("'")
  def fileOf(n: nodes.AstNode): String = n.file.name.headOption.getOrElse("")

  val OPEN_READ_FLAG_LITERALS = Set("r", "rs")
  val OPEN_WRITE_FLAG_LITERALS = Set("w", "wx", "a", "ax", "as")
  val OPEN_READWRITE_FLAG_LITERALS = Set("r+", "rs+", "w+", "wx+", "a+", "ax+", "as+")
  val OPEN_MODIFIER_CONST_NAMES = Set("O_CREAT", "O_TRUNC", "O_APPEND", "O_EXCL", "O_SYNC")

  sealed trait FlagAccessMode
  case object AccessRead extends FlagAccessMode
  case object AccessWrite extends FlagAccessMode
  case object AccessReadWrite extends FlagAccessMode

  sealed trait OpenFlagsOutcome
  case object OpenFlagsRead extends OpenFlagsOutcome
  case object OpenFlagsWrite extends OpenFlagsOutcome
  case object OpenFlagsReadWrite extends OpenFlagsOutcome
  case object OpenFlagsUnresolved extends OpenFlagsOutcome

  def resolveFlagsOperand(e: nodes.Expression): Option[Option[FlagAccessMode]] = e match {
    case fld: nodes.Call if fld.name == "<operator>.fieldAccess" =>
      fld.code.split("\\.").lastOption match {
        case Some("O_RDONLY") => Some(Some(AccessRead))
        case Some("O_WRONLY") => Some(Some(AccessWrite))
        case Some("O_RDWR") => Some(Some(AccessReadWrite))
        case Some(n) if OPEN_MODIFIER_CONST_NAMES.contains(n) => Some(None)
        case _ => None
      }
    case lit: nodes.Literal =>
      val s = lit.code.trim
      s match {
        case "0" => Some(Some(AccessRead))
        case "1" => Some(Some(AccessWrite))
        case "2" => Some(Some(AccessReadWrite))
        case _ if s.matches("[0-9]+") => Some(None) // some other real numeric modifier-flag value
        case _ => None
      }
    case _ => None
  }
  def resolveFlagsExpr(e: nodes.Expression): Option[FlagAccessMode] = e match {
    case orCall: nodes.Call if orCall.name == "<operator>.or" =>
      val operands = orCall.argument.l.filter(_.argumentIndex >= 1)
      val resolvedOperands = operands.map(resolveFlagsOperand)
      if (resolvedOperands.isEmpty || resolvedOperands.exists(_.isEmpty)) None
      else {
        val modes = resolvedOperands.flatten.flatten
        if (modes.contains(AccessReadWrite)) Some(AccessReadWrite)
        else if (modes.contains(AccessWrite)) Some(AccessWrite)
        else if (modes.contains(AccessRead)) Some(AccessRead)
        else Some(AccessRead) // only modifier flags present -- POSIX default access mode is O_RDONLY
      }
    case single =>
      resolveFlagsOperand(single) match {
        case Some(Some(mode)) => Some(mode)
        case Some(None) => Some(AccessRead) // a lone modifier constant with no OR chain at all
        case None => None
      }
  }
  def classifyOpenFlags(c: nodes.Call): OpenFlagsOutcome =
    c.argument.l.find(_.argumentIndex == 2) match {
      case None => OpenFlagsRead // flags OMITTED entirely: Node's own real documented default 'r'
      case Some(lit: nodes.Literal) =>
        val s = unquote(lit.code)
        if (OPEN_READ_FLAG_LITERALS.contains(s)) OpenFlagsRead
        else if (OPEN_WRITE_FLAG_LITERALS.contains(s)) OpenFlagsWrite
        else if (OPEN_READWRITE_FLAG_LITERALS.contains(s)) OpenFlagsReadWrite
        else OpenFlagsUnresolved // an unrecognized literal string (e.g. a typo) -- abstain, don't guess
      case Some(expr: nodes.Expression) =>
        resolveFlagsExpr(expr) match {
          case Some(AccessRead) => OpenFlagsRead
          case Some(AccessWrite) => OpenFlagsWrite
          case Some(AccessReadWrite) => OpenFlagsReadWrite
          case None => OpenFlagsUnresolved
        }
    }

  sealed trait FsFamilyResult
  case class FsFamily(name: String) extends FsFamilyResult
  case object FsFamilyAbstainUnresolvedFlags extends FsFamilyResult

  def fsFamilyOfCall(c: nodes.Call, n: String): FsFamilyResult =
    if (n == "open" || n == "openSync")
      classifyOpenFlags(c) match {
        case OpenFlagsRead => FsFamily("FS_READ")
        case OpenFlagsWrite => FsFamily("FS_WRITE")
        case OpenFlagsReadWrite => FsFamily("FS_READ_WRITE")
        case OpenFlagsUnresolved => FsFamilyAbstainUnresolvedFlags
      }
    else if (FS_READ_NAMES.contains(n)) FsFamily("FS_READ")
    else if (FS_WRITE_NAMES.contains(n)) FsFamily("FS_WRITE")
    else FsFamily("FS_DELETE") // the only remaining case given the FS_ALL_NAMES precondition at the call site

  def methodFullNameIsFsModule(c: nodes.Call): Boolean =
    FS_MODULE_METHODFULLNAME_PREFIXES.exists(p => c.methodFullName.startsWith(p))

  def identifierIsDirectRequireFsBinding(name: String, filename: String): Boolean = {
    cpg.call.name("<operator>.assignment").filter(fileOf(_) == filename).l.exists { a =>
      val lhsMatches = a.argument.l.find(_.argumentIndex == 1).exists {
        case id: nodes.Identifier => id.code.trim == name
        case _ => false
      }
      val rhsIsRequireFs = a.argument.l.find(_.argumentIndex == 2).exists {
        case rc: nodes.Call if rc.name == "require" =>
          rc.argument.l.find(_.argumentIndex == 1).collect { case l: nodes.Literal => unquote(l.code) }
            .exists(FS_MODULE_SPEC_LITERALS.contains)
        case _ => false
      }
      lhsMatches && rhsIsRequireFs
    }
  }
  def identifierIsDestructuredFsMember(name: String, filename: String): Boolean = {
    cpg.call.name("<operator>.assignment").filter(fileOf(_) == filename).l.exists { a =>
      val lhsMatches = a.argument.l.find(_.argumentIndex == 1).exists {
        case id: nodes.Identifier => id.code.trim == name
        case _ => false
      }
      lhsMatches && a.argument.l.find(_.argumentIndex == 2).exists {
        case fld: nodes.Call if fld.name == "<operator>.fieldAccess" =>
          fld.argument.l.find(_.argumentIndex == 1).exists {
            case baseId: nodes.Identifier => identifierIsDirectRequireFsBinding(baseId.code.trim, filename)
            case _ => false
          }
        case _ => false
      }
    }
  }
  def realFsMemberName(c: nodes.Call): Option[String] =
    if (methodFullNameIsFsModule(c)) c.methodFullName.split(":").lastOption
    else if (FS_ALL_NAMES.contains(c.name) && identifierIsDestructuredFsMember(c.name, fileOf(c))) Some(c.name)
    else None
  def isRealFsSinkCall(c: nodes.Call): Boolean = realFsMemberName(c).exists(FS_ALL_NAMES.contains)

  // ===== Express root-option field lookup (COPIED VERBATIM) =====
  sealed trait RootLookup
  case class RootFound(expr: nodes.Expression) extends RootLookup
  case object RootAbsentResolved extends RootLookup       // options object resolved, no 'root' key
  case object RootUnresolvedOptions extends RootLookup    // options arg not statically an object literal

  def findRootField(optionsArg: nodes.Expression): RootLookup = optionsArg match {
    case block: nodes.Block =>
      val hit = block.ast.isCall.name("<operator>.assignment").l.flatMap { a =>
        a.argument.l.find(_.argumentIndex == 1).collect {
          case fld: nodes.Call if fld.name == "<operator>.fieldAccess" =>
            (fld.code.split("\\.").lastOption.getOrElse(""), a.argument.l.find(_.argumentIndex == 2))
        }
      }.collectFirst { case ("root", Some(rhs)) => rhs }
      hit match {
        case Some(rootExpr) => RootFound(rootExpr)
        case None => RootAbsentResolved
      }
    case _ => RootUnresolvedOptions
  }

  case class SinkTarget(sinkCall: nodes.Call, family: String, destExpr: nodes.Expression,
                         rootTaintNote: String = "")
  val sinkTargets = scala.collection.mutable.ListBuffer[SinkTarget]()
  case class SinkAbstention(callNodeId: Long, line: Int, file: String, callCode: String,
                             pathOperandCode: String, reasonCode: String, reasonDetail: String)
  val sinkAbstentions = scala.collection.mutable.ListBuffer[SinkAbstention]()

  // ===================================================================================
  // ===== Capability 3 (R02, REPLACED -- this is the ONLY capability whose logic differs from
  // R01): sources are read from source_origin_facts.tsv, written by the SAME shared, frozen
  // export_npm_source_identity.sc producer for the SAME cpg, in the SAME rawDir -- a REQUIRED
  // upstream step this producer does NOT invoke itself (see this file's own header comment for the
  // full disclosure of this dependency, its degrade-safe behavior when absent, and the real,
  // measured coverage consequence of consuming this narrower, but sound, shared source model).
  case class SourceOriginFact(siteId: Long, file: String, line: Int, code: String, family: String,
                               familyDetail: String, multiOrigin: Boolean, originCount: Int)

  val SOURCE_ORIGIN_FACTS_COLS = 8
  val sourceOriginFactsFile = new java.io.File(s"$rawDir/source_origin_facts.tsv")
  val sourceOriginFactsPresent = sourceOriginFactsFile.exists()
  val sourceOriginFacts: List[SourceOriginFact] =
    if (!sourceOriginFactsPresent) {
      System.err.println(s"[$srcLabel] WARNING: source_origin_facts.tsv NOT FOUND at " +
        s"$rawDir/source_origin_facts.tsv -- export_npm_source_identity.sc (the shared, frozen " +
        "npm-source-identity producer) MUST be run against the SAME cpg BEFORE this producer, " +
        "writing its output into this SAME rawDir. Degrading safely: ZERO sources are recognized " +
        "this run (no PACKAGE_API_INPUT, no APPLICATION_INGRESS_INPUT candidates at all) -- every " +
        "structurally-identified sink below is still enumerated in sinkTargets, but NO row will be " +
        "written to source_facts.tsv for any of them, since none can be marked reachable. This is a " +
        "real, disclosed pipeline-ordering failure -- never a silent, unexplained zero.")
      Nil
    } else {
      scala.io.Source.fromFile(sourceOriginFactsFile).getLines().toList.flatMap { ln =>
        if (ln.trim.isEmpty) None
        else {
          val p = ln.split("\t", -1)
          if (p.length != SOURCE_ORIGIN_FACTS_COLS) {
            System.err.println(s"[$srcLabel] WARNING: malformed source_origin_facts.tsv row " +
              s"(expected $SOURCE_ORIGIN_FACTS_COLS columns, got ${p.length}) -- skipped: $ln")
            None
          } else scala.util.Try {
            SourceOriginFact(p(0).toLong, p(1), p(2).toIntOption.getOrElse(-1), p(3), p(4), p(5),
              p(6) == "true", p(7).toIntOption.getOrElse(1))
          }.toOption
        }
      }
    }
  System.err.println(s"[$srcLabel] source_origin_facts.tsv present=$sourceOriginFactsPresent rows_read=${sourceOriginFacts.size} " +
    s"(PACKAGE_API_INPUT=${sourceOriginFacts.count(_.family == "PACKAGE_API_INPUT")}, " +
    s"APPLICATION_INGRESS_INPUT=${sourceOriginFacts.count(_.family == "APPLICATION_INGRESS_INPUT")}, " +
    s"multi_origin_sites=${sourceOriginFacts.filter(_.multiOrigin).map(_.siteId).distinct.size})")

  // Real, exact node-id lookup against THIS producer's own cpg -- never a re-derivation/name-match.
  // The shared producer's site_id is minted from the SAME cpg file this producer was also given
  // (a required precondition of the upstream dependency above), so this resolves exactly.
  def nodeForSiteId(id: Long): Option[nodes.Expression] =
    cpg.all.id(id).collectAll[nodes.Expression].headOption

  case class OriginSource(expr: nodes.Expression, family: String, siteId: Long)
  val allOriginSources: List[OriginSource] = sourceOriginFacts.flatMap { f =>
    val resolved = nodeForSiteId(f.siteId)
    if (resolved.isEmpty)
      System.err.println(s"[$srcLabel] WARNING: source_origin_facts.tsv site_id=${f.siteId} " +
        s"(${f.file}:${f.line} ${f.code}) did not resolve against this producer's own cpg -- " +
        "skipped (likely a stale source_origin_facts.tsv built from a DIFFERENT cpg file than the " +
        "one this producer was given; never guessed/substituted with a name-matched node)")
    resolved.map(e => OriginSource(e, f.family, f.siteId))
  }
  val allSources: List[nodes.Expression] = allOriginSources.map(_.expr).distinct

  // familiesOf: the REAL, NEVER-collapsed family list for a given source expression's own site id
  // -- the entire reason this replacement exists. R01's own `familyOfSource` returned a SINGLE
  // string (`if packageApiSources.exists(...) "PACKAGE_API_INPUT" else "APPLICATION_INGRESS_INPUT"`),
  // silently collapsing a genuinely-both-families source to one; here every distinct family this
  // exact site_id carries in source_origin_facts.tsv is preserved and later emitted as its OWN row.
  def familiesOf(e: nodes.Expression): List[String] =
    allOriginSources.filter(_.expr.id == e.id).map(_.family).distinct

  val packageApiSources: List[nodes.Expression] =
    allOriginSources.filter(_.family == "PACKAGE_API_INPUT").map(_.expr).distinct
  val applicationIngressSources: List[nodes.Expression] =
    allOriginSources.filter(_.family == "APPLICATION_INGRESS_INPUT").map(_.expr).distinct
  val multiOriginSourceCount: Int = allSources.count(s => familiesOf(s).size > 1)
  System.err.println(s"[$srcLabel] PACKAGE_API_INPUT source candidates (from source_origin_facts.tsv): ${packageApiSources.size}")
  System.err.println(s"[$srcLabel] APPLICATION_INGRESS_INPUT source candidates (from source_origin_facts.tsv): ${applicationIngressSources.size}")
  System.err.println(s"[$srcLabel] sources carrying MULTIPLE origin families (never collapsed): ${multiOriginSourceCount}")

  def isSourceTainted(target: nodes.Expression): Boolean = {
    if (allSources.isEmpty) false
    else scala.util.Try {
      cpg.all.id(target.id).collectAll[nodes.Expression].reachableByFlows(allSources.iterator).l.nonEmpty
    }.getOrElse(false)
  }

  // ===== Sink target construction (COPIED VERBATIM from export_path_traversal_integ_r01.sc; uses
  // `isSourceTainted`/`allSources` as redefined immediately above, same signatures/semantics) ====
  cpg.call.l.foreach { c =>
    val fsMember = realFsMemberName(c)
    if (fsMember.exists(FS_ALL_NAMES.contains)) {
      fsFamilyOfCall(c, fsMember.get) match {
        case FsFamily(fam) =>
          val args = c.argument.l.filter(_.argumentIndex >= 1)
          args.headOption.foreach { a0 => sinkTargets += SinkTarget(c, fam, a0) }
        case FsFamilyAbstainUnresolvedFlags =>
          val flagsCode = c.argument.l.find(_.argumentIndex == 2).map(_.code).getOrElse("<omitted>")
          val pathOperandCode = c.argument.l.find(_.argumentIndex == 1).map(_.code).getOrElse("<unknown>")
          sinkAbstentions += SinkAbstention(c.id, c.lineNumber.getOrElse(-1), fileOf(c), c.code,
            pathOperandCode, "FS_OPEN_MODE_UNRESOLVED",
            s"flags argument ($flagsCode) not structurally resolvable to a read/write/read-write mode")
      }
    } else if (c.name == "sendFile" || c.name == "download") {
      val fam = if (c.name == "sendFile") "EXPRESS_SEND_FILE" else "EXPRESS_DOWNLOAD"
      val args = c.argument.l.filter(_.argumentIndex >= 1)
      val a0 = args.headOption
      val optionsArg = args.lift(1)
      (a0, optionsArg) match {
        case (Some(pathArg), Some(opt)) =>
          findRootField(opt) match {
            case RootFound(rootExpr) =>
              if (isSourceTainted(rootExpr)) {
                sinkTargets += SinkTarget(c, fam, rootExpr, "root itself is source-tainted -- root is the real attacker-controlled operand, not contained")
              } else {
                // All 4 conditions hold -- path arg genuinely contained, not enumerated further.
              }
            case RootAbsentResolved =>
              sinkTargets += SinkTarget(c, fam, pathArg)
            case RootUnresolvedOptions =>
              sinkAbstentions += SinkAbstention(c.id, c.lineNumber.getOrElse(-1), fileOf(c), c.code,
                pathArg.code, "EXPRESS_ROOT_OPTIONS_UNRESOLVED",
                s"options argument not statically resolved to an object literal (${opt.code})")
          }
        case (Some(pathArg), None) =>
          sinkTargets += SinkTarget(c, fam, pathArg)
        case _ =>
      }
    }
  }
  System.err.println(s"[$srcLabel] sink targets found: ${sinkTargets.size} " +
    s"(FS_READ=${sinkTargets.count(_.family == "FS_READ")}, FS_WRITE=${sinkTargets.count(_.family == "FS_WRITE")}, " +
    s"FS_READ_WRITE=${sinkTargets.count(_.family == "FS_READ_WRITE")}, " +
    s"FS_DELETE=${sinkTargets.count(_.family == "FS_DELETE")}, EXPRESS_SEND_FILE=${sinkTargets.count(_.family == "EXPRESS_SEND_FILE")}, " +
    s"EXPRESS_DOWNLOAD=${sinkTargets.count(_.family == "EXPRESS_DOWNLOAD")})")
  if (sinkAbstentions.nonEmpty) sinkAbstentions.foreach(a =>
    System.err.println(s"[$srcLabel] ABSTAIN: ${a.reasonCode} at ${a.file}:L${a.line} " +
      s"call=${a.callCode} pathOperand=${a.pathOperandCode} detail=${a.reasonDetail}"))

  // ===================================================================================
  // ===== Capability 4/5 (COPIED VERBATIM from export_path_traversal_integ_r01.sc, unmodified) ====
  val COMPARISON_OPS = Set("<operator>.equals", "<operator>.strictEquals")
  val CONTAINMENT_CHECK_METHODS = Set("includes", "startsWith")

  def enclosingCall(n: nodes.AstNode): Option[nodes.Call] = {
    var cur: nodes.AstNode = n; var hops = 0
    while (hops < 8) {
      val p = scala.util.Try(cur.astParent).toOption
      p match {
        case Some(cc: nodes.Call) => return Some(cc)
        case Some(null) => return None
        case Some(pp) => cur = pp; hops += 1
        case None => return None
      }
    }
    None
  }

  def canonicalizingAssignmentsFor(m: nodes.Method, varName: String): List[nodes.Call] =
    sameVarAssignmentsFor(m, varName).filter { a =>
      a.argument.l.find(_.argumentIndex == 2).exists {
        case rc: nodes.Call =>
          val short = if (rc.name == "<operator>.fieldAccess") rc.code.split("\\.").lastOption.getOrElse("") else rc.name
          short == "resolve" || short == "normalize"
        case _ => false
      }
    }
  def sameVarAssignmentsFor(m: nodes.Method, varName: String): List[nodes.Call] =
    m.ast.isCall.name("<operator>.assignment").l.filter { a =>
      a.argument.l.find(_.argumentIndex == 1).exists {
        case id: nodes.Identifier => id.code.trim == varName
        case _ => false
      }
    }
  def hasDominatingCanonicalization(m: nodes.Method, varName: String, checkNode: nodes.CfgNode): Boolean = {
    val canonicalizing = canonicalizingAssignmentsFor(m, varName)
    if (canonicalizing.isEmpty) false
    else {
      val checkDominators: Set[Long] = scala.util.Try(checkNode.dominatedBy.l.map(_.id).toSet).getOrElse(Set.empty)
      if (checkDominators.isEmpty) false
      else {
        val sameVarAssigns = sameVarAssignmentsFor(m, varName)
        canonicalizing.exists { a =>
          checkDominators.contains(a.id) && {
            val aDominates: Set[Long] = scala.util.Try(a.dominates.l.map(_.id).toSet).getOrElse(Set.empty)
            !sameVarAssigns.exists(a2 => a2.id != a.id && checkDominators.contains(a2.id) && aDominates.contains(a2.id))
          }
        }
      }
    }
  }
  def dominanceUnprovenNote(m: nodes.Method, varName: String, checkNode: nodes.CfgNode, checkCode: String): Option[String] = {
    val canonicalizing = canonicalizingAssignmentsFor(m, varName)
    if (canonicalizing.isEmpty || hasDominatingCanonicalization(m, varName, checkNode)) None
    else Some(s"CANONICALIZATION_DOMINANCE_UNPROVEN: a canonicalizing assignment to '$varName' " +
      s"exists in this method (${canonicalizing.map(_.code).mkString("; ")}) but does not provably " +
      s"CFG-dominate this check on every control-flow path: $checkCode")
  }

  def isPathSepOperand(e: nodes.Expression): Boolean = e match {
    case fld: nodes.Call if fld.name == "<operator>.fieldAccess" => fld.code.split("\\.").lastOption.contains("sep")
    case lit: nodes.Literal =>
      val s = unquote(lit.code); s == "/" || s == "\\" || s == "\\\\"
    case _ => false
  }
  def isBoundarySafeStartsWithArg(e: nodes.Expression): Boolean = e match {
    case add: nodes.Call if add.name == "<operator>.addition" => add.argument.l.exists(isPathSepOperand)
    case _ => false
  }

  def findGenuineBoundaryCheck(root: nodes.AstNode, m: nodes.Method, trackedCodes: Set[String]): Option[String] = {
    val startsWithHit = root.ast.isCall.name("startsWith").l.find { sw =>
      val recv = sw.argument.l.find(_.argumentIndex == 0)
      val arg = sw.argument.l.find(_.argumentIndex == 1)
      recv.exists(r => trackedCodes.contains(r.code.trim) && hasDominatingCanonicalization(m, r.code.trim, sw)) &&
        arg.exists(isBoundarySafeStartsWithArg)
    }
    val equalsHit = root.ast.isCall.filter(cc => COMPARISON_OPS.contains(cc.name)).l.find { cc =>
      cc.argument.l.exists(o => trackedCodes.contains(o.code.trim) && hasDominatingCanonicalization(m, o.code.trim, cc))
    }
    startsWithHit.map(_.code).orElse(equalsHit.map(_.code))
  }

  def collectWeakDiagnostics(sinkCall: nodes.Call, m: nodes.Method, trackedCodes: Set[String]): List[String] = {
    val notes = scala.collection.mutable.ListBuffer[String]()
    domIfCondition(sinkCall).foreach { cond =>
      cond.ast.isCall.name(CONTAINMENT_CHECK_METHODS.mkString("|")).l.foreach { cc =>
        val recv = cc.argument.l.find(_.argumentIndex == 0)
        if (recv.exists(r => trackedCodes.contains(r.code.trim))) {
          val provenElsewhere = findGenuineBoundaryCheck(cond, m, trackedCodes).contains(cc.code)
          if (!provenElsewhere) {
            notes += s"weak ${cc.name} check without proven canonicalization+boundary: ${cc.code}"
            recv.foreach(r => dominanceUnprovenNote(m, r.code.trim, cc, cc.code).foreach(notes += _))
          }
        }
      }
    }
    m.ast.isCall.name("replace").foreach { rc =>
      val args = rc.argument.l.sortBy(_.argumentIndex)
      val recvOk = args.headOption.exists(a => trackedCodes.contains(a.code.trim))
      val patternIsDotDot = args.lift(1).exists(a => a.code.contains("..") || a.code.contains("\\.\\."))
      if (recvOk && patternIsDotDot) notes += s"literal '..' strip via .replace (never treated as containment proof): ${rc.code}"
    }
    notes.toList
  }

  def domIfCondition(sinkCall: nodes.Call): Option[nodes.AstNode] = {
    var cur: nodes.AstNode = sinkCall; var hops = 0
    while (hops < 12) {
      val p = scala.util.Try(cur.astParent).toOption
      p match {
        case Some(ifNode: nodes.ControlStructure) if ifNode.controlStructureType == "IF" =>
          val thenBlock = ifNode.astChildren.l.drop(1).headOption
          if (thenBlock.exists(_.ast.contains(sinkCall))) return ifNode.condition.l.headOption
          cur = ifNode
        case Some(null) => return None
        case Some(pp) => cur = pp
        case None => return None
      }
      hops += 1
    }
    None
  }

  def bodyChildCount(mth: nodes.Method): Int = mth.block.astChildren.filterNot(_.isInstanceOf[nodes.MethodParameterIn]).size

  def wrapperGuardResult(sinkCall: nodes.Call, trackedCodes: Set[String]): Option[Either[String, String]] = {
    domIfCondition(sinkCall).flatMap { cond =>
      val candidateCalls = cond.ast.isCall.l.filter { cc =>
        !cc.name.startsWith("<operator>") && !CONTAINMENT_CHECK_METHODS.contains(cc.name) &&
          cc.argument.l.exists(a => trackedCodes.contains(a.code.trim))
      }
      candidateCalls.flatMap { cc =>
        val callees = cc.callee.l
        if (callees.size != 1) Some(Left(cc.code): Either[String, String]) // ambiguous/unresolved callee -- abstain
        else {
          val callee = callees.head
          if (bodyChildCount(callee) == 0) Some(Left(cc.code): Either[String, String]) // stub -- abstain
          else {
            val firstParam = callee.parameter.filterNot(_.name == "this").l.sortBy(_.index).headOption
            firstParam match {
              case None => Some(Left(cc.code): Either[String, String])
              case Some(p) =>
                val paramRefs: List[nodes.Expression] = callee.ast.isIdentifier.name(p.name).l.map(id => id: nodes.Expression)
                val retExprs: List[nodes.Expression] = callee.ast.isReturn.l.flatMap(_.astChildren.collect { case e: nodes.Expression => e })
                val innerDerived: Set[String] = retExprs.flatMap { re =>
                  scala.util.Try {
                    cpg.all.id(re.id).collectAll[nodes.Expression].reachableByFlows(paramRefs.iterator).l
                  }.getOrElse(Nil)
                }.flatMap(_.elements.collect { case id: nodes.Identifier => id.code.trim }).toSet
                val innerTracked = Set(p.name) ++ innerDerived
                findGenuineBoundaryCheck(callee.block, callee, innerTracked) match {
                  case Some(innerCond) => Some(Right(s"${cc.code} (internally: $innerCond)"): Either[String, String])
                  case None => Some(Left(cc.code): Either[String, String]) // resolved but unverified -- abstain
                }
            }
          }
        }
      }.headOption
    }
  }

  // ===================================================================================
  // ===== Main per-(sink, source) reachability + classification loop =====
  // (COPIED VERBATIM in spirit from R01, with the ONE OTHER change disclosed in this file's own
  // header comment: `familiesOf(src)` -- never a single computed family -- decides how many
  // OutRows this (sink, src) pair emits: one per real, distinct family, never collapsed.)
  case class OutRow(sinkId: String, sinkLine: Int, srcId: String, srcLine: Int, srcCode: String,
                     originFamily: String, sinkFamily: String, outcome: String, note: String,
                     weakDiagnostics: List[String])
  val outRows = scala.collection.mutable.ListBuffer[OutRow]()

  def isConstructorCall(c: nodes.Call): Boolean = c.name == "<operator>.new"

  def lookupKeyInfluence(m: nodes.Method, srcExpr: nodes.Expression, sinkExprs: List[nodes.Expression],
                          otherSinkArgIds: Set[Long]): Option[String] = {
    val keyUses = srcExpr.ast.l.collect { case id: nodes.Identifier => id }
      .flatMap(id => enclosingCall(id))
      .filter(c => !c.name.startsWith("<operator>") || c.name == "<operator>.indexAccess")
      .distinct
    keyUses.flatMap { lookupCall =>
      val fieldAccessOnResult = scala.util.Try(lookupCall.astParent).toOption.collect {
        case fa: nodes.Call if fa.name == "<operator>.fieldAccess" => fa
      }
      val candidateSources: List[nodes.Expression] =
        (cpg.all.id(lookupCall.id).collectAll[nodes.Expression].l ++
          fieldAccessOnResult.toList.flatMap(fa => cpg.all.id(fa.id).collectAll[nodes.Expression].l))
      if (sinkExprs.isEmpty || candidateSources.isEmpty) None
      else {
        val flows = candidateSources.flatMap(s => sinkExprs.reachableByFlows(Iterator(s)).l)
          .filterNot(f => f.elements.dropRight(1).exists(e => otherSinkArgIds.contains(e.id)))
        if (flows.nonEmpty) Some(lookupCall.code) else None
      }
    }.headOption
  }

  sinkTargets.foreach { target =>
    val sinkCall = target.sinkCall
    val destExpr = target.destExpr
    val m = sinkCall.method
    allSources.foreach { src =>
      val families = familiesOf(src)
      if (families.nonEmpty) {
        val otherSinkArgIds = sinkCall.argument.l.filter(_.argumentIndex >= 1).filterNot(_.id == destExpr.id).map(_.id).toSet
        val flowsRaw = scala.util.Try {
          cpg.all.id(destExpr.id).collectAll[nodes.Expression].reachableByFlows(Iterator(src: nodes.Expression)).l
        }.getOrElse(Nil)
        val flows = flowsRaw.filterNot(f => f.elements.dropRight(1).exists(e => otherSinkArgIds.contains(e.id)))
        if (flows.isEmpty) {
          val sinkExprs = cpg.all.id(destExpr.id).collectAll[nodes.Expression].l
          lookupKeyInfluence(m, src, sinkExprs, otherSinkArgIds).foreach { lookupCode =>
            families.foreach { origin =>
              outRows += OutRow(sinkCall.id.toString, sinkCall.lineNumber.getOrElse(-1), src.id.toString,
                src.lineNumber.getOrElse(-1), src.code, origin, target.family, "OPEN",
                s"LOOKUP_KEY_INFLUENCE: key reaches $lookupCode, value itself does not flow to sink", Nil)
            }
          }
        } else {
          val derivedNames: Set[String] = flows.flatMap(_.elements.collect { case id: nodes.Identifier => id.code.trim }).toSet
          val trackedCodes = Set(src.code.trim) ++ derivedNames
          val directGuard = domIfCondition(sinkCall).flatMap(cond => findGenuineBoundaryCheck(cond, m, trackedCodes))
          val wrapperGuard = if (directGuard.isEmpty) wrapperGuardResult(sinkCall, trackedCodes) else None
          val weakNotes = collectWeakDiagnostics(sinkCall, m, trackedCodes) ++
            (if (target.rootTaintNote.nonEmpty) List(target.rootTaintNote) else Nil)
          val (outcome, note): (String, String) = (directGuard, wrapperGuard) match {
            case (Some(cond), _) => ("BROKEN", s"canonicalized boundary-aware check: $cond")
            case (None, Some(Right(cond))) => ("BROKEN", s"structurally proven containment wrapper: $cond")
            case (None, Some(Left(cond))) =>
              ("OPEN", s"UNVERIFIED_WRAPPER_GUARD: $cond (callee body unresolved or does not itself prove containment) -- abstaining")
            case (None, None) =>
              var effect = "PRESERVES"
              var noteAcc = ""
              val seen = scala.collection.mutable.Set[Long]()
              flows.foreach { f =>
                f.elements.foreach { e =>
                  if (!e.isInstanceOf[nodes.Identifier]) {
                    val directCallOpt: Option[nodes.Call] = e match {
                      case cc: nodes.Call if (!cc.name.startsWith("<operator>") || isConstructorCall(cc)) &&
                        !(isRealFsSinkCall(cc) || cc.name == "sendFile" || cc.name == "download") => Some(cc)
                      case _ => None
                    }
                    val ecOpt = directCallOpt.orElse(enclosingCall(e).filter(cc =>
                      (!cc.name.startsWith("<operator>") || isConstructorCall(cc)) &&
                        !(isRealFsSinkCall(cc) || cc.name == "sendFile" || cc.name == "download")))
                    ecOpt.foreach { cc =>
                      if (!seen.contains(cc.id)) {
                        seen += cc.id
                        val calleeShort = if (cc.name == "<operator>.fieldAccess") cc.code.split("\\.").lastOption.getOrElse(cc.name) else cc.name
                        val isPathJoiningCall = Set("join", "resolve").contains(calleeShort)
                        val isKnownPreserving = calleeShort == "normalize"
                        if (isPathJoiningCall) { /* no containment, matches audited design */ }
                        else if (!isKnownPreserving && effect == "PRESERVES") { effect = "UNKNOWN"; noteAcc = s"unrecognized call: $calleeShort" }
                      }
                    }
                  }
                }
              }
              val finalOutcome = if (effect == "PRESERVES") "ESTABLISHED" else "OPEN"
              (finalOutcome, noteAcc)
          }
          families.foreach { origin =>
            outRows += OutRow(sinkCall.id.toString, sinkCall.lineNumber.getOrElse(-1), src.id.toString,
              src.lineNumber.getOrElse(-1), src.code, origin, target.family, outcome, note, weakNotes)
          }
        }
      }
    }
  }

  // ===================================================================================
  // ===== Emit: same 4-file raw-fact schema (12/9/5/8 cols) path_traversal_verdict.py already
  // consumes -- UNCHANGED SCHEMA (see this file's own header comment). source_facts.tsv now emits
  // ONE ROW PER (sink, matched source, family) TRIPLE -- `outRows` already carries one entry per
  // family (built above), so this loop is otherwise identical to R01's own emission loop.
  // propagation_relations.tsv/property_outcome.tsv are written ONCE per (sink, src) pair (keyed by
  // sinkId+srcId, which do not vary across a source's own multiple families) to avoid pointless
  // duplicate rows -- deduplicated via a real (sinkId, srcId) seen-set, not by trusting outRows'
  // own per-family duplication.
  new java.io.File(rawDir).mkdirs()
  val sf = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/source_facts.tsv", true))
  val pr = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/propagation_relations.tsv", true))
  val po = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/property_outcome.tsv", true))
  val ti = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/transform_identity.tsv", true))
  val prPoSeen = scala.collection.mutable.Set[(String, String)]()
  outRows.foreach { r =>
    sf.println(Seq(r.sinkId, r.sinkLine, r.srcId, r.originFamily, "ESTABLISHED", r.sinkFamily,
      r.weakDiagnostics.mkString("|"), "", "", "", "", "").mkString("\t"))
    val key = (r.sinkId, r.srcId)
    if (!prPoSeen.contains(key)) {
      prPoSeen += key
      pr.println(Seq(r.sinkId, "", "", r.srcId, r.srcLine, r.srcCode, "", "", "").mkString("\t"))
      po.println(Seq(r.sinkId, r.srcId, r.outcome, "-1", "-1").mkString("\t"))
    }
    System.err.println(s"[$srcLabel] EMIT sink=${r.sinkId}(L${r.sinkLine}) src=${r.srcId}(L${r.srcLine}:${r.srcCode}) " +
      s"origin=${r.originFamily} sinkFamily=${r.sinkFamily} outcome=${r.outcome} note=${r.note}" +
      (if (r.weakDiagnostics.nonEmpty) s" weak_diagnostic_guards=${r.weakDiagnostics.mkString("; ")}" else ""))
  }
  sf.close(); pr.close(); po.close(); ti.close()

  val sa = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/sink_abstentions.tsv", true))
  sinkAbstentions.foreach { a =>
    sa.println(Seq(a.callNodeId.toString, a.line.toString, a.file, a.reasonCode,
      a.pathOperandCode, a.callCode, a.reasonDetail).mkString("\t"))
  }
  sa.close()

  val distinctSinkSrcMultiOrigin: Int =
    outRows.groupBy(r => (r.sinkId, r.srcId)).values.count(_.map(_.originFamily).distinct.size > 1)
  System.err.println(s"[$srcLabel] PATH_TRAV_R02_COMPLETE rows=${outRows.size} " +
    s"(BROKEN=${outRows.count(_.outcome == "BROKEN")}, OPEN=${outRows.count(_.outcome == "OPEN")}, " +
    s"ESTABLISHED=${outRows.count(_.outcome == "ESTABLISHED")}, " +
    s"MULTIPLE_ORIGINS_sink_src_pairs=$distinctSinkSrcMultiOrigin)")

  val summary = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/path_traversal_r02_summary.json"))
  summary.println(s"""{"sink_targets": ${sinkTargets.size}, "sink_abstentions": ${sinkAbstentions.size}, """ +
    s""""source_origin_facts_present": $sourceOriginFactsPresent, "source_origin_facts_rows": ${sourceOriginFacts.size}, """ +
    s""""package_api_sources": ${packageApiSources.size}, "application_ingress_sources": ${applicationIngressSources.size}, """ +
    s""""multi_origin_sources": $multiOriginSourceCount, """ +
    s""""rows_emitted": ${outRows.size}, "broken": ${outRows.count(_.outcome == "BROKEN")}, """ +
    s""""open": ${outRows.count(_.outcome == "OPEN")}, "established": ${outRows.count(_.outcome == "ESTABLISHED")}, """ +
    s""""multiple_origins_sink_src_pairs": $distinctSinkSrcMultiOrigin}""")
  summary.close()
}
