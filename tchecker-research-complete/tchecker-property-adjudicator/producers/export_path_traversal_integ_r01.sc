// PATH-TRAV-R01: a NEW, standalone producer for ATTACKER_CONTROL_OF_FILESYSTEM_LOCATION that
// corrects the 3 confirmed-unsound guard shapes and the aliased/destructured-import blind spot
// documented in docs/milestones/PATH_TRAVERSAL_R01_AUDIT.md (a real, execution-verified read-only
// audit of export_path_traversal_integ.sc), and adds a PACKAGE_API_INPUT source tier alongside the
// existing APPLICATION_INGRESS_INPUT one, per direct instruction. `export_path_traversal_integ.sc`
// and its two sibling frozen files (characterize_path_traversal_sinks.sc,
// characterize_path_traversal_property_effects.sc) are NEVER imported, edited, or reused by
// reference here -- every mechanic below (dominance walk, findObjectField-style field lookup,
// bodyChildCount wrapper-resolution) is RE-DERIVED FRESH in this file and verified against this
// file's own real Joern fixtures (see fixtures/path_traversal_r01/), even where the underlying
// concept was already proven correct in the audited file.
//
// ===== Real CPG evidence this file's design was built from (fixture-first, never guessed) =====
// Import/module identity (fixtures/path_traversal_r01/src/import_*): a real jssrc2cpg CPG shows
// `const fs = require('fs')` + `fs.readFile(...)` resolves `call.methodFullName == "fs:readFile"`
// via js2cpg's OWN JavaScriptTypeRecovery pass -- and, decisively, `const filesystem =
// require('fs'); filesystem.readFile(...)` ALSO resolves to `methodFullName == "fs:readFile"`,
// the EXACT SAME identity, regardless of the local binding's name. `node:fs` resolves to
// `"node:fs:readFile"`; `fs/promises` to `"fs/promises:readFile"`. ESM shapes (`import fs from
// 'fs'`, `import * as ns from 'fs'`, `import { readFile as x } from 'fs'`,
// `import { readFile } from 'node:fs'`) all resolve the same way (confirmed: `fs:fs:readFile`,
// `fs:ns:readFile`, `fs:readFile`, `node:fs:readFile` respectively -- always containing the
// literal module-identity segment as a PREFIX of the methodFullName, never merely as free text).
// An unrelated object literally named `fs` (`const fs = { readFile: (p) => other(p) }`) resolves
// its own `.readFile` call to `methodFullName == "{ readFile: (p: ANY) => ANY; }:readFile"` -- an
// object-literal TYPE name, which never starts with any real fs-module prefix -- so the same
// single prefix check used to CATCH the aliased-real case also correctly REJECTS the impostor,
// with no extra negative-control code needed.
// The one shape type recovery does NOT resolve through methodFullName: CommonJS destructuring,
// `const { readFile, writeFile } = require('fs'); readFile(c, cb)` -- the bare call's
// methodFullName stays an unresolved local-file stub (`probe.js::program:readFile`). Real,
// confirmed desugared shape (`joern --script` probe, verbatim): `_tmp_0 = require('fs')` then
// `readFile = _tmp_0.readFile` (an `<operator>.assignment` whose RHS is a `<operator>.fieldAccess`
// Call with `argument(1)` = base Identifier, `argument(2)` = a FieldIdentifier naming the member)
// in the SAME enclosing scope -- this file's `identifierIsDestructuredFsMember` resolves exactly
// this two-hop chain explicitly, rather than trusting methodFullName for this one shape.
// Guard/containment shapes (fixtures/path_traversal_r01/src/guard_*): `<operator>.addition`'s own
// arguments are ALSO 1-indexed (`'/safe/base' + path.sep` => argument(1)="/safe/base",
// argument(2)=path.sep, a `<operator>.fieldAccess` whose own `.code` ends in `.sep`) -- confirmed
// real, used to recognize a boundary-safe `X.startsWith(base + path.sep)` operand structurally
// (an addition literally containing a path-separator operand), never a bare literal/identifier.
// Regex-literal `.code` carries its own flags verbatim (`/\.\./` vs `/\.\./g`), confirmed real.
// Wrapper-function resolution (`isContained(candidate)` vs `isSafeSomehow(candidate)`): confirmed
// real via `c.callee.l` -- a genuinely LOCAL function with a real body reports
// `method.block.astChildren.size > 0` (isContained: 4); an undefined/unresolvable callee is still
// linked to a stub Method node by MethodStubCreator, but with `block.astChildren.size == 0`
// (isSafeSomehow: 0) -- the same `bodyChildCount` signal already verified working in the audited
// file's own TS-overload bridge, re-derived fresh here for wrapper-guard resolution specifically.
// Express root option (fixtures/path_traversal_r01/src/express_*): `res.sendFile(path, {root:
// X})`'s 2nd argument desugars to a `Block` containing an `<operator>.assignment`
// (`_tmp_0.root = X`) whose LHS is a `<operator>.fieldAccess` -- confirmed real, structurally
// identical for `res.download`. When the 2nd argument is instead an unresolved variable
// (`res.sendFile(path, opts)`), it is a bare `Identifier`, not a `Block` -- confirmed real,
// distinguishable from "resolved object with no root key" (a `Block` with zero matching
// `<operator>.assignment`s) -- this file abstains on the former and treats the latter as
// genuinely no-root, rather than conflating the two the way the audited file's `findObjectField`
// (returning `None` for both) implicitly did.
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

@main def exec(cpgFile: String, rawDir: String, srcLabel: String) = {
  importCpg(cpgFile)
  implicit val ec: EngineContext = EngineContext()

  // ===================================================================================
  // ===== Capability 1: 5-way sink family split =====
  // FS_READ / FS_WRITE / FS_DELETE / EXPRESS_SEND_FILE / EXPRESS_DOWNLOAD -- distinct family
  // tags carried all the way to source_facts.tsv (column 6, see the row-emission section) so a
  // downstream consumer can group/filter by family, per direct instruction. `open`/`openSync` are
  // classified FS_READ: Node's own default flag for `fs.open()`/`fs.openSync()` when the `flags`
  // argument is omitted is `'r'` (read), and this producer does not (yet) analyze the `flags`
  // argument's own value to distinguish a read-mode open from a write/append-mode one -- FS_READ
  // is the documented, conservative default; a future phase inspecting `flags` explicitly could
  // split further. This choice is disclosed, not silently assumed.
  val FS_READ_NAMES = Set("readFile", "readFileSync", "createReadStream", "stat", "existsSync", "open", "openSync")
  val FS_WRITE_NAMES = Set("writeFile", "writeFileSync", "createWriteStream")
  val FS_DELETE_NAMES = Set("unlink", "unlinkSync")
  val FS_ALL_NAMES = FS_READ_NAMES ++ FS_WRITE_NAMES ++ FS_DELETE_NAMES
  def fsFamilyOfName(n: String): Option[String] =
    if (FS_READ_NAMES.contains(n)) Some("FS_READ")
    else if (FS_WRITE_NAMES.contains(n)) Some("FS_WRITE")
    else if (FS_DELETE_NAMES.contains(n)) Some("FS_DELETE")
    else None

  // ===== Capability 2: structural (not literal-text) fs import/require recognition =====
  val FS_MODULE_METHODFULLNAME_PREFIXES = Seq("fs:", "node:fs:", "fs/promises:", "node:fs/promises:")
  val FS_MODULE_SPEC_LITERALS = Set("fs", "node:fs", "fs/promises", "node:fs/promises")

  def unquote(s: String): String = s.trim.stripPrefix("\"").stripPrefix("'").stripSuffix("\"").stripSuffix("'")
  def fileOf(n: nodes.AstNode): String = n.file.name.headOption.getOrElse("")

  // Direct case: this call's OWN methodFullName (assigned by js2cpg's real type-recovery pass)
  // already carries the fs-module identity as a structural prefix -- covers plain `fs.readFile`,
  // every aliased CommonJS `require('fs')` binding regardless of local name, and every ESM import
  // shape (default/namespace/named/aliased-named), confirmed real (see header comment). This is
  // the fix for the audit's own confirmed gap: `filesystem.readFile(...)` (aliased) now resolves
  // identically to `fs.readFile(...)`.
  def methodFullNameIsFsModule(c: nodes.Call): Boolean =
    FS_MODULE_METHODFULLNAME_PREFIXES.exists(p => c.methodFullName.startsWith(p))

  // Fallback case (methodFullName does NOT resolve, confirmed real for CommonJS destructuring --
  // `const { readFile } = require('fs'); readFile(x)`): trace the bare call's own identifier name
  // back to an assignment `NAME = BASE.member` where `BASE` is itself a direct `require(fsSpec)`
  // binding. Scoped by FILE, not by the call's own single enclosing method: real, confirmed shape
  // (see fixtures/path_traversal_r01/src/import_destructured_fs.js) -- the `require`+destructuring
  // assignment lives at module/program top-level scope, while the call site using it is typically
  // INSIDE a nested function (e.g. a Meteor.methods handler); `m.ast` for that nested method's own
  // Method node does not include the outer program scope's own statements, so a same-method-only
  // search silently misses the overwhelmingly common real case. Two explicit, independently-
  // verified hops -- never trusts the variable's NAME alone (this is exactly what rejects the
  // "unrelated object literally named fs" negative control: `notFs.readFile` has no such
  // `require('fs')`-rooted chain anywhere in the file, so this returns false for it).
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
  // The real fs MEMBER name for a call: for a methodFullName-resolved call this is the LAST
  // ':'-delimited segment of methodFullName -- NOT necessarily `c.name`, which for an aliased ESM
  // named import (`import { readFile as readFileAliased } from 'fs'; readFileAliased(x)`) is
  // confirmed real to be the LOCAL alias text ("readFileAliased"), while methodFullName still
  // correctly resolves to "fs:readFile" -- using `c.name` here would silently miss every aliased
  // named import, so this always prefers the methodFullName-derived member name when available.
  def realFsMemberName(c: nodes.Call): Option[String] =
    if (methodFullNameIsFsModule(c)) c.methodFullName.split(":").lastOption
    else if (FS_ALL_NAMES.contains(c.name) && identifierIsDestructuredFsMember(c.name, fileOf(c))) Some(c.name)
    else None
  def isRealFsSinkCall(c: nodes.Call): Boolean = realFsMemberName(c).exists(FS_ALL_NAMES.contains)

  // ===== Express root-option field lookup (re-derived fresh; see header comment for the real
  // Block-vs-Identifier shape this distinguishes) =====
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
  val sinkAbstentions = scala.collection.mutable.ListBuffer[String]()

  // ===================================================================================
  // ===== Capability 3: two independently-tagged source families =====
  val SOURCE_PATTERN = "(req|request)\\.(body|query|params|headers|payload|url)(\\..*)?"
  val MESSAGE_SOURCE_PATTERN = "(message|item)\\.(urls|text|attachments)(\\..*)?"

  // APPLICATION_INGRESS_INPUT (carried over, unchanged from the audited file's own verified
  // design -- req.*/message.* field access is a structural CPG field-access match already, not
  // literal-text sink matching, and Meteor.methods registration is an application-boundary
  // concept unrelated to module-import aliasing, so it does not share capability 2's gap).
  def findIngressParams(): List[nodes.MethodParameterIn] = {
    val meteorMethodsCalls = cpg.call.name("Meteor.methods").l ++ cpg.call.filter(_.code.startsWith("Meteor.methods")).l
    val objArgs = meteorMethodsCalls.flatMap(_.argument.l.filter(a => a.argumentIndex == 1)).distinct
    val registeredNames = objArgs.flatMap { obj =>
      obj.ast.isCall.name("<operator>.assignment").l.flatMap { assign =>
        assign.argument(2) match {
          case id: nodes.Identifier => Some(id.name)
          case ref: nodes.MethodRef => Some(ref.methodFullName.split("[:.]").lastOption.getOrElse(ref.code))
          case _ => None
        }
      }
    }.distinct
    System.err.println(s"  Meteor.methods ingress registrations found: ${registeredNames.mkString(",")}")
    registeredNames.flatMap { name => cpg.method.name(name).parameter.filter(_.name != "this").l }
  }
  val sourceCallsFieldAccess = cpg.call.name("<operator>.fieldAccess").code(s"($SOURCE_PATTERN)|($MESSAGE_SOURCE_PATTERN)").l
  val ingressParams = findIngressParams()
  val applicationIngressSources: List[nodes.Expression] =
    (sourceCallsFieldAccess.map(c => c: nodes.Expression) ++
      ingressParams.flatMap(p => p.method.ast.isIdentifier.name(p.name).l.map(id => id: nodes.Expression))).distinct
  System.err.println(s"[$srcLabel] APPLICATION_INGRESS_INPUT source candidates: ${applicationIngressSources.size}")

  // PACKAGE_API_INPUT (ported from the SAME real, empirically-grounded design ReDoS's own
  // export_redos_npm_integ.sc built and fixture-verified -- module.exports=/module.exports.NAME=/
  // exports.NAME=/ESM named+default exports, all desugaring to the same Identifier=MethodRef CPG
  // shape; abstain on dynamic keys, require()-based re-exports, ambiguous assignments, class
  // constructors -- re-derived fresh in this file, not imported from the ReDoS producer).
  def resolveExportRhs(rhs: nodes.Expression, scopeMethod: nodes.Method): Either[String, nodes.Method] = {
    def methodFromRef(ref: nodes.MethodRef): Either[String, nodes.Method] =
      cpg.method.fullName(ref.methodFullName).headOption match {
        case Some(m) if m.name == "<init>" => Left("CLASS_CONSTRUCTOR_NOT_PUBLIC_API")
        case Some(m) => Right(m)
        case None => Left("METHODREF_TARGET_NOT_FOUND")
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
          case 1 => candidateAssigns.head.argument.l.find(_.argumentIndex == 2) match {
            case Some(ref: nodes.MethodRef) => methodFromRef(ref)
            case _ => Left("UNRESOLVED_RHS_SHAPE")
          }
          case _ => Left("AMBIGUOUS_IDENTIFIER_MULTIPLE_METHODREF_ASSIGNMENTS")
        }
      case _ => Left("UNRESOLVED_RHS_SHAPE")
    }
  }
  case class ExportedFn(method: nodes.Method, exportName: String)
  val exportedFns = scala.collection.mutable.ListBuffer[ExportedFn]()
  val exportAbstentions = scala.collection.mutable.ListBuffer[(String, String)]()
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
          case Some(lit: nodes.Literal) => (Some(unquote(lit.code)), false)
          case _ => (None, true)
        }
      case _ if lhsCode == "module.exports" => (Some("module.exports"), false)
      case _ => (Some(lhsCode.split("\\.").last), false)
    }
    if (dynamicKey) exportAbstentions += ((lhsCode, "DYNAMIC_COMPUTED_EXPORT_KEY"))
    else resolveExportRhs(rhsExpr, a.method) match {
      case Right(m) => exportedFns += ExportedFn(m, exportNameOpt.getOrElse("<unknown>"))
      case Left(reason) => exportAbstentions += ((lhsCode, reason))
    }
  }
  val distinctExportedFns = exportedFns.toList.groupBy(_.method.id).values.map(_.head).toList
  System.err.println(s"[$srcLabel] PACKAGE_API_INPUT exported functions resolved: ${distinctExportedFns.size} " +
    s"(${distinctExportedFns.map(e => s"${e.exportName}@${e.method.name}").mkString(",")})")
  if (exportAbstentions.nonEmpty)
    System.err.println(s"[$srcLabel] PACKAGE_API_INPUT export ABSTENTIONS: " +
      exportAbstentions.map { case (lhs, r) => s"$lhs=$r" }.mkString(" | "))
  val packageApiSources: List[nodes.Expression] = distinctExportedFns.flatMap { e =>
    e.method.parameter.filter(_.name != "this").l.flatMap(p => p.method.ast.isIdentifier.name(p.name).l.map(id => id: nodes.Expression))
  }.distinct
  System.err.println(s"[$srcLabel] PACKAGE_API_INPUT source candidates: ${packageApiSources.size}")

  val allSources: List[nodes.Expression] = (applicationIngressSources ++ packageApiSources).distinct
  def familyOfSource(e: nodes.Expression): String =
    if (packageApiSources.exists(_.id == e.id)) "PACKAGE_API_INPUT" else "APPLICATION_INGRESS_INPUT"

  def isSourceTainted(target: nodes.Expression): Boolean = {
    if (allSources.isEmpty) false
    else scala.util.Try {
      cpg.all.id(target.id).collectAll[nodes.Expression].reachableByFlows(allSources.iterator).l.nonEmpty
    }.getOrElse(false)
  }

  // ===== Sink target construction (5-way family split + corrected root handling, capability 5) ====
  cpg.call.l.foreach { c =>
    val fsMember = realFsMemberName(c)
    if (fsMember.exists(FS_ALL_NAMES.contains)) {
      fsFamilyOfName(fsMember.get).foreach { fam =>
        val args = c.argument.l.filter(_.argumentIndex >= 1)
        args.headOption.foreach { a0 => sinkTargets += SinkTarget(c, fam, a0) }
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
                // Condition (b) FAILS: root itself is attacker-reachable -- root is the real
                // location-determining operand here, so root (not the path arg) is what must be
                // tracked as attacker-controlled; the sub-path within it is not the issue.
                sinkTargets += SinkTarget(c, fam, rootExpr, "root itself is source-tainted -- root is the real attacker-controlled operand, not contained")
              } else {
                // All 4 conditions hold: exact options object supplies 'root' (findRootField
                // required a resolved Block), root is fixed/untainted (just confirmed), the path
                // arg is the operand Express's root-relative resolution confines, and no
                // laundering is possible since root itself was independently taint-checked. The
                // path arg is genuinely contained -- do not enumerate it as an attacker-controlled
                // full-location alternative. (Matches the audited file's already-correct
                // sendFile-only design; this file additionally applies it to EXPRESS_DOWNLOAD,
                // closing the asymmetry, and additionally proves condition (b) instead of assuming it.)
              }
            case RootAbsentResolved =>
              sinkTargets += SinkTarget(c, fam, pathArg)
            case RootUnresolvedOptions =>
              // Control #10: options arg present but not statically an object literal -- abstain,
              // never guess whether a 'root' key exists.
              sinkAbstentions += s"${fam} at L${c.lineNumber.getOrElse(-1)}: options argument not statically resolved to an object literal (${opt.code}) -- ABSTAIN on root-presence, no sink target emitted"
          }
        case (Some(pathArg), None) =>
          sinkTargets += SinkTarget(c, fam, pathArg)
        case _ =>
      }
    }
  }
  System.err.println(s"[$srcLabel] sink targets found: ${sinkTargets.size} " +
    s"(FS_READ=${sinkTargets.count(_.family == "FS_READ")}, FS_WRITE=${sinkTargets.count(_.family == "FS_WRITE")}, " +
    s"FS_DELETE=${sinkTargets.count(_.family == "FS_DELETE")}, EXPRESS_SEND_FILE=${sinkTargets.count(_.family == "EXPRESS_SEND_FILE")}, " +
    s"EXPRESS_DOWNLOAD=${sinkTargets.count(_.family == "EXPRESS_DOWNLOAD")})")
  if (sinkAbstentions.nonEmpty) sinkAbstentions.foreach(a => System.err.println(s"[$srcLabel] ABSTAIN: $a"))

  // ===================================================================================
  // ===== Capability 4/5: corrected containment idioms =====
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

  // A candidate is "canonicalized" when, in the SAME method, it is assigned the result of
  // path.resolve(...) or path.normalize(...) -- required BEFORE any boundary check on it counts,
  // per direct instruction ("a value that has gone through a REAL normalization/resolution step").
  def hasCanonicalizationAssignment(m: nodes.Method, varName: String): Boolean =
    m.ast.isCall.name("<operator>.assignment").l.exists { a =>
      val lhsMatches = a.argument.l.find(_.argumentIndex == 1).exists {
        case id: nodes.Identifier => id.code.trim == varName; case _ => false
      }
      lhsMatches && a.argument.l.find(_.argumentIndex == 2).exists {
        case rc: nodes.Call =>
          val short = if (rc.name == "<operator>.fieldAccess") rc.code.split("\\.").lastOption.getOrElse("") else rc.name
          short == "resolve" || short == "normalize"
        case _ => false
      }
    }

  def isPathSepOperand(e: nodes.Expression): Boolean = e match {
    case fld: nodes.Call if fld.name == "<operator>.fieldAccess" => fld.code.split("\\.").lastOption.contains("sep")
    case lit: nodes.Literal =>
      val s = unquote(lit.code); s == "/" || s == "\\" || s == "\\\\"
    case _ => false
  }
  // The corrected sibling-prefix fix: a `.startsWith(X)` call only counts as boundary-safe when X
  // is structurally `<base> + <path-separator>` (an addition literally containing a separator
  // operand) -- a bare `.startsWith(base)` (no separator) can never satisfy this, closing the
  // `/safe` vs `/safe-backup/secret` bug.
  def isBoundarySafeStartsWithArg(e: nodes.Expression): Boolean = e match {
    case add: nodes.Call if add.name == "<operator>.addition" => add.argument.l.exists(isPathSepOperand)
    case _ => false
  }

  // Searches `root` (either a dominating if's own condition, or a whole method body for the
  // wrapper-proof case) for a GENUINELE proven containment comparison: EITHER (a) a
  // `.startsWith(base + sep)` call whose receiver is both in `trackedCodes` AND itself
  // canonicalized in `m`, or (b) an equals/strictEquals comparison whose operand is in
  // `trackedCodes` AND itself canonicalized in `m`. Returns the matched code snippet.
  def findGenuineBoundaryCheck(root: nodes.AstNode, m: nodes.Method, trackedCodes: Set[String]): Option[String] = {
    val startsWithHit = root.ast.isCall.name("startsWith").l.find { sw =>
      val recv = sw.argument.l.find(_.argumentIndex == 0)
      val arg = sw.argument.l.find(_.argumentIndex == 1)
      recv.exists(r => trackedCodes.contains(r.code.trim) && hasCanonicalizationAssignment(m, r.code.trim)) &&
        arg.exists(isBoundarySafeStartsWithArg)
    }
    val equalsHit = root.ast.isCall.filter(cc => COMPARISON_OPS.contains(cc.name)).l.find { cc =>
      cc.argument.l.exists(o => trackedCodes.contains(o.code.trim) && hasCanonicalizationAssignment(m, o.code.trim))
    }
    startsWithHit.map(_.code).orElse(equalsHit.map(_.code))
  }

  // Weak/insufficient shapes that must NEVER by themselves produce BROKEN, but ARE surfaced as a
  // diagnostic note per direct instruction (capability 5): bare .startsWith/.includes without a
  // proven boundary+canonicalization, and a literal '..' strip via .replace (global or
  // non-global -- neither proves canonical containment against alternate separators or repeated
  // traversal components, per the audit's own bug description; item 4's own list of narrowly-
  // proven idioms does not include any regex-strip shape at all, so this file never promotes one
  // to BROKEN, closing the audit's bug #3 for both regex-flag variants, not just the non-global one).
  def collectWeakDiagnostics(sinkCall: nodes.Call, m: nodes.Method, trackedCodes: Set[String]): List[String] = {
    val notes = scala.collection.mutable.ListBuffer[String]()
    domIfCondition(sinkCall).foreach { cond =>
      cond.ast.isCall.name(CONTAINMENT_CHECK_METHODS.mkString("|")).l.foreach { cc =>
        val recv = cc.argument.l.find(_.argumentIndex == 0)
        if (recv.exists(r => trackedCodes.contains(r.code.trim))) {
          val provenElsewhere = findGenuineBoundaryCheck(cond, m, trackedCodes).contains(cc.code)
          if (!provenElsewhere) notes += s"weak ${cc.name} check without proven canonicalization+boundary: ${cc.code}"
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

  // Capability 4, third idiom: a wrapper function proven internally correct. Resolves the
  // dominating if-condition's own function call(s) to a real body (bodyChildCount>0, per the
  // real probe evidence in the header comment); recurses `findGenuineBoundaryCheck` against that
  // body using the callee's OWN first non-this parameter as the tracked candidate. An unresolved
  // callee (stub, bodyChildCount==0) OR a resolved body that does not itself prove containment
  // both correctly ABSTAIN (Left) rather than assume safety -- never silently promoted to BROKEN.
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
                // The wrapper's own internal check very often runs on a LOCAL variable derived
                // from the parameter (e.g. `const resolved = path.resolve(base, candidate)`), not
                // the bare parameter identifier itself -- so, mirroring the outer sink-level
                // derivedNames mechanism, trace real dataflow from the parameter to the wrapper's
                // own return expression(s) and fold every identifier confirmed on that path into
                // the tracked set before searching for a genuine boundary check.
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
      val otherSinkArgIds = sinkCall.argument.l.filter(_.argumentIndex >= 1).filterNot(_.id == destExpr.id).map(_.id).toSet
      val flowsRaw = scala.util.Try {
        cpg.all.id(destExpr.id).collectAll[nodes.Expression].reachableByFlows(Iterator(src: nodes.Expression)).l
      }.getOrElse(Nil)
      val flows = flowsRaw.filterNot(f => f.elements.dropRight(1).exists(e => otherSinkArgIds.contains(e.id)))
      val origin = familyOfSource(src)
      if (flows.isEmpty) {
        val sinkExprs = cpg.all.id(destExpr.id).collectAll[nodes.Expression].l
        lookupKeyInfluence(m, src, sinkExprs, otherSinkArgIds).foreach { lookupCode =>
          outRows += OutRow(sinkCall.id.toString, sinkCall.lineNumber.getOrElse(-1), src.id.toString,
            src.lineNumber.getOrElse(-1), src.code, origin, target.family, "OPEN",
            s"LOOKUP_KEY_INFLUENCE: key reaches $lookupCode, value itself does not flow to sink", Nil)
        }
      } else {
        val derivedNames: Set[String] = flows.flatMap(_.elements.collect { case id: nodes.Identifier => id.code.trim }).toSet
        val trackedCodes = Set(src.code.trim) ++ derivedNames
        val directGuard = domIfCondition(sinkCall).flatMap(cond => findGenuineBoundaryCheck(cond, m, trackedCodes))
        val wrapperGuard = if (directGuard.isEmpty) wrapperGuardResult(sinkCall, trackedCodes) else None
        val weakNotes = collectWeakDiagnostics(sinkCall, m, trackedCodes) ++
          (if (target.rootTaintNote.nonEmpty) List(target.rootTaintNote) else Nil)
        (directGuard, wrapperGuard) match {
          case (Some(cond), _) =>
            outRows += OutRow(sinkCall.id.toString, sinkCall.lineNumber.getOrElse(-1), src.id.toString,
              src.lineNumber.getOrElse(-1), src.code, origin, target.family, "BROKEN",
              s"canonicalized boundary-aware check: $cond", weakNotes)
          case (None, Some(Right(cond))) =>
            outRows += OutRow(sinkCall.id.toString, sinkCall.lineNumber.getOrElse(-1), src.id.toString,
              src.lineNumber.getOrElse(-1), src.code, origin, target.family, "BROKEN",
              s"structurally proven containment wrapper: $cond", weakNotes)
          case (None, Some(Left(cond))) =>
            outRows += OutRow(sinkCall.id.toString, sinkCall.lineNumber.getOrElse(-1), src.id.toString,
              src.lineNumber.getOrElse(-1), src.code, origin, target.family, "OPEN",
              s"UNVERIFIED_WRAPPER_GUARD: $cond (callee body unresolved or does not itself prove containment) -- abstaining", weakNotes)
          case (None, None) =>
            var effect = "PRESERVES"
            var note = ""
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
                      else if (!isKnownPreserving && effect == "PRESERVES") { effect = "UNKNOWN"; note = s"unrecognized call: $calleeShort" }
                    }
                  }
                }
              }
            }
            val finalOutcome = if (effect == "PRESERVES") "ESTABLISHED" else "OPEN"
            outRows += OutRow(sinkCall.id.toString, sinkCall.lineNumber.getOrElse(-1), src.id.toString,
              src.lineNumber.getOrElse(-1), src.code, origin, target.family, finalOutcome, note, weakNotes)
        }
      }
    }
  }

  // ===================================================================================
  // ===== Emit: same 4-file raw-fact schema adjudicate_js.py already consumes (12/9/5/8 cols) =====
  // source_facts.tsv columns 0-4 are read positionally by adjudicate_js.py (sink_id, sink_line,
  // src_id, origin_family, status) -- unchanged from the audited file's own schema, confirmed by
  // direct inspection (adjudicate_js.py never reads columns 5+). Column 5 (sink_family) and
  // column 6 (weak_diagnostic_guards, '|'-joined) are NEW, previously-always-blank columns
  // repurposed here -- adjudicate_js.py's own `rows(name, 12)` only requires exactly 12 fields per
  // row, never inspects 5+, so this is additive and does not change adjudicate_js.py's behavior.
  new java.io.File(rawDir).mkdirs()
  val sf = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/source_facts.tsv", true))
  val pr = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/propagation_relations.tsv", true))
  val po = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/property_outcome.tsv", true))
  val ti = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/transform_identity.tsv", true))
  outRows.foreach { r =>
    sf.println(Seq(r.sinkId, r.sinkLine, r.srcId, r.originFamily, "ESTABLISHED", r.sinkFamily,
      r.weakDiagnostics.mkString("|"), "", "", "", "", "").mkString("\t"))
    pr.println(Seq(r.sinkId, "", "", r.srcId, r.srcLine, r.srcCode, "", "", "").mkString("\t"))
    po.println(Seq(r.sinkId, r.srcId, r.outcome, "-1", "-1").mkString("\t"))
    System.err.println(s"[$srcLabel] EMIT sink=${r.sinkId}(L${r.sinkLine}) src=${r.srcId}(L${r.srcLine}:${r.srcCode}) " +
      s"origin=${r.originFamily} sinkFamily=${r.sinkFamily} outcome=${r.outcome} note=${r.note}" +
      (if (r.weakDiagnostics.nonEmpty) s" weak_diagnostic_guards=${r.weakDiagnostics.mkString("; ")}" else ""))
  }
  sf.close(); pr.close(); po.close(); ti.close()
  System.err.println(s"[$srcLabel] PATH_TRAV_R01_COMPLETE rows=${outRows.size} " +
    s"(BROKEN=${outRows.count(_.outcome == "BROKEN")}, OPEN=${outRows.count(_.outcome == "OPEN")}, " +
    s"ESTABLISHED=${outRows.count(_.outcome == "ESTABLISHED")})")

  val summary = new java.io.PrintWriter(new java.io.FileWriter(s"$rawDir/path_traversal_r01_summary.json"))
  summary.println(s"""{"sink_targets": ${sinkTargets.size}, "sink_abstentions": ${sinkAbstentions.size}, """ +
    s""""package_api_sources": ${packageApiSources.size}, "application_ingress_sources": ${applicationIngressSources.size}, """ +
    s""""exported_functions_resolved": ${distinctExportedFns.size}, "export_abstentions": ${exportAbstentions.size}, """ +
    s""""rows_emitted": ${outRows.size}, "broken": ${outRows.count(_.outcome == "BROKEN")}, """ +
    s""""open": ${outRows.count(_.outcome == "OPEN")}, "established": ${outRows.count(_.outcome == "ESTABLISHED")}}""")
  summary.close()
}
