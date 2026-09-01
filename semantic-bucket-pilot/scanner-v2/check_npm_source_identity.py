#!/usr/bin/env python3
"""NPM-SOURCE-IDENTITY-R01 regression: runs against FROZEN real Joern output
(export_npm_source_identity.sc, pinned Joern version -- see
tchecker-research-complete/tchecker-property-adjudicator/fixtures/npm_source_identity_r01/),
checked into that fixtures directory so this reproduces without needing Joern again -- the same
convention as check_redos_verdict.py's own `study/redos_npm/fixtures/`.

Covers, per direct instruction, real regression evidence for all 7 required capabilities:
  1. closure captures resolved through real refsTo/closureBindingId/ClosureBinding identity
  2. lexical shadowing / same-name parameters kept distinct
  3. deterministic output (byte-for-byte structural sortedness; the actual two-independent-Joern-
     run diff is quoted verbatim, real, in docs/milestones/NPM_SOURCE_IDENTITY_R01_IMPLEMENTATION.md
     -- not re-run here, since this script deliberately never shells out to Joern, matching
     check_redos_verdict.py's own frozen-fixture convention)
  4. MULTIPLE_ORIGINS -- never collapsed to one row
  5. canonical source paths + content hashes
  6. package-owned vs vendored attribution
  7. vendored-code deduplication while retaining every exposing package
plus the real motifer/logify/miniml/ms package validation (raw_real_packages/).
"""
import pathlib
import sys
import tempfile

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
import npm_source_identity as nsi  # noqa: E402
import provenance  # noqa: E402
import vendored_attribution  # noqa: E402

FX = pathlib.Path(
    "/home/user/bug_tracker/tchecker-research-complete/tchecker-property-adjudicator"
    "/fixtures/npm_source_identity_r01"
)
RAW = FX / "raw"
RAW_REAL = FX / "raw_real_packages"

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


# =========================================================================================
# Requirement 1: closure captures via real refsTo/closureBindingId/ClosureBinding identity
# (synthetic fixtures)
# =========================================================================================
identity_rows = nsi.read_closure_identity(str(RAW))
by_id = {r["identifier_id"]: r for r in identity_rows}

# cap1_module_closure_capture.js: configure() writes handlerState, useState() reads it -- both
# CAPTURED, resolving to the SAME module-scope root Local (never guessed by name -- confirmed by
# a shared resolved_root_id across two DIFFERENT identifier references in two DIFFERENT methods).
cap1_rows = [r for r in identity_rows if r["file"] == "cap1_module_closure_capture.js"
             and r["identifier_code"] == "handlerState" and r["resolution_kind"] == "CAPTURED"]
ck("CAP1: handlerState captured in BOTH configure() and useState(), same real resolved root",
   len(cap1_rows) == 2 and len({r["resolved_root_id"] for r in cap1_rows}) == 1
   and cap1_rows[0]["resolved_root_kind"] == "LOCAL" and cap1_rows[0]["capture_depth"] == "1")

# cap1_two_level_nested_capture.js: a 3-level real nesting chain (module -> makeOuter -> outer ->
# inner) resolved via RECURSIVE closureBindingId walking (generalizing exactHandlerDefinition's
# own single-hop `_refOut` lookup) -- capture_depth must be 3, not 1.
two_level = [r for r in identity_rows if r["file"] == "cap1_two_level_nested_capture.js"
             and r["identifier_code"] == "counter" and r["method_full_name"].endswith(":inner")]
ck("CAP1: a 3-level-nested closure capture resolves with capture_depth==3 (recursive chain-walk, "
   "not a single hop)",
   len(two_level) == 1 and two_level[0]["capture_depth"] == "3"
   and two_level[0]["resolution_kind"] == "CAPTURED")

# AMBIGUOUS: RE reassigned twice at module scope before the nested closure that reads it --
# real, identity-based (never name-matching) reassignment-ambiguity abstention.
ambiguous_rows = [r for r in identity_rows if r["file"] == "ambiguous_closure_reassignment.js"
                   and r["resolution_kind"] == "AMBIGUOUS"]
ck("CAP1 (abstention): RE reassigned before capture -> AMBIGUOUS, "
   "MULTIPLE_LIVE_ASSIGNMENTS_TO_RESOLVED_LOCAL, real closure-identity abstention (never guessed)",
   len(ambiguous_rows) == 3
   and all(r["note"] == "MULTIPLE_LIVE_ASSIGNMENTS_TO_RESOLVED_LOCAL" for r in ambiguous_rows))

# =========================================================================================
# Requirement 2: lexical shadowing / same-name parameters kept distinct (synthetic fixtures)
# =========================================================================================
alpha_req = by_id.get("68719476793") or next(
    r for r in identity_rows if r["file"] == "cap2_shadow_same_name_params.js"
    and r["line"] == "6" and r["identifier_code"] == "req")
beta_req = next(r for r in identity_rows if r["file"] == "cap2_shadow_same_name_params.js"
                 and r["line"] == "10" and r["identifier_code"] == "req")
ck("CAP2: two exported functions' own identically-named `req` parameters resolve to DISTINCT "
   "real MethodParameterIn roots -- never conflated",
   alpha_req["resolved_root_kind"] == "METHOD_PARAMETER_IN"
   and beta_req["resolved_root_kind"] == "METHOD_PARAMETER_IN"
   and alpha_req["resolved_root_id"] != beta_req["resolved_root_id"])

outer_label = next(r for r in identity_rows if r["file"] == "cap2_shadow_nested_scope.js"
                    and r["method_full_name"].endswith(":describeOuter")
                    and r["identifier_code"] == "label")
inner_label = next(r for r in identity_rows if r["file"] == "cap2_shadow_nested_scope.js"
                    and r["method_full_name"].endswith(":nested")
                    and r["identifier_code"] == "label")
ck("CAP2: module-scope `label` (read by describeOuter) and describeInner's own inner-scope "
   "`label` resolve to DISTINCT real Locals -- the inner closure's read never falls back to the "
   "unrelated outer declaration",
   outer_label["resolved_root_id"] != inner_label["resolved_root_id"])

# =========================================================================================
# Requirement 3: deterministic output -- structural sortedness of the frozen, committed files
# (the real two-independent-run byte-for-byte diff is quoted in the milestone doc)
# =========================================================================================
def _is_sorted_closure_identity(rows):
    ids = [int(r["identifier_id"]) for r in rows]
    return ids == sorted(ids)


def _is_sorted_origin_facts(rows):
    keys = [(int(r["site_id"]), r["origin_family"]) for r in nsi.read_source_origin_facts(str(RAW))]
    return keys == sorted(keys)


ck("DETERMINISM: closure_identity.tsv (synthetic fixture) is sorted by identifier_id (int)",
   _is_sorted_closure_identity(identity_rows))
ck("DETERMINISM: source_origin_facts.tsv (synthetic fixture) is sorted by (site_id int, family)",
   _is_sorted_origin_facts(RAW))
real_identity_rows = nsi.read_closure_identity(str(RAW_REAL))
ck("DETERMINISM: closure_identity.tsv (real motifer/logify/miniml/ms run) is sorted by "
   "identifier_id (int) -- same sort discipline holds at real-package scale (3329 rows)",
   _is_sorted_closure_identity(real_identity_rows))

# =========================================================================================
# Requirement 4: MULTIPLE_ORIGINS -- never collapsed to one row (synthetic fixtures)
# =========================================================================================
fams = nsi.families_by_site(str(RAW))
multi_site_rows = [r for r in nsi.read_source_origin_facts(str(RAW))
                    if r["file"] == "cap4_multiple_origins.js"]
ck("CAP4: the SAME site (an exported function's own bare `req` parameter reference) carries "
   "BOTH PACKAGE_API_INPUT and APPLICATION_INGRESS_INPUT as two SEPARATE rows -- never collapsed",
   len(multi_site_rows) == 2
   and {r["origin_family"] for r in multi_site_rows} == {"PACKAGE_API_INPUT", "APPLICATION_INGRESS_INPUT"}
   and all(r["multi_origin"] and r["origin_count"] == 2 for r in multi_site_rows))

single_site_rows = [r for r in nsi.read_source_origin_facts(str(RAW))
                     if r["file"] == "cap4_single_origin_control.js"]
ck("CAP4 (negative control): an ordinary PACKAGE_API_INPUT-only site emits exactly ONE row, "
   "multi_origin=false, origin_count=1 -- MULTIPLE_ORIGINS machinery does not over-fire",
   len(single_site_rows) == 1 and single_site_rows[0]["origin_family"] == "PACKAGE_API_INPUT"
   and not single_site_rows[0]["multi_origin"] and single_site_rows[0]["origin_count"] == 1)

# =========================================================================================
# Export-surface regression (CommonJS + ESM named/default + class + object-literal + honest
# abstentions -- generalizing resolveExportRhs/R02's class+object-literal capabilities)
# =========================================================================================
export_rows = nsi.read_export_surface(str(RAW))
by_export_id = {}
for r in export_rows:
    by_export_id.setdefault(r["file"], []).append(r)

ck("EXPORT: commonjs_direct_export.js resolves module.exports = function(...) directly (no "
   "identifier indirection)",
   any(r["file"] == "commonjs_direct_export.js" and r["resolution_status"] == "RESOLVED"
       for r in export_rows))
ck("EXPORT: class_export_control.js -- constructor ABSTAINED (CLASS_CONSTRUCTOR_NOT_PUBLIC_API), "
   "its 2 OTHER instance methods RESOLVED as CLASS_INSTANCE_METHOD",
   any(r["file"] == "class_export_control.js" and r["abstain_reason"] == "CLASS_CONSTRUCTOR_NOT_PUBLIC_API"
       for r in export_rows)
   and sum(1 for r in export_rows if r["file"] == "class_export_control.js"
           and r["rhs_kind"] == "CLASS_INSTANCE_METHOD" and r["resolution_status"] == "RESOLVED") == 2)
ck("EXPORT: object_literal_export_control.js -- both `foo`/`bar` shorthand properties RESOLVED",
   sum(1 for r in export_rows if r["file"] == "object_literal_export_control.js"
       and r["resolution_status"] == "RESOLVED") == 2)
ck("EXPORT: reexport_abstention.js (`export * from ...`, miniml's own real re-export shape) "
   "honestly ABSTAINS as REEXPORT_UNRESOLVED -- never silently dropped, never guessed",
   any(r["file"] == "reexport_abstention.js" and r["abstain_reason"] == "REEXPORT_UNRESOLVED"
       for r in export_rows))
ck("EXPORT: dynamic_export_key.js (`module.exports[key] = fn`, non-literal key) ABSTAINS "
   "DYNAMIC_COMPUTED_EXPORT_KEY",
   any(r["file"] == "dynamic_export_key.js" and r["abstain_reason"] == "DYNAMIC_COMPUTED_EXPORT_KEY"
       for r in export_rows))
ck("EXPORT: esm_named_default_export.js -- both ESM named AND default exports RESOLVED (confirms "
   "the R01-documented desugar-to-CommonJS-shape claim inside THIS new producer)",
   sum(1 for r in export_rows if r["file"] == "esm_named_default_export.js"
       and r["resolution_status"] == "RESOLVED") == 2)

# =========================================================================================
# Real motifer + logify + miniml + ms package validation (raw_real_packages/)
# =========================================================================================
real_rows = nsi.read_closure_identity(str(RAW_REAL))
motifer_logger = [r for r in real_rows if r["file"] == "motifer/index.js" and r["identifier_code"] == "logger"]
logify_logger = [r for r in real_rows if "logify" in r["file"] and r["identifier_code"] == "logger"]

ck("REAL (motifer-26.1.1): the module-scope `logger` (`let logger = null;`) is DIRECT at its own "
   "declaration site and CAPTURED everywhere it is read from a nested function (LoggerObject, "
   "LoggerFactory, ExpressLoggerFactory, write) -- ALL resolving to the SAME real root Local",
   any(r["resolution_kind"] == "DIRECT" for r in motifer_logger)
   and any(r["resolution_kind"] == "CAPTURED" for r in motifer_logger)
   and len({r["resolved_root_id"] for r in motifer_logger if r["resolution_kind"] in ("DIRECT", "CAPTURED")}) == 1)

ck("REAL (motifer-26.1.1): a genuine 2-level-nested real closure (the arrow function passed to "
   "express.use(...), itself nested inside ExpressLoggerFactory) resolves logger with "
   "capture_depth==2 -- the recursive chain-walk generalization is exercised on real code, not "
   "just a synthetic fixture",
   any(r["capture_depth"] == "2" for r in motifer_logger))

motifer_root = next(r["resolved_root_id"] for r in motifer_logger if r["resolution_kind"] == "DIRECT")
logify_roots = {r["resolved_root_id"] for r in logify_logger}
ck("REAL (motifer vs logify): motifer's own module-scope `logger` and logify's own, completely "
   "unrelated `logger` locals (dist/index.js's Logger.prototype.child() + plugin/event.js's own "
   "init(logger) parameter) resolve to REAL, DISTINCT CPG node ids in the SAME combined CPG -- "
   "never conflated across two unrelated real npm packages",
   motifer_root not in logify_roots and len(logify_roots) == 2)

real_export_rows = nsi.read_export_surface(str(RAW_REAL))
motifer_exports = [r for r in real_export_rows if r["file"] == "motifer/index.js"]
ck("REAL (motifer-26.1.1): module.exports = {LoggerFactory, ExpressLoggerFactory, Logger, "
   "ApmFactory} -- 3 plain functions RESOLVED, Logger's own constructor ABSTAINED "
   "(CLASS_CONSTRUCTOR_NOT_PUBLIC_API), Logger.prototype.getLogger RESOLVED as its real public API",
   sum(1 for r in motifer_exports if r["resolution_status"] == "RESOLVED"
       and r["rhs_kind"] == "MODULE_EXPORTS_ASSIGN") == 3
   and any(r["abstain_reason"] == "CLASS_CONSTRUCTOR_NOT_PUBLIC_API" for r in motifer_exports)
   and any(r["export_name"] == "Logger.prototype.getLogger" and r["resolution_status"] == "RESOLVED"
           for r in motifer_exports))

ms_exports = [r for r in real_export_rows if r["file"] == "ms/index.js"]
ck("REAL (ms-2.1.3): minimal positive control -- module.exports = function(val, options){...} "
   "resolves directly",
   any(r["resolution_status"] == "RESOLVED" for r in ms_exports))

miniml_reexports = [r for r in real_export_rows
                     if r["file"] in ("miniml/index.js", "miniml/lib/index.js")]
ck("REAL (miniml-1.0.19): all 6 real `export * from ...` re-export lines (index.js + lib/index.js) "
   "honestly ABSTAIN as REEXPORT_UNRESOLVED -- a real, distinctly-labeled abstention, never a "
   "silent gap and never a guessed resolution through the re-export chain",
   len(miniml_reexports) == 6
   and all(r["abstain_reason"] == "REEXPORT_UNRESOLVED" for r in miniml_reexports))

miniml_resolved = [r for r in real_export_rows if r["file"].startswith("miniml/") and r["resolution_status"] == "RESOLVED"]
ck("REAL (miniml-1.0.19): plenty of its own real named function exports (validateSqlExpression, "
   "loadYamlFile, renderQuery, ...) resolve normally alongside the honest re-export abstentions",
   len(miniml_resolved) >= 15)

# =========================================================================================
# Requirement 5: canonical source paths + content hashes (build_js_source_manifest, reusing
# provenance.py verbatim -- confirmed by identity, never reimplemented)
# =========================================================================================
ck("REUSE: npm_source_identity.sha256_hex IS provenance.sha256_hex (same function object, "
   "never reimplemented)", nsi.sha256_hex is provenance.sha256_hex)
ck("REUSE: npm_source_identity.compute_source_tree_sha256 IS provenance's own",
   nsi.compute_source_tree_sha256 is provenance.compute_source_tree_sha256)
ck("REUSE: npm_source_identity.classify_vendored_hint IS provenance's own",
   nsi.classify_vendored_hint is provenance.classify_vendored_hint)

with tempfile.TemporaryDirectory() as td:
    tdp = pathlib.Path(td)
    (tdp / "index.js").write_text("module.exports = function(x){ return x; };\n")
    (tdp / "vendor").mkdir()
    (tdp / "vendor" / "somelib").mkdir()
    (tdp / "vendor" / "somelib" / "x.js").write_bytes(b"var SAME = 1;\n")
    manifest = nsi.build_js_source_manifest(str(tdp), "demo-pkg", "1.0.0", tarball_bytes=b"fake-tarball")
    ck("CAP5: build_js_source_manifest resolves a real relpath -> real sha256 content_hash + "
       "provenance_hint (PACKAGE_OWNED_HINT for index.js, VENDORED_HINT for vendor/somelib/x.js)",
       manifest["files"]["index.js"]["provenance_hint"] == "PACKAGE_OWNED_HINT"
       and manifest["files"]["vendor/somelib/x.js"]["provenance_hint"] == "VENDORED_HINT"
       and manifest["files"]["index.js"]["content_hash"] == provenance.sha256_hex(
           b"module.exports = function(x){ return x; };\n"))
    ck("CAP5: source_tree_sha256 is REPRODUCIBLE (rebuilding the manifest from the same tree "
       "gives the SAME hash) and independent of the tarball_bytes passed in",
       nsi.build_js_source_manifest(str(tdp), "demo-pkg", "9.9.9", tarball_bytes=b"different-bytes")
       ["source_tree_sha256"] == manifest["source_tree_sha256"])

    sf_ok = nsi.lookup_source_fact("index.js", manifest)
    ck("CAP5: lookup_source_fact resolves a real raw-output `file` field against the manifest",
       sf_ok["resolved"] and sf_ok["content_hash"] == manifest["files"]["index.js"]["content_hash"])
    sf_missing = nsi.lookup_source_fact("does/not/exist.js", manifest)
    ck("CAP5: lookup_source_fact fails CLOSED (resolved=False, real reason) for a path the "
       "manifest never saw -- never guessed, never silently skipped",
       not sf_missing["resolved"] and sf_missing["provenance_hint"] == "PATH_NOT_IN_MANIFEST")

    # strip_prefix: simulate export_npm_source_identity.sc's own real "combined multi-package
    # root" file-path convention (e.g. "demo-pkg/index.js" from the real motifer+logify CPG run).
    sf_prefixed = nsi.lookup_source_fact("demo-pkg/vendor/somelib/x.js", manifest, strip_prefix="demo-pkg")
    ck("CAP5: lookup_source_fact's strip_prefix correctly joins a combined-multi-package-root "
       "raw file field back to a SINGLE package's own manifest",
       sf_prefixed["resolved"] and sf_prefixed["source_path"] == "vendor/somelib/x.js")

# =========================================================================================
# Requirements 6 + 7: package-owned vs vendored attribution + cross-package vendored dedup,
# retaining EVERY exposing package (via vendored_attribution.py's real, unmodified
# attribute_finding, and its one additive `keys` parameter on aggregate_vendored_dedup)
# =========================================================================================
with tempfile.TemporaryDirectory() as td:
    tdp = pathlib.Path(td)
    for pkg in ("pkg-alpha", "pkg-beta"):
        (tdp / pkg / "vendor" / "somelib").mkdir(parents=True)
        (tdp / pkg / "vendor" / "somelib" / "shared.js").write_bytes(b"var VULN = 1;\n")
        (tdp / pkg / "lib").mkdir(parents=True)
        (tdp / pkg / "lib" / "own.js").write_text("module.exports = function(){ return 1; };\n")

    manifests = {
        pkg: nsi.build_js_source_manifest(str(tdp / pkg), pkg, "1.0.0")
        for pkg in ("pkg-alpha", "pkg-beta")
    }
    findings_by_package = {}
    for pkg in ("pkg-alpha", "pkg-beta"):
        m = manifests[pkg]
        vendored_fact = nsi.lookup_source_fact("vendor/somelib/shared.js", m)
        owned_fact = nsi.lookup_source_fact("lib/own.js", m)
        findings_by_package[pkg] = [
            nsi.make_finding(pkg, "site-vendored", "PACKAGE_API_INPUT", vendored_fact,
                              file="vendor/somelib/shared.js", line="1", site_code="VULN"),
            nsi.make_finding(pkg, "site-owned", "PACKAGE_API_INPUT", owned_fact,
                              file="lib/own.js", line="1", site_code="own"),
        ]

    records, aggregated = nsi.attribute_and_dedup_by_package(findings_by_package)

    owned_finding = findings_by_package["pkg-alpha"][1]
    ck("CAP6: a PACKAGE_OWNED_HINT finding is left UNTOUCHED by vendored attribution (no "
       "vendored_attribution field attached at all -- attribution is additive/conditional)",
       "vendored_attribution" not in owned_finding)

    vendored_finding = findings_by_package["pkg-alpha"][0]
    ck("CAP6: a VENDORED_HINT finding IS attributed, real library id extracted from the path "
       "(vendor/somelib/... -> 'somelib'), attribution string names BOTH the library and the "
       "bundling package",
       vendored_finding.get("vendored_attribution", {}).get("status") == "ATTRIBUTED"
       and vendored_finding["vendored_attribution"]["vendored_library_id"] == "somelib"
       and vendored_finding["vendored_attribution"]["attribution"] == "somelib as bundled by pkg-alpha")

    buckets = aggregated[nsi.NPM_SOURCE_IDENTITY_FINDING_KEY]
    ck("CAP7: the byte-identical vendored file bundled by BOTH pkg-alpha and pkg-beta "
       "deduplicates to EXACTLY ONE bucket (never 2 -- content-hash-based dedup, not "
       "per-package-independent counting)",
       len(buckets) == 1)
    only_bucket = next(iter(buckets.values()))
    ck("CAP7: the deduplicated bucket's own `packages` list retains BOTH exposing packages "
       "(never drops one) and its raw_exposure_count reflects both real occurrences",
       only_bucket["packages"] == ["pkg-alpha", "pkg-beta"] and only_bucket["raw_exposure_count"] == 2)

    summary = nsi.summarize(aggregated)
    ck("CAP7: summarize() reports deduplicated_count=1 alongside raw_exposure_count=2 -- the two "
       "headline numbers side by side, never collapsed into one",
       summary == {"deduplicated_count": 1, "raw_exposure_count": 2})

    ck("ADDITIVE CHANGE: vendored_attribution.aggregate_vendored_dedup's existing C/C++ default "
       "behavior (keys=None -> ALL_FINDING_KEYS) is UNCHANGED -- a record with no npm-shaped key "
       "at all still yields the same empty-bucket shape for every one of the original 9 keys",
       set(vendored_attribution.aggregate_vendored_dedup([{"package_name": "x"}]).keys())
       == set(vendored_attribution.ALL_FINDING_KEYS))

print(f"NPM_SOURCE_IDENTITY_R01={ok}/{total}")
sys.exit(0 if ok == total else 1)
