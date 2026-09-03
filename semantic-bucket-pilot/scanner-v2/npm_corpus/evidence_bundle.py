#!/usr/bin/env python3
"""R06 persistence fix: writes a MINIMAL, COMPRESSED, per-package evidence bundle before a
package's work_root is deleted, so a future verdict-only rerun (R06 corpus-wide pass, or any
later scanner revision) does not require a full Joern rebuild for every package -- only for
whichever subset actually needs re-verdicting.

Real bug this fixes: the frozen `run_pipeline_one.py` (PIPELINE_FREEZE.md,
`1c031795a3383ff63aa1a22e382daeae`) unconditionally `shutil.rmtree(work_root, ...)`s
EVERYTHING after each package -- CPG binaries, raw exported TSVs, normalized JSON, scanner
outputs -- leaving nothing but the summary JSONL row. This module is deliberately NOT a
change to that frozen file (it stays frozen, untouched, still driving the live R05 baseline
run) -- it is new code for the SEPARATE, corrected future pipeline
(`run_pipeline_one_r06.py`), developed and tested here on the isolated `claude/r06-precision-
fix` branch only.

What is kept (deliberately NOT "normalized only" -- see below) vs. what stays deleted:

  KEPT (bundled):
  - `cpp_raw/*.tsv`         -- RAW exported C++ facts. Required as-is: resource_guard_verdict_
                               r04/r05/r06.py all read `<raw>/methods.tsv` etc. directly, never
                               the normalized cpp_facts.json. A bundle without this could not
                               actually support a verdict-only R06 rerun -- this is a real
                               technical requirement, not a stylistic choice, and is called out
                               explicitly here because "normalized JS/C++ facts" alone would be
                               insufficient for R06's own real input contract.
  - `cpp_facts.json`        -- normalized C++ facts, the real input link_napi_facts.py (FIX01I)
                               consumes for its cpp_program argument.
  - `js_facts.json`         -- normalized JS facts, the real input (after the cheap, small,
                               deterministic polyglot_compat_adapter.py step, NOT itself
                               persisted separately -- re-running that adapter at rerun time is
                               instant and avoids bundling a redundant near-duplicate file).
  - `build_config.json`     -- this package's own exception-configuration evidence.
  - `cross_language_bindings.json` -- the REGISTRATION/LINK evidence link_napi_facts.py (FIX01I)
                               actually produced (registrations, linked_calls, unlinked_calls),
                               extracted from `merged.json` rather than keeping the whole merged
                               document, which would otherwise duplicate cpp_facts.json/
                               js_facts.json's own bulk with no new information.
  - `r04_out.json`, `r05_out.json`, `r06_out.json` -- the scanner outputs already computed
                               for this package.
  - `redos_raw`             -- RAW exported ReDoS facts (export_redos_npm_integ_r02.sc's own
                               source_facts.tsv/propagation_relations.tsv/property_outcome.tsv/
                               transform_identity.tsv output), same real requirement and same
                               treatment as `cpp_raw` above: redos_verdict.py reads this
                               directory directly, so a bundle without it could not support a
                               verdict-only ReDoS rerun either.
  - `redos_out.json`        -- the ReDoS scanner output already computed for this package
                               (roadmap step 8's run_pipeline_one_r06.py wiring).
  - `pt_raw`                 -- RAW exported Path Traversal facts (export_path_traversal_integ_r02
                               .sc's own source_facts.tsv/propagation_relations.tsv/
                               property_outcome.tsv/transform_identity.tsv/sink_abstentions.tsv
                               output, PLUS export_npm_source_identity_r02.sc's own
                               source_origin_facts.tsv/export_surface.tsv/closure_identity.tsv --
                               both producers write into this SAME directory, and
                               path_traversal_verdict.py reads it directly), same real
                               requirement and treatment as `redos_raw` above.
  - `path_traversal_out.json` -- the Path Traversal scanner output already computed for this
                               package (roadmap step 8's run_pipeline_one_r06.py wiring, second
                               JS/TS class).
  - `sd_facts`                -- RAW exported Serialize DoS facts (export_serialize_facts.sc's
                               own serialize_sinks.tsv/uncaught_handlers.tsv/depth_guards.tsv,
                               PLUS transform_presence.sc's own transform_presence.tsv -- both
                               producers write into this SAME directory, and
                               serialize_dos_r03.py's own derive() reads it directly), same real
                               requirement and treatment as redos_raw/pt_raw above.
  - `sd_taint_raw`            -- RAW per-package taint-engine sub-pipeline output
                               (setup_candidate_multisource.sc's own source_facts.tsv/
                               propagation_relations.tsv/transform_identity.tsv/
                               multisource_evidence.tsv/definition_resolution.tsv, PLUS
                               export_property_propagation.sc's own property_propagation.tsv/
                               property_outcome.tsv, one subdirectory per distinct sink-file
                               package key) -- only present when at least one qualifying
                               attacker-controlled-unbounded-stringify sink existed (the common
                               case has none, and this directory is legitimately absent/empty).
                               Listed in `OPTIONAL_RELATIVE_PATHS`, not `BUNDLED_RELATIVE_PATHS`
                               -- its absence is disclosed (`manifest["optional_missing"]`) but
                               never counted against `completeness_status`.
  - `sd_taint_evidence`       -- per-package adjudicate_js.py evidence_final.json output (one
                               subdirectory per distinct sink-file package key), same
                               "legitimately absent when nothing qualified, and never penalized"
                               treatment as sd_taint_raw above (also in `OPTIONAL_RELATIVE_PATHS`).
  - `serialize_dos_out.json`  -- the Serialize DoS scanner output already computed for this
                               package (roadmap step 8's run_pipeline_one_r06.py wiring, third
                               JS/TS class), same real precedent as redos_out.json/
                               path_traversal_out.json above. Always written on a successful run
                               (regardless of whether the taint sub-pipeline ran), so this one
                               stays in `BUNDLED_RELATIVE_PATHS` like every other `*_out.json`.

  NOT kept (stays deleted, per the explicit instruction to keep deleting large CPG/work dirs):
  - `cpp.cpg.bin`, `js.cpg.bin` -- the large Joern CPG binaries.
  - `pkg/` (extracted npm tarball source), `headers/` (staged node-addon-api/nan headers) --
    both cheaply re-fetchable from the same pinned tarball_url / registry version if ever
    needed again; neither is scanner evidence.
  - `js_raw/*.tsv` -- NOT currently consumed by any downstream stage in THIS pipeline (only
    js_facts.json, its normalized form, is). Disclosed scope boundary, not an oversight: the
    real closure/CFG facts FIX01I ultimately needs (per FIX01H/I's own frozen design on
    `claude/crosslang-linker-fix`) require an EXTENDED export_neutral.sc this pipeline does not
    yet run -- that is the already-planned separate "regenerate JS facts with CFG and closure
    facts" pass, not something this persistence fix silently tries to backfill.
  - `*.log`, `merged.json` (superseded by the smaller `cross_language_bindings.json` extract).

Atomicity: written to a temp path in the SAME directory as the final bundle path, then
`os.rename`'d into place -- atomic on the same filesystem, identical idiom to
`make_checkpoint.py`'s own atomic-write. A reader can never observe a partially-written
bundle file.

BUNDLE INTEGRITY (item 4): every manifest records, alongside `included`/`missing`:
  - `schema_version` -- `"evidence_bundle/2"`. A future consumer checks this before
    assuming the manifest's own shape; bumped whenever a field is added/removed/renamed.
  - `package_name`/`version` -- already required, unchanged.
  - `tarball_sha256` -- sha256 of the REAL npm tarball bytes this package's facts were
    derived from (passed in by the caller, which already has them from the download stage;
    `None`, disclosed, if the caller doesn't supply it -- never fabricated).
  - `analyzer_hashes` -- sha256 of the real analyzer source files that PRODUCED this
    bundle's evidence (`resource_guard_verdict_r06.py`, `extract_build_config.py`,
    `run_pipeline_one_r06.py`, `evidence_bundle.py` itself), hashed at bundle-write time --
    lets a downstream consumer detect that a bundle was produced by a DIFFERENT analyzer
    revision than the one currently checked out, before trusting its verdicts as comparable.
  - `artifact_hashes` -- sha256 of each INDIVIDUAL bundled file's own real bytes (not just
    the aggregate `compressed_bytes`/bundle-level sha256 already recorded elsewhere), keyed
    by the same relative path as `included`.
  - `completeness_status` -- `"COMPLETE"` only when every real path in
    `BUNDLED_RELATIVE_PATHS` was actually included (`missing` is empty) AND the caller's own
    `pipeline_status` (if supplied) is `"ANALYZED"`; `"PARTIAL"` otherwise. A partial or
    resource-limited package (a genuinely real, disclosed outcome, not an error in this
    module) still gets whatever real evidence it has bundled -- but is marked so a consumer
    cannot mistake it for complete evidence. See `require_complete_bundle()` below for the
    loader-side guard that enforces this. `optional_missing` (an absent path from
    `OPTIONAL_RELATIVE_PATHS` -- see below) is disclosed the same way but deliberately NOT
    part of this check: an entry there is absent because of a real, expected upstream
    decision (e.g. Serialize DoS's own taint-engine sub-pipeline correctly not running at
    all when nothing qualified it), not because anything failed or was skipped.
"""
import gzip
import hashlib
import io
import json
import os
import tarfile

# Real per-package facts this bundle preserves -- see module docstring for why each is (or
# is not) included. Paths are relative to work_root/work/ except cpp_raw/ which is a directory.
BUNDLED_RELATIVE_PATHS = (
    "cpp_raw",             # directory of raw TSVs -- required as-is by R04/R05
    "cpp_facts.json",      # normalized C++ facts -- required by link_napi_facts.py (FIX01I)
    "js_facts.json",       # normalized JS facts -- required by link_napi_facts.py (FIX01I)
    "build_config.json",
    "r04_out.json",
    "r05_out.json",
    # OVERNIGHT-DIAGNOSTIC-100: adapted from the original R06 list (dropped r06_out.json --
    # #41 has not merged R06/FIX01I into the driven r04/r05 lineage, so this diagnostic run
    # does not produce it; see PRECISION_FIX_NOT_INTEGRATED in run_diagnostic_100.py) and added
    # the five newly-wired diagnostic-only property scanners' own raw output files.
    "lock_balance_out.json",
    "protected_field_out.json",
    "oob_write_out.json",
    "oob_index_write_out.json",
    "oob_read_out.json",
    "oob_compare_out.json",
    # REDOS INTEGRATION (roadmap step 8): redos_raw follows the exact same "bundle the raw-
    # output directory as-is" precedent as cpp_raw above; redos_out.json follows the exact same
    # precedent as r04_out.json/r05_out.json/r06_out.json.
    "redos_raw",
    "redos_out.json",
    # PATH TRAVERSAL INTEGRATION (roadmap step 8): pt_raw follows the exact same "bundle the raw-
    # output directory as-is" precedent as cpp_raw/redos_raw above (it holds BOTH producers' own
    # output, written into the same directory); path_traversal_out.json follows the exact same
    # precedent as redos_out.json.
    "pt_raw",
    "path_traversal_out.json",
    # SERIALIZE DOS INTEGRATION (roadmap step 8, third JS/TS class): sd_facts follows the exact
    # same "bundle the raw-output directory as-is, required" precedent as cpp_raw/redos_raw/
    # pt_raw above (every successful run writes it); serialize_dos_out.json follows the exact
    # same precedent as redos_out.json/path_traversal_out.json above. sd_taint_raw/
    # sd_taint_evidence are NOT here -- see OPTIONAL_RELATIVE_PATHS below, since (unlike every
    # other entry in this tuple) they are legitimately, expectedly absent on the common-case
    # successful run (a package with no qualifying attacker-controlled-unbounded-stringify sink
    # never runs the taint-engine sub-pipeline at all -- see run_pipeline_one_r06.py's own
    # Serialize DoS stage), and this tuple's own semantics (an absent entry always counts
    # against `completeness_status`, enforced by write_evidence_bundle() below) would otherwise
    # incorrectly mark that common, fully-successful case "PARTIAL".
    "sd_facts",
    "serialize_dos_out.json",
    # LLM-INPUT INTEGRATION: llm_raw follows the exact same "bundle the raw-output directory
    # as-is, required" precedent as sd_facts/redos_raw/pt_raw above (this producer, unlike
    # Serialize DoS's own taint-engine sub-pipeline, always runs unconditionally and always
    # writes real output on every successful run -- no conditional sub-pipeline shape here);
    # llm_input_out.json follows the exact same precedent as the other *_out.json entries.
    "llm_raw",
    "llm_input_out.json",
    # NOSQLI INTEGRATION: nosqli_raw follows the exact same "bundle the raw-output directory
    # as-is, required" precedent as llm_raw/sd_facts/redos_raw/pt_raw above -- this producer,
    # like LLM-input's own, always runs unconditionally on every successful run (no conditional
    # sub-pipeline shape); nosqli_out.json follows the exact same precedent as the other
    # *_out.json entries.
    "nosqli_raw",
    "nosqli_out.json",
    # SSRF INTEGRATION: ssrf_raw follows the exact same "bundle the raw-output directory as-is,
    # required" precedent as nosqli_raw/llm_raw/sd_facts/redos_raw/pt_raw above (this producer
    # always runs unconditionally on every successful run); ssrf_out.json follows the exact same
    # precedent as the other *_out.json entries.
    "ssrf_raw",
    "ssrf_out.json",
    # FIVE-MORE-CLASSES INTEGRATION: same "bundle the raw-output directory as-is, required"
    # precedent -- each of these five always runs unconditionally on every successful run, same
    # as every entry above; each _out.json follows the exact same *_out.json precedent.
    "guard_fallthrough_raw",
    "guard_fallthrough_out.json",
    "globalmut_raw",
    "globalmut_out.json",
    "denylist_bypass_raw",
    "denylist_bypass_out.json",
    "validation_bypass_raw",
    "validation_bypass_out.json",
    "malicious_npm_raw",
    "malicious_npm_out.json",
    # ESCAPE-PARITY-BOUNDARY INTEGRATION: same "bundle the raw-output directory as-is,
    # required" precedent as every entry above -- the producer always runs unconditionally on
    # every successful run; escape_parity_out.json follows the exact same *_out.json precedent.
    "escape_parity_raw",
    "escape_parity_out.json",
)

# Real per-package facts that are bundled and hashed WHEN PRESENT, exactly like
# BUNDLED_RELATIVE_PATHS, but whose absence is a legitimate, expected outcome of a real
# upstream decision (not a sign anything failed or was skipped) -- so, unlike
# BUNDLED_RELATIVE_PATHS, an absent entry here is never counted against `completeness_status`.
# Recorded in the manifest's own `optional_missing` (disclosed, not penalized) rather than
# `missing` (disclosed AND penalized) when absent.
OPTIONAL_RELATIVE_PATHS = (
    # SERIALIZE DOS INTEGRATION (roadmap step 8, third JS/TS class): the taint-engine
    # sub-pipeline (setup_candidate_multisource.sc + export_property_propagation.sc +
    # adjudicate_js.py) only runs at all when sd_facts's own serialize_sinks.tsv had at least
    # one qualifying attacker-controlled-unbounded-stringify sink -- the common case has none,
    # and both directories are then correctly, entirely absent, not merely empty.
    "sd_taint_raw",
    "sd_taint_evidence",
)

SCHEMA_VERSION = "evidence_bundle/2"

# The real analyzer files whose content determines what evidence THIS bundle actually
# contains -- hashed at bundle-write time so a downstream consumer can detect drift against
# whichever revision it currently has checked out. Paths relative to this file's own directory.
# OVERNIGHT-DIAGNOSTIC-100: adapted from the original R06 list to name the analyzers THIS
# diagnostic run actually drives. resource_guard_verdict_r06.py is deliberately absent -- #41
# (merging R06/FIX01I into the driven r04/r05 lineage) is not complete, so this run uses
# resource_guard_verdict_r04.py/_r05.py (the already-driven, already-gated lineage) instead,
# labeling Resource Guard PRECISION_FIX_NOT_INTEGRATED (see run_diagnostic_100.py) rather than
# silently pulling in unintegrated logic. The five newly-wired property scanners are added so a
# downstream consumer can detect drift against any of them too.
_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOLS_DIR = "/home/user/bug_tracker/tchecker-research-complete/portable-engine-full-review-package/tools"
ANALYZER_FILES = {
    "resource_guard_verdict_r04.py": os.path.join(os.path.dirname(_HERE), "resource_guard_verdict_r04.py"),
    "resource_guard_verdict_r05.py": os.path.join(os.path.dirname(_HERE), "resource_guard_verdict_r05.py"),
    "extract_build_config.py": os.path.join(_HERE, "extract_build_config.py"),
    "evidence_bundle.py": os.path.join(_HERE, "evidence_bundle.py"),
    "provenance.py": os.path.join(os.path.dirname(_HERE), "provenance.py"),
    "lock_balance_verdict.py": os.path.join(os.path.dirname(_HERE), "lock_balance_verdict.py"),
    "protected_field_verdict.py": os.path.join(os.path.dirname(_HERE), "protected_field_verdict.py"),
    "oob_write_verdict.py": os.path.join(_TOOLS_DIR, "oob_write_verdict.py"),
    "oob_index_write_verdict.py": os.path.join(_TOOLS_DIR, "oob_index_write_verdict.py"),
    "oob_read_verdict.py": os.path.join(_TOOLS_DIR, "oob_read_verdict.py"),
    "oob_compare_verdict.py": os.path.join(_TOOLS_DIR, "oob_compare_verdict.py"),
    # REDOS INTEGRATION (roadmap step 8): redos_verdict.py (frozen) is the analyzer that produces
    # redos_out.json -- same real path-construction convention as resource_guard_verdict_r04.py/
    # _r05.py above (SCANNER_V2-root-relative, via os.path.dirname(_HERE) since _HERE is the
    # npm_corpus/ subdirectory).
    "redos_verdict.py": os.path.join(os.path.dirname(_HERE), "redos_verdict.py"),
    # PATH TRAVERSAL INTEGRATION (roadmap step 8): path_traversal_verdict.py is the analyzer that
    # produces path_traversal_out.json -- same real path-construction convention as
    # redos_verdict.py above.
    "path_traversal_verdict.py": os.path.join(os.path.dirname(_HERE), "path_traversal_verdict.py"),
    # SERIALIZE DOS INTEGRATION (roadmap step 8, third JS/TS class): serialize_dos_r03.py (frozen,
    # merged from a separate parallel session's own serialize-dos-r01/ directory) is the analyzer
    # that produces serialize_dos_out.json -- UNLIKE every other entry in this dict, it does NOT
    # live under SCANNER_V2 (redos_verdict.py/path_traversal_verdict.py's own base path above), so
    # its own real absolute path is used directly rather than being built from _HERE.
    "serialize_dos_r03.py": ("/home/user/bug_tracker/tchecker-research-complete/"
                              "serialize-dos-r01/serialize_dos_r03.py"),
    # LLM-INPUT INTEGRATION: llm_input_verdict.py (frozen, already-gated) is the analyzer that
    # produces llm_input_out.json -- lives under tchecker-property-adjudicator/adjudicator/, not
    # SCANNER_V2, same "real absolute path used directly" treatment as serialize_dos_r03.py above.
    "llm_input_verdict.py": ("/home/user/bug_tracker/tchecker-research-complete/"
                              "tchecker-property-adjudicator/adjudicator/llm_input_verdict.py"),
    # NOSQLI INTEGRATION: nosqli_verdict.py (new this session) is the analyzer that produces
    # nosqli_out.json -- same real path-construction convention as redos_verdict.py/
    # path_traversal_verdict.py above (SCANNER_V2-root-relative).
    "nosqli_verdict.py": os.path.join(os.path.dirname(_HERE), "nosqli_verdict.py"),
    # SSRF INTEGRATION: ssrf_verdict.py (new this session) is the analyzer that produces
    # ssrf_out.json -- same real path-construction convention as nosqli_verdict.py/
    # redos_verdict.py/path_traversal_verdict.py above (SCANNER_V2-root-relative).
    "ssrf_verdict.py": os.path.join(os.path.dirname(_HERE), "ssrf_verdict.py"),
    # FIVE-MORE-CLASSES INTEGRATION: unlike every other entry in this dict, these five live
    # under tchecker-research-complete/gates/, not SCANNER_V2 -- same "real absolute path used
    # directly" treatment as serialize_dos_r03.py/llm_input_verdict.py above.
    "guard_fallthrough_verdict.py": ("/home/user/bug_tracker/tchecker-research-complete/"
                                      "gates/guard_fallthrough_verdict.py"),
    "globalmut_verdict.py": ("/home/user/bug_tracker/tchecker-research-complete/"
                              "gates/globalmut_verdict.py"),
    "denylist_bypass_verdict.py": ("/home/user/bug_tracker/tchecker-research-complete/"
                                    "gates/denylist_bypass_verdict.py"),
    "validation_bypass_verdict.py": ("/home/user/bug_tracker/tchecker-research-complete/"
                                      "gates/validation_bypass_verdict.py"),
    "malicious_npm_verdict.py": ("/home/user/bug_tracker/tchecker-research-complete/"
                                  "gates/malicious_npm_verdict.py"),
}


class IncompleteBundleError(Exception):
    """Raised by `require_complete_bundle()` when a bundle's own manifest reports anything
    other than `completeness_status == "COMPLETE"` -- a partial or resource-limited bundle
    must never be silently consumed as if it were complete evidence."""


def _sha256_file(path):
    if not os.path.isfile(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _real_analyzer_hashes():
    return {name: _sha256_file(path) for name, path in ANALYZER_FILES.items()}


def _deterministic_member(info):
    """Strips run-environment metadata (filesystem mtime, uid/gid, user/group names,
    umask-dependent mode bits) from a tar member so the same input evidence bytes always
    produce the same bundle bytes -- a re-run over identical evidence must reproduce the
    recorded per-bundle sha256 exactly."""
    info.mtime = 0
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mode = 0o755 if info.isdir() else 0o644
    return info


def _extract_cross_language_bindings(work_dir):
    """Pulls just the registration/link evidence out of merged.json, if it exists, without
    keeping the whole merged document (which would duplicate cpp_facts.json/js_facts.json)."""
    merged_path = os.path.join(work_dir, "merged.json")
    if not os.path.isfile(merged_path):
        return None
    try:
        with open(merged_path) as f:
            merged = json.load(f)
    except Exception:
        return None
    return merged.get("cross_language_bindings")


def write_evidence_bundle(work_root, bundle_dir, pkg_name, version,
                            tarball_sha256=None, pipeline_status=None):
    """Writes work_root/work/'s real evidence (see BUNDLED_RELATIVE_PATHS) as a single
    gzip-compressed tar to bundle_dir/<pkg_name>@<version>.tar.gz, atomically. Returns
    (bundle_path_or_None, manifest_dict). Never raises on a missing individual file -- a
    package that failed before a given stage simply won't have that stage's file, and the
    manifest records exactly what was and was not included, same disclosed-abstention
    discipline as the rest of this pipeline. Returns (None, manifest) if NOTHING was found
    to bundle (e.g. the package failed before work/ was ever created).

    `tarball_sha256` -- sha256 of the real npm tarball bytes this package's facts were
    derived from, if the caller has it (`None`, disclosed, if not supplied -- never
    fabricated). `pipeline_status` -- this package's own real pipeline status
    (`rec["status"]`, e.g. `"ANALYZED"`/`"RESOURCE_LIMIT"`/...), used ONLY to compute
    `completeness_status` below; not otherwise interpreted by this module."""
    work_dir = os.path.join(work_root, "work")
    os.makedirs(bundle_dir, exist_ok=True)

    safe_name = pkg_name.replace("/", "__")
    stem = f"{safe_name}@{version}"
    final_path = os.path.join(bundle_dir, f"{stem}.tar.gz")
    tmp_path = os.path.join(bundle_dir, f".{stem}.tar.gz.tmp")

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "package_name": pkg_name, "version": version,
        "tarball_sha256": tarball_sha256,
        "pipeline_status": pipeline_status,
        "analyzer_hashes": _real_analyzer_hashes(),
        "artifact_hashes": {},
        "included": [], "missing": [], "optional_missing": [],
    }

    xlb = _extract_cross_language_bindings(work_dir)

    # Build the whole tar in memory first so a crash mid-build can never leave a partial file
    # at tmp_path -- only the final, atomic os.replace touches the real filesystem path.
    # gzip is opened explicitly with mtime=0 (and no embedded filename): the default
    # "w:gz" path stamps the current wall-clock time into the gzip header, making two
    # bundles of identical evidence differ byte-for-byte.
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", fileobj=buf, mode="wb", mtime=0) as gz, \
            tarfile.open(fileobj=gz, mode="w") as tf:
        def _bundle_one(rel, absent_bucket):
            """Bundles work_dir/rel (file or non-empty directory) into tf and records it in
            manifest["included"]/["artifact_hashes"]; if genuinely absent, records rel into
            manifest[absent_bucket] instead ("missing" for a required path -- counts against
            completeness_status below -- or "optional_missing" for one that is legitimately,
            expectedly sometimes absent on an otherwise fully-successful run -- disclosed but
            never penalized)."""
            src = os.path.join(work_dir, rel)
            if os.path.isdir(src):
                inner_files = sorted(
                    os.path.relpath(os.path.join(dp, fn), src)
                    for dp, _, fns in os.walk(src) for fn in fns
                )
                if inner_files:
                    tf.add(src, arcname=rel, filter=_deterministic_member)
                    manifest["included"].append(rel)
                    manifest["artifact_hashes"][rel] = {
                        inner: _sha256_file(os.path.join(src, inner)) for inner in inner_files
                    }
                else:
                    manifest[absent_bucket].append(rel)
            elif os.path.isfile(src):
                tf.add(src, arcname=rel, filter=_deterministic_member)
                manifest["included"].append(rel)
                manifest["artifact_hashes"][rel] = _sha256_file(src)
            else:
                manifest[absent_bucket].append(rel)

        for rel in BUNDLED_RELATIVE_PATHS:
            _bundle_one(rel, "missing")
        for rel in OPTIONAL_RELATIVE_PATHS:
            _bundle_one(rel, "optional_missing")
        if xlb is not None:
            xlb_bytes = json.dumps(xlb, indent=2, sort_keys=True).encode("utf-8")
            info = tarfile.TarInfo(name="cross_language_bindings.json")
            info.size = len(xlb_bytes)
            tf.addfile(info, io.BytesIO(xlb_bytes))
            manifest["included"].append("cross_language_bindings.json")
            manifest["artifact_hashes"]["cross_language_bindings.json"] = _sha256_bytes(xlb_bytes)
        else:
            manifest["missing"].append("cross_language_bindings.json")

        # COMPLETENESS (item 4): COMPLETE only when nothing real is missing AND (if the
        # caller supplied it) the package's own pipeline run itself completed ANALYZED --
        # a partial or resource-limited package's bundle is real, kept, and still useful for
        # whatever it does contain, but must never be silently treated as complete evidence.
        manifest["completeness_status"] = (
            "COMPLETE" if not manifest["missing"] and pipeline_status in (None, "ANALYZED")
            else "PARTIAL"
        )

        manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
        info = tarfile.TarInfo(name="manifest.json")
        info.size = len(manifest_bytes)
        tf.addfile(info, io.BytesIO(manifest_bytes))

    if not manifest["included"]:
        return None, manifest  # nothing real to keep -- don't write an empty/manifest-only bundle

    with open(tmp_path, "wb") as f:
        f.write(buf.getvalue())
    os.replace(tmp_path, final_path)  # atomic on the same filesystem
    manifest["bundle_path"] = final_path
    manifest["compressed_bytes"] = os.path.getsize(final_path)
    return final_path, manifest


def read_bundle_manifest(bundle_path):
    """Reads and returns the real `manifest.json` from inside a bundle .tar.gz, without
    extracting anything else. Neutral -- does NOT enforce completeness; use
    `require_complete_bundle()` for that. Raises FileNotFoundError/tarfile errors/
    json.JSONDecodeError directly (never silently returns a fabricated empty manifest)."""
    with tarfile.open(bundle_path, "r:gz") as tf:
        member = tf.getmember("manifest.json")
        f = tf.extractfile(member)
        return json.loads(f.read())


def require_complete_bundle(bundle_path):
    """BUNDLE INTEGRITY (item 4) -- the required loader-side guard: reads the real manifest
    and RAISES `IncompleteBundleError` unless `completeness_status == "COMPLETE"`. Any code
    path that intends to consume a bundle's evidence AS IF it were a complete, verdict-ready
    record (e.g. the post-freeze targeted rerun) must call this first -- a partial or
    resource-limited bundle must never be silently treated as complete evidence. Returns the
    real manifest dict on success (same shape as `read_bundle_manifest`)."""
    manifest = read_bundle_manifest(bundle_path)
    if manifest.get("completeness_status") != "COMPLETE":
        raise IncompleteBundleError(
            f"{bundle_path}: completeness_status={manifest.get('completeness_status')!r} "
            f"(pipeline_status={manifest.get('pipeline_status')!r}, "
            f"missing={manifest.get('missing')!r}) -- refusing to consume as complete evidence"
        )
    return manifest
