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
    loader-side guard that enforces this.
"""
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
        "included": [], "missing": [],
    }

    xlb = _extract_cross_language_bindings(work_dir)

    # Build the whole tar in memory first so a crash mid-build can never leave a partial file
    # at tmp_path -- only the final, atomic os.replace touches the real filesystem path.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for rel in BUNDLED_RELATIVE_PATHS:
            src = os.path.join(work_dir, rel)
            if os.path.isdir(src):
                inner_files = sorted(
                    os.path.relpath(os.path.join(dp, fn), src)
                    for dp, _, fns in os.walk(src) for fn in fns
                )
                if inner_files:
                    tf.add(src, arcname=rel)
                    manifest["included"].append(rel)
                    manifest["artifact_hashes"][rel] = {
                        inner: _sha256_file(os.path.join(src, inner)) for inner in inner_files
                    }
                else:
                    manifest["missing"].append(rel)
            elif os.path.isfile(src):
                tf.add(src, arcname=rel)
                manifest["included"].append(rel)
                manifest["artifact_hashes"][rel] = _sha256_file(src)
            else:
                manifest["missing"].append(rel)
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
