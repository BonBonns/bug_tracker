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
  - `r04_out.json`, `r05_out.json` -- the scanner outputs already computed for this package.

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
"""
import io
import json
import os
import tarfile

# Real per-package facts this bundle preserves -- see module docstring for why each is (or
# is not) included. Paths are relative to work_root/work/ except cpp_raw/ which is a directory.
BUNDLED_RELATIVE_PATHS = (
    "cpp_raw",             # directory of raw TSVs -- required as-is by R04/R05/R06
    "cpp_facts.json",      # normalized C++ facts -- required by link_napi_facts.py (FIX01I)
    "js_facts.json",       # normalized JS facts -- required by link_napi_facts.py (FIX01I)
    "build_config.json",
    "r04_out.json",
    "r05_out.json",
)


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


def write_evidence_bundle(work_root, bundle_dir, pkg_name, version):
    """Writes work_root/work/'s real evidence (see BUNDLED_RELATIVE_PATHS) as a single
    gzip-compressed tar to bundle_dir/<pkg_name>@<version>.tar.gz, atomically. Returns
    (bundle_path_or_None, manifest_dict). Never raises on a missing individual file -- a
    package that failed before a given stage simply won't have that stage's file, and the
    manifest records exactly what was and was not included, same disclosed-abstention
    discipline as the rest of this pipeline. Returns (None, manifest) if NOTHING was found
    to bundle (e.g. the package failed before work/ was ever created)."""
    work_dir = os.path.join(work_root, "work")
    os.makedirs(bundle_dir, exist_ok=True)

    safe_name = pkg_name.replace("/", "__")
    stem = f"{safe_name}@{version}"
    final_path = os.path.join(bundle_dir, f"{stem}.tar.gz")
    tmp_path = os.path.join(bundle_dir, f".{stem}.tar.gz.tmp")

    manifest = {"package_name": pkg_name, "version": version, "included": [], "missing": []}

    xlb = _extract_cross_language_bindings(work_dir)

    # Build the whole tar in memory first so a crash mid-build can never leave a partial file
    # at tmp_path -- only the final, atomic os.replace touches the real filesystem path.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for rel in BUNDLED_RELATIVE_PATHS:
            src = os.path.join(work_dir, rel)
            if os.path.isdir(src):
                if os.listdir(src):
                    tf.add(src, arcname=rel)
                    manifest["included"].append(rel)
                else:
                    manifest["missing"].append(rel)
            elif os.path.isfile(src):
                tf.add(src, arcname=rel)
                manifest["included"].append(rel)
            else:
                manifest["missing"].append(rel)
        if xlb is not None:
            xlb_bytes = json.dumps(xlb, indent=2, sort_keys=True).encode("utf-8")
            info = tarfile.TarInfo(name="cross_language_bindings.json")
            info.size = len(xlb_bytes)
            tf.addfile(info, io.BytesIO(xlb_bytes))
            manifest["included"].append("cross_language_bindings.json")
        else:
            manifest["missing"].append("cross_language_bindings.json")

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
