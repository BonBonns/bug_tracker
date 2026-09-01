#!/usr/bin/env python3
"""NAN-REPLAY-TASK4: "Replay Nan over the preserved 97-package sample using existing facts --
no Joern rebuild -- so the combined aggregator includes Nan results." (direct instruction,
task 4 of 5 required before the Nan integration can be called frozen)

NOT a new corpus run: no Joern is invoked, no CPG is rebuilt, no C/C++/JS facts are
regenerated. `resource_guard_verdict_nan.py` runs fresh over each bundle's own already-
preserved `cpp_raw/*.tsv` -- same discipline replay_100_bundles.py's own R06 rerun already
established (item 1 of that round).

THE REAL GAP THIS SCRIPT CLOSES: the 100-package evidence bundles never preserve the raw
jssrc2cpg TSV export `resource_guard_verdict_nan.py`'s own `load_js_raw()` reads -- only the
NORMALIZED `js_facts.json` (evidence_bundle.py's own module docstring: raw js_raw is
deliberately excluded, "js_facts.json, its normalized form" already carries what's needed).
`resource_guard_verdict_nan.load_js_raw_from_facts_json()` (added this round) adapts
js_facts.json into the exact same `{"calls", "calls_by_name", "args_by_call"}` shape
`load_js_raw()` returns -- confirmed BYTE-IDENTICAL, not merely "runs without error": a real
js_facts.json was generated from the Nan capability's own comprehensive_fixture (the same
fixture `NAN_CAPABILITY_DESIGN.md`/`NAN_CAPABILITY_FREEZE.md` validated the whole capability
against) via the real `normalize_joern_facts.py` the live pipeline itself uses, and
`compute_findings(cpp, load_js_raw(tsv_dir))` vs `compute_findings(cpp,
load_js_raw_from_facts_json(json_path))` produced EXACT-EQUAL classification dicts and finding
lists (0 mismatches across 40 real calls / their arguments) -- see NAN_REPLAY_TASK4_RESULTS.md
for the full account.

PROVENANCE: same re-fetch-and-verify discipline replay_100_bundles.py's own
PROVENANCE_SOURCE_DECISION established (no bundle preserves per-file source bytes) --
`resource_guard_verdict_nan`'s own findings need the SAME per-file content_hash manifest
r04/r05/r06 findings already got in the v5 replay, so this script re-runs the identical
download-verify-hash-delete cycle (reusing `replay_100_bundles.download_and_verify_source`
verbatim, not a second implementation) SCOPED to `nan_findings` alone --
`provenance.enrich_record()` only ever touches keys present in the record it's given, so
passing `{"nan_findings": findings}` never touches or re-verifies the v5 record's own
already-resolved r04/r05/r06/staged provenance.

PIPELINE ORDER (same as rerun_aggregator_applicability.py's own documented real order):
provenance.enrich_record (nan_findings only) -> applicability_gate.apply_applicability (re-run
over the WHOLE merged record; idempotent on every already-APPLICABLE finding, newly evaluates
nan_findings) -> adjudication_registry.apply_known_adjudications (idempotent re-apply) ->
staged_enablement.enforce_staged_enablement -> vendored_attribution.attribute_record (now
covers nan_findings too, see this round's own vendored_attribution.py fix) ->
six_property_aggregator.aggregate_record.

Usage: python3 nan_replay_over_97.py [--limit N] [--only PKG@VERSION,...]
"""
import json
import os
import shutil
import sys
import tarfile
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER_V2 = os.path.dirname(os.path.dirname(HERE))
OVERNIGHT_DIR = os.path.join(SCANNER_V2, "npm_corpus", "overnight_100")
BUNDLE_DIR = os.path.join(OVERNIGHT_DIR, "evidence_bundles_100")
RESULTS_DIR = os.path.join(HERE, "results")
sys.path.insert(0, SCANNER_V2)
sys.path.insert(0, HERE)

import provenance  # noqa: E402
import applicability_gate as ag  # noqa: E402
import adjudication_registry as ar  # noqa: E402
import staged_enablement as se  # noqa: E402
import vendored_attribution as va  # noqa: E402
import six_property_aggregator as agg  # noqa: E402
import resource_guard_verdict_nan as nan  # noqa: E402
import replay_100_bundles as R  # noqa: E402

ALL_PROPERTY_KEYS = agg.ALL_PROPERTY_KEYS


def load_v5():
    recs = {}
    with open(os.path.join(RESULTS_DIR, "replay_records_v5.jsonl")) as f:
        for line in f:
            d = json.loads(line)
            recs[(d.get("package_name"), d.get("version"))] = d
    return recs


def nan_replay_one(pkg_name, version, sample_info, work_dir, timing):
    """Extracts the bundle, computes nan_findings fresh over preserved cpp_raw + an
    adapted js_facts.json, re-fetches/verifies the pinned source for nan-scoped provenance,
    and returns (nan_findings_enriched, prov_meta_dict)."""
    bpath = os.path.join(BUNDLE_DIR, R.bundle_filename(pkg_name, version))
    with tarfile.open(bpath, "r:gz") as tf:
        R.safe_extract_tar(tf, work_dir)

    cpp_raw_dir = os.path.join(work_dir, "cpp_raw")
    js_facts_path = os.path.join(work_dir, "js_facts.json")

    t0 = time.time()
    cpp = nan.load_cpp_raw(cpp_raw_dir)
    js = nan.load_js_raw_from_facts_json(js_facts_path)
    _reg, _aud, _cls, findings = nan.compute_findings(cpp, js)
    timing["nan_compute_seconds"] = time.time() - t0

    real_manifest, prov_source, tarball_ok, tree_ok, fail_detail = R.download_and_verify_source(
        pkg_name, version, sample_info["tarball_url"],
        sample_info["tarball_sha256"], sample_info["source_tree_sha256"],
        work_dir, timing)

    manifest_for_enrich = {
        "package_name": pkg_name, "version": version,
        "tarball_sha256": sample_info["tarball_sha256"],
        "source_tree_sha256": sample_info["source_tree_sha256"],
        "files": real_manifest["files"] if real_manifest is not None else {},
    }
    rec_for_enrich = {"nan_findings": findings}
    provenance.enrich_record(rec_for_enrich, cpp_raw_dir, manifest_for_enrich, "")

    prov_meta = {
        "_nan_provenance_source": prov_source,
        "_nan_tarball_hash_verified": tarball_ok,
        "_nan_source_tree_hash_verified": tree_ok,
        "_nan_refetch_failure_detail": fail_detail,
    }
    return rec_for_enrich["nan_findings"], prov_meta


def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--only", type=str, default=None)
    args = p.parse_args()

    v5 = load_v5()
    _all_records, records_by_status, sample_by_key = R.load_frozen_manifest()

    replayed_keys = [k for k, v in v5.items() if v.get("outcome") == "REPLAYED"]
    replayed_keys.sort()
    if args.only:
        wanted = set()
        for spec in args.only.split(","):
            name, _, ver = spec.rpartition("@")
            wanted.add((name, ver))
        replayed_keys = [k for k in replayed_keys if k in wanted]
    if args.limit:
        replayed_keys = replayed_keys[:args.limit]

    out_path = os.path.join(RESULTS_DIR, "replay_records_v6_nan.jsonl")
    ledger_path = os.path.join(RESULTS_DIR, "nan_replay_failure_ledger.jsonl")
    if os.path.exists(out_path):
        os.remove(out_path)
    if os.path.exists(ledger_path):
        os.remove(ledger_path)

    v6_records = []
    total_nan_findings = 0
    total_nan_reportable = 0
    failures = []

    for i, key in enumerate(replayed_keys):
        pkg_name, version = key
        rec = dict(v5[key])  # shallow copy; the record's own findings lists are replaced below,
                              # not mutated element-by-element, so this is safe.
        sample_info = sample_by_key.get(key)
        timing = {}
        work_dir = tempfile.mkdtemp(prefix="nan_replay_")
        try:
            if sample_info is None:
                raise R.ReplayFailure("NO_SAMPLE_INFO", str(key))
            nan_findings, prov_meta = nan_replay_one(
                pkg_name, version, sample_info, work_dir, timing)
            rec["nan_findings"] = nan_findings
            rec.update(prov_meta)
            rec["_nan_timing"] = timing

            n_applied = ag.apply_applicability(rec)
            ar.apply_known_adjudications(rec)
            se.enforce_staged_enablement(rec)
            va.attribute_record(rec)
            summary = agg.aggregate_record(rec, enabled_properties=se.ENABLED_PROPERTIES)
            rec["_six_property_summary"] = summary
            rec["_n_applicability_applied_nan_replay"] = n_applied

            total_nan_findings += len(nan_findings)
            total_nan_reportable += sum(1 for f in nan_findings if f.get("reportable"))
        except Exception as e:
            failures.append({"package_name": pkg_name, "version": version,
                              "reason": type(e).__name__, "detail": str(e)})
            with open(ledger_path, "a") as f:
                f.write(json.dumps({"package_name": pkg_name, "version": version,
                                     "reason": type(e).__name__, "detail": str(e)}) + "\n")
            # Keep the v5 record as-is (no nan_findings key) rather than fabricate a result --
            # a real, disclosed failure, never silently swallowed.
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

        v6_records.append(rec)
        with open(out_path, "a") as f:
            f.write(json.dumps(rec, sort_keys=True, default=str) + "\n")
        print(f"[{i+1}/{len(replayed_keys)}] {pkg_name}@{version}: "
              f"nan_findings={len(rec.get('nan_findings') or [])}")

    for key, v in v5.items():
        if v.get("outcome") != "REPLAYED":
            with open(out_path, "a") as f:
                f.write(json.dumps(v, sort_keys=True, default=str) + "\n")

    out = {
        "packages_attempted": len(replayed_keys),
        "packages_succeeded": len(replayed_keys) - len(failures),
        "packages_failed": len(failures),
        "failures": failures,
        "total_nan_findings_raw": total_nan_findings,
        "total_nan_findings_reportable": total_nan_reportable,
    }
    with open(os.path.join(RESULTS_DIR, "nan_replay_summary.json"), "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
