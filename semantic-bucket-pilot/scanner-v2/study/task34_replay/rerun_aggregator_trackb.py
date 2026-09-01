#!/usr/bin/env python3
"""TRACK-B-R01 (roadmap step 7): reruns lock_balance_verdict.py (this repo's own, now-fixed
WRAPPER-SITE-R01 version) and oob_index_write_verdict.py (tchecker-research-complete's own,
now-fixed OOB-EQUIV-R01 version) fresh over the same 97 preserved bundles, replacing their own
raw findings/candidates -- no Joern rebuild, no new download; both scanners' real inputs
(cpp_raw/*.tsv, cpp_facts.json) are already preserved per-bundle. oob_write_candidates,
protected_field_findings, oob_read_candidates are reused verbatim (untouched by either fix).

Then reruns the full downstream pipeline (reachability_tier -> applicability_gate ->
adjudication_registry -> staged_enablement -> vendored_attribution -> six_property_aggregator)
over the updated records, same real order as rerun_aggregator_step6.py.

Writes results/replay_records_v8.jsonl and results/trackb_rerun_delta.json.
"""
import json
import os
import subprocess
import sys
import tarfile
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER_V2 = os.path.dirname(os.path.dirname(HERE))
RESULTS_DIR = os.path.join(HERE, "results")
BUNDLE_DIR = os.path.join(SCANNER_V2, "npm_corpus", "overnight_100", "evidence_bundles_100")
LOCK_BALANCE_VERDICT = os.path.join(SCANNER_V2, "lock_balance_verdict.py")
OOB_INDEX_TOOLS_DIR = ("/home/user/bug_tracker/tchecker-research-complete/"
                        "portable-engine-full-review-package/tools")
sys.path.insert(0, SCANNER_V2)
sys.path.insert(0, OOB_INDEX_TOOLS_DIR)
import reachability_tier as rt  # noqa: E402
import applicability_gate as ag  # noqa: E402
import adjudication_registry as ar  # noqa: E402
import staged_enablement as se  # noqa: E402
import vendored_attribution as va  # noqa: E402
import six_property_aggregator as agg  # noqa: E402
import oob_index_write_verdict as oiw  # noqa: E402
import provenance as prov  # noqa: E402

ALL_PROPERTY_KEYS = agg.ALL_PROPERTY_KEYS
STAGED_KEYS = ("lock_balance_findings", "protected_field_findings", "oob_write_candidates",
               "oob_index_write_candidates", "oob_read_candidates")


# PROV-REUSE-R01 (correction, added after the first run of this script surfaced the bug): the
# first version of this script replaced lock_balance_findings/oob_index_write_candidates with
# brand-new dicts from the fixed scanners, but never re-ran provenance.enrich_record() (or its
# equivalent) on them before the rest of the pipeline -- so provenance.finalize_reportability()'s
# own `bool(finding["provenance"]["resolved"])` term saw an ABSENT "provenance" key on every one
# of them and forced reportable=False unconditionally, regardless of adjudication_status. This
# silently zeroed the "reportable" funnel for both properties (oob_index_write_candidates:
# 7 -> 0, not 7 -> 2 as the real fix should produce), even though the raw findings themselves --
# and the real STRUCTURALLY_GONE/STILL_PRESENT_STRUCTURALLY status of each Track B target -- were
# unaffected and correct.
#
# Fixed here by re-enriching each new finding's provenance before it re-enters the pipeline.
# Re-fetching the pinned tarball from npm 97 times (replay_100_bundles.py's own approach, the
# only other real source of a source-file content hash, since run_pipeline_one.py's own
# disk-bounding discipline deletes the extracted source tree after every scan) would work but is
# needless: this SAME record's OTHER, untouched properties (r04/r05/r06/nan/protected_field/
# oob_write/oob_read/oob_compare, plus the pre-overwrite lock_balance_findings/
# oob_index_write_candidates themselves) already carry real, hash-verified provenance for the
# very same source files (same package, same version, same pinned tarball) -- reusing an
# already-resolved provenance entry keyed by its own source_path is not a shortcut, it is exactly
# what a fresh enrich_record() call would re-derive. A relpath never seen among this record's own
# already-resolved findings (should not occur for the 3 known Track B target functions, since
# their own files are already covered by an existing R04-style finding or the pre-overwrite
# candidate lists) falls back to provenance.enrich_finding()'s own real, fail-closed
# PATH_NOT_IN_MANIFEST path -- never fabricated.
def _provenance_by_source_path(record):
    out = {}
    for key in ALL_PROPERTY_KEYS:
        for f in record.get(key) or []:
            p = f.get("provenance") or {}
            if p.get("resolved") and p.get("source_path") and p["source_path"] not in out:
                out[p["source_path"]] = p
    return out


def _package_manifest_stub(record):
    """package_name/version/tarball_sha256/source_tree_sha256 are per-package constants --
    identical across every finding's own provenance -- so any ONE already-resolved entry gives a
    real manifest stub (files={}) for the enrich_finding() fallback path, honestly leaving a
    genuinely-unseen relpath PATH_NOT_IN_MANIFEST rather than inventing an identity for it."""
    for key in ALL_PROPERTY_KEYS:
        for f in record.get(key) or []:
            p = f.get("provenance") or {}
            if p.get("resolved"):
                return {"package_name": p.get("package_name"), "version": p.get("version"),
                        "tarball_sha256": p.get("tarball_sha256"),
                        "source_tree_sha256": p.get("source_tree_sha256"), "files": {}}
    return {"package_name": record.get("package_name"), "version": record.get("version"),
            "tarball_sha256": None, "source_tree_sha256": None, "files": {}}


def _reenrich_candidates(new_findings, id_field_name, key, cpp_raw_dir, prov_by_path,
                          manifest_stub):
    """Returns (n_reused, n_fell_back) so main() can report real reuse coverage rather than
    silently assuming every new finding matched an already-resolved source_path."""
    method_file_map = prov.load_method_file_map(cpp_raw_dir)
    candidate_rule = prov.PROPERTY_CANDIDATE_RULES[key]
    n_reused = n_fell_back = 0
    for f in new_findings:
        node_id = f.get(id_field_name)
        raw_file = method_file_map.get(node_id) if node_id is not None else None
        relpath = raw_file.lstrip("./") if raw_file else None
        reused = prov_by_path.get(relpath) if relpath else None
        if reused is not None:
            f["provenance"] = {
                "schema": "source-provenance-finding/0.3",
                "package_name": reused.get("package_name"),
                "version": reused.get("version"),
                "tarball_sha256": reused.get("tarball_sha256"),
                "source_tree_sha256": reused.get("source_tree_sha256"),
                "joined_via_field": id_field_name,
                "source_path": relpath,
                "content_hash": reused.get("content_hash"),
                "resolved": True,
            }
            n_reused += 1
        else:
            prov.enrich_finding(f, node_id, method_file_map, manifest_stub, "", id_field_name)
            n_fell_back += 1
        prov.finalize_reportability(f, candidate_rule(f))
    return n_reused, n_fell_back


def bundle_filename(pkg_name, version):
    return f"{pkg_name.replace('/', '__')}@{version}.tar.gz"


def load_v7():
    replayed, others = [], []
    with open(os.path.join(RESULTS_DIR, "replay_records_v7.jsonl")) as f:
        for line in f:
            d = json.loads(line)
            (replayed if d.get("outcome") == "REPLAYED" else others).append(d)
    return replayed, others


def snapshot(record):
    snap = {}
    for key in STAGED_KEYS:
        for i, f in enumerate(record.get(key) or []):
            snap[(key, i)] = (f.get("reachability_status"), f.get("reportable"))
    return snap


def main():
    replayed_v7, others = load_v7()
    v7_fresh, _ = load_v7()
    out_path = os.path.join(RESULTS_DIR, "replay_records_v8.jsonl")
    if os.path.exists(out_path):
        os.remove(out_path)

    n_lock_before = n_lock_after = 0
    n_oobidx_before = n_oobidx_after = 0
    n_prov_reused = n_prov_fell_back = 0
    v8_records = []

    for rec in replayed_v7:
        pkg, ver = rec["package_name"], rec["version"]
        bpath = os.path.join(BUNDLE_DIR, bundle_filename(pkg, ver))
        with tempfile.TemporaryDirectory() as td:
            with tarfile.open(bpath, "r:gz") as tf:
                tf.extractall(td)
            cpp_raw_dir = os.path.join(td, "cpp_raw")
            cpp_facts_path = os.path.join(td, "cpp_facts.json")
            js_path = os.path.join(td, "js_facts.json")

            n_lock_before += len(rec.get("lock_balance_findings") or [])
            n_oobidx_before += len(rec.get("oob_index_write_candidates") or [])

            # snapshot BEFORE either property is overwritten -- see PROV-REUSE-R01 above.
            prov_by_path = _provenance_by_source_path(rec)
            manifest_stub = _package_manifest_stub(rec)

            # --- rerun lock_balance_verdict.py (fixed) ---
            lock_out = os.path.join(td, "lock_out.json")
            subprocess.run([sys.executable, LOCK_BALANCE_VERDICT, cpp_raw_dir, lock_out],
                            check=True, capture_output=True)
            lock_doc = json.load(open(lock_out))
            new_lock_findings = lock_doc.get("findings", [])
            r1, f1 = _reenrich_candidates(new_lock_findings, "method_id", "lock_balance_findings",
                                           cpp_raw_dir, prov_by_path, manifest_stub)
            rec["lock_balance_findings"] = new_lock_findings

            # --- rerun oob_index_write_verdict.py (fixed) ---
            new_cands = oiw.emit_candidates(cpp_facts_path)
            r2, f2 = _reenrich_candidates(new_cands, "function_id", "oob_index_write_candidates",
                                           cpp_raw_dir, prov_by_path, manifest_stub)
            rec["oob_index_write_candidates"] = new_cands
            n_prov_reused += r1 + r2
            n_prov_fell_back += f1 + f2

            n_lock_after += len(rec["lock_balance_findings"])
            n_oobidx_after += len(rec["oob_index_write_candidates"])

            # --- full downstream pipeline, real order ---
            cpp = json.load(open(cpp_facts_path))
            js = json.load(open(js_path))
            rt.classify_record_reachability(rec, js, cpp)
            ag.apply_applicability(rec)
            ar.apply_known_adjudications(rec)
            se.enforce_staged_enablement(rec)
            va.attribute_record(rec)
            summary = agg.aggregate_record(rec, enabled_properties=se.ENABLED_PROPERTIES)
            rec["_six_property_summary"] = summary

        v8_records.append(rec)
        with open(out_path, "a") as f:
            f.write(json.dumps(rec, sort_keys=True, default=str) + "\n")

    for rec in others:
        with open(out_path, "a") as f:
            f.write(json.dumps(rec, sort_keys=True, default=str) + "\n")

    funnel_before = {k: {"raw": 0, "reportable": 0} for k in ALL_PROPERTY_KEYS}
    funnel_after = {k: {"raw": 0, "reportable": 0} for k in ALL_PROPERTY_KEYS}
    for rec in v7_fresh:
        for k in ALL_PROPERTY_KEYS:
            for f in rec.get(k) or []:
                funnel_before[k]["raw"] += 1
                if f.get("reportable"):
                    funnel_before[k]["reportable"] += 1
    for rec in v8_records:
        for k in ALL_PROPERTY_KEYS:
            for f in rec.get(k) or []:
                funnel_after[k]["raw"] += 1
                if f.get("reportable"):
                    funnel_after[k]["reportable"] += 1

    # Real, per-site check: did the 6 REAL false positives Track B targeted disappear
    # structurally (verdict itself no longer produced), not merely suppressed?
    targets = [
        ("@fugood/whisper.node", "1.1.3", "lock_balance_findings", "ggml_graph_compute_secondary_thread"),
        ("smart-whisper", "0.8.1", "lock_balance_findings", "ggml_graph_compute_secondary_thread"),
        ("@appthreat/sqlite3", "9.0.1", "oob_index_write_candidates", "sha1QueryFunc"),
        ("@appthreat/sqlite3", "9.0.1", "oob_index_write_candidates", "lsModeFunc"),
        ("@appthreat/sqlite3", "9.0.1", "oob_index_write_candidates", "sqlite3_get_table_cb"),
    ]
    by_key = {(r["package_name"], r["version"]): r for r in v8_records}
    structural_status = []
    for pkg, ver, key, fn_name in targets:
        rec = by_key.get((pkg, ver))
        if rec is None:
            structural_status.append({"package": pkg, "version": ver, "key": key,
                                       "function": fn_name, "status": "PACKAGE_NOT_FOUND"})
            continue
        matches = [f for f in (rec.get(key) or [])
                   if fn_name in (f.get("method_name") or f.get("function") or "")]
        structural_status.append({
            "package": pkg, "version": ver, "key": key, "function": fn_name,
            "remaining_raw_findings": len(matches),
            "status": "STRUCTURALLY_GONE" if not matches else "STILL_PRESENT_STRUCTURALLY",
        })

    out = {
        "lock_balance_raw_before": n_lock_before, "lock_balance_raw_after": n_lock_after,
        "oob_index_write_raw_before": n_oobidx_before, "oob_index_write_raw_after": n_oobidx_after,
        "provenance_reuse_coverage": {
            "n_reused_from_same_record": n_prov_reused,
            "n_fell_back_to_fresh_enrich_finding": n_prov_fell_back,
        },
        "funnel_before": funnel_before, "funnel_after": funnel_after,
        "structural_status_of_track_b_targets": structural_status,
    }
    with open(os.path.join(RESULTS_DIR, "trackb_rerun_delta.json"), "w") as f:
        json.dump(out, f, indent=2, sort_keys=True, default=str)
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    main()
