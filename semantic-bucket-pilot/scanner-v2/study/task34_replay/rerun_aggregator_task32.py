#!/usr/bin/env python3
"""TASK32-REOPEN step 3: reruns task #34's own aggregator (reachability_tier ->
adjudication_registry -> staged_enablement -> vendored_attribution ->
six_property_aggregator) over the SAME 97 preserved bundles, now that
TIER_TRANSITIVELY_CALLED_FROM_REGISTERED is wired into staged_enablement.py's allowlist and
node-libcurl's adjudication is recorded. Still no Joern rebuild, no new download, no re-running
R06 (its own raw output -- provenance/applicability/adjudication-independent of the reachability
tier scheme -- is reused verbatim from the original replay's own r06_findings). Only the
reachability-dependent stages are recomputed.

Writes results/replay_records_v2.jsonl (full updated records, same 97+3 accounting) and
results/task32_rerun_delta.json (a real, computed before/after comparison -- never asserted).
"""
import json
import os
import sys
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER_V2 = os.path.dirname(os.path.dirname(HERE))
RESULTS_DIR = os.path.join(HERE, "results")
BUNDLE_DIR = os.path.join(SCANNER_V2, "npm_corpus", "overnight_100", "evidence_bundles_100")
sys.path.insert(0, SCANNER_V2)
import reachability_tier as rt  # noqa: E402
import adjudication_registry as ar  # noqa: E402
import staged_enablement as se  # noqa: E402
import vendored_attribution as va  # noqa: E402
import six_property_aggregator as agg  # noqa: E402

ALL_PROPERTY_KEYS = agg.ALL_PROPERTY_KEYS


def bundle_filename(pkg_name, version):
    return f"{pkg_name.replace('/', '__')}@{version}.tar.gz"


def load_v1():
    replayed, others = [], []
    with open(os.path.join(RESULTS_DIR, "replay_records.jsonl")) as f:
        for line in f:
            d = json.loads(line)
            (replayed if d.get("outcome") == "REPLAYED" else others).append(d)
    return replayed, others


def snapshot_reachability(record):
    """{(key, index): reachability_status} for every staged finding -- the real BEFORE state,
    read directly off the v1 record before this rerun touches anything."""
    snap = {}
    for key in ("lock_balance_findings", "protected_field_findings", "oob_write_candidates",
                "oob_index_write_candidates", "oob_read_candidates"):
        for i, f in enumerate(record.get(key) or []):
            snap[(key, i)] = f.get("reachability_status")
    return snap


def main():
    replayed_v1, others = load_v1()
    out_path = os.path.join(RESULTS_DIR, "replay_records_v2.jsonl")
    if os.path.exists(out_path):
        os.remove(out_path)

    tier_transitions = {}  # (before, after) -> count
    per_property_transitions = {}  # key -> {(before, after): count}
    newly_reportable = []
    v2_records = []

    for rec in replayed_v1:
        pkg, ver = rec["package_name"], rec["version"]
        before = snapshot_reachability(rec)

        bpath = os.path.join(BUNDLE_DIR, bundle_filename(pkg, ver))
        with tarfile.open(bpath, "r:gz") as tf:
            cpp = json.load(tf.extractfile("cpp_facts.json"))
            js = json.load(tf.extractfile("js_facts.json"))

        # Recompute the reachability-dependent stages ONLY -- provenance (source_path/
        # content_hash/scanner_candidate/applicability_status), the raw R04-R06/staged findings
        # themselves, and _provenance_source/_tarball_hash_verified etc. are untouched, reused
        # verbatim from the v1 record (no Joern rebuild, no re-download, no re-running R06).
        rt.classify_record_reachability(rec, js, cpp)
        n_adjudicated = ar.apply_known_adjudications(rec)
        se.enforce_staged_enablement(rec)
        va.attribute_record(rec)
        summary = agg.aggregate_record(rec, enabled_properties=se.ENABLED_PROPERTIES)
        rec["_six_property_summary"] = summary
        rec["_n_newly_adjudicated_this_rerun"] = n_adjudicated

        after = snapshot_reachability(rec)
        for k in before:
            b, a = before[k], after[k]
            tier_transitions[(b, a)] = tier_transitions.get((b, a), 0) + 1
            key = k[0]
            per_property_transitions.setdefault(key, {})
            per_property_transitions[key][(b, a)] = per_property_transitions[key].get((b, a), 0) + 1
            if b != a and rec.get(key) and rec[key][k[1]].get("reportable"):
                newly_reportable.append({
                    "package_name": pkg, "version": ver, "property": key,
                    "before_tier": b, "after_tier": a,
                    "function": rec[key][k[1]].get("function") or rec[key][k[1]].get("method_name"),
                })

        v2_records.append(rec)
        with open(out_path, "a") as f:
            f.write(json.dumps(rec, sort_keys=True, default=str) + "\n")

    for rec in others:
        with open(out_path, "a") as f:
            f.write(json.dumps(rec, sort_keys=True, default=str) + "\n")

    # real funnel comparison, v1 vs v2, per property
    funnel_v1 = {k: {"raw": 0, "reportable": 0} for k in ALL_PROPERTY_KEYS}
    funnel_v2 = {k: {"raw": 0, "reportable": 0} for k in ALL_PROPERTY_KEYS}
    # NOTE: replayed_v1's own dicts were mutated in place above (classify_record_reachability
    # etc. all mutate their `record` argument) -- the v1 funnel must be read back from a FRESH
    # reload of the original file, never from these now-v2 dicts.
    v1_fresh, _ = load_v1_fresh(RESULTS_DIR)
    for rec in v1_fresh:
        for k in ALL_PROPERTY_KEYS:
            for f in rec.get(k) or []:
                funnel_v1[k]["raw"] += 1
                if f.get("reportable"):
                    funnel_v1[k]["reportable"] += 1
    for rec in v2_records:
        for k in ALL_PROPERTY_KEYS:
            for f in rec.get(k) or []:
                funnel_v2[k]["raw"] += 1
                if f.get("reportable"):
                    funnel_v2[k]["reportable"] += 1

    delta = {
        "tier_transitions": {f"{b}->{a}": n for (b, a), n in sorted(tier_transitions.items())},
        "per_property_transitions": {
            key: {f"{b}->{a}": n for (b, a), n in sorted(v.items())}
            for key, v in per_property_transitions.items()},
        "newly_reportable_findings": newly_reportable,
        "funnel_v1": funnel_v1,
        "funnel_v2": funnel_v2,
        "total_adjudications_applied": sum(r.get("_n_newly_adjudicated_this_rerun", 0)
                                            for r in v2_records),
    }
    with open(os.path.join(RESULTS_DIR, "task32_rerun_delta.json"), "w") as f:
        json.dump(delta, f, indent=2, sort_keys=True, default=str)

    print("TIER TRANSITIONS (before -> after, real counts):")
    for (b, a), n in sorted(tier_transitions.items(), key=lambda kv: -kv[1]):
        marker = "  <-- CHANGED" if b != a else ""
        print(f"  {b} -> {a}: {n}{marker}")
    print(f"\nTotal adjudications newly applied: {delta['total_adjudications_applied']}")
    print(f"Newly reportable findings from this rerun: {len(newly_reportable)}")
    for k in ALL_PROPERTY_KEYS:
        v1, v2 = funnel_v1[k], funnel_v2[k]
        changed = " <-- CHANGED" if v1 != v2 else ""
        print(f"  {k}: v1 raw={v1['raw']} reportable={v1['reportable']} | "
              f"v2 raw={v2['raw']} reportable={v2['reportable']}{changed}")


def load_v1_fresh(results_dir):
    replayed, others = [], []
    with open(os.path.join(results_dir, "replay_records.jsonl")) as f:
        for line in f:
            d = json.loads(line)
            (replayed if d.get("outcome") == "REPLAYED" else others).append(d)
    return replayed, others


if __name__ == "__main__":
    main()
