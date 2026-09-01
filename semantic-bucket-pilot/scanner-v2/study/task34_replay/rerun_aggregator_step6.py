#!/usr/bin/env python3
"""ROADMAP-STEP6-R01: reruns the aggregator (reachability_tier -> adjudication_registry ->
staged_enablement -> vendored_attribution -> six_property_aggregator) over the SAME 97
preserved bundles, now that TIER_CALLBACK_OR_WORKER_PROVEN and TIER_MODULE_LOAD_EXECUTION_PROVEN
are wired into staged_enablement.py's allowlist. Same real discipline as
rerun_aggregator_task32.py's own precedent (which did the identical thing for
TIER_TRANSITIVELY_CALLED_FROM_REGISTERED): no Joern rebuild, no new download, no re-running any
scanner -- only the reachability-dependent stages are recomputed, over
`replay_records_v6_nan.jsonl` (the latest record set, already including nan_findings from task 4).

Writes results/replay_records_v7.jsonl and results/step6_reachability_rerun_delta.json.
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
import applicability_gate as ag  # noqa: E402
import adjudication_registry as ar  # noqa: E402
import staged_enablement as se  # noqa: E402
import vendored_attribution as va  # noqa: E402
import six_property_aggregator as agg  # noqa: E402

ALL_PROPERTY_KEYS = agg.ALL_PROPERTY_KEYS
STAGED_KEYS = ("lock_balance_findings", "protected_field_findings", "oob_write_candidates",
               "oob_index_write_candidates", "oob_read_candidates")


def bundle_filename(pkg_name, version):
    return f"{pkg_name.replace('/', '__')}@{version}.tar.gz"


def load_v6():
    replayed, others = [], []
    with open(os.path.join(RESULTS_DIR, "replay_records_v6_nan.jsonl")) as f:
        for line in f:
            d = json.loads(line)
            (replayed if d.get("outcome") == "REPLAYED" else others).append(d)
    return replayed, others


def snapshot_reachability(record):
    snap = {}
    for key in STAGED_KEYS:
        for i, f in enumerate(record.get(key) or []):
            snap[(key, i)] = f.get("reachability_status")
    return snap


def main():
    replayed_v6, others = load_v6()
    v6_fresh, _ = load_v6()  # a second, untouched load for the real BEFORE funnel
    out_path = os.path.join(RESULTS_DIR, "replay_records_v7.jsonl")
    if os.path.exists(out_path):
        os.remove(out_path)

    tier_transitions = {}
    per_property_transitions = {}
    newly_reportable = []
    v7_records = []

    for rec in replayed_v6:
        pkg, ver = rec["package_name"], rec["version"]
        before = snapshot_reachability(rec)

        bpath = os.path.join(BUNDLE_DIR, bundle_filename(pkg, ver))
        with tarfile.open(bpath, "r:gz") as tf:
            cpp = json.load(tf.extractfile("cpp_facts.json"))
            js = json.load(tf.extractfile("js_facts.json"))

        rt.classify_record_reachability(rec, js, cpp)
        # Real pipeline order (rerun_aggregator_applicability.py's own documented order):
        # reachability_tier -> applicability_gate -> adjudication_registry -> staged_enablement
        # -> vendored_attribution -> six_property_aggregator. Missing this step in an earlier
        # draft of this script silently left every newly-promoted candidate's own
        # applicability_status at NOT_YET_DETERMINED -- caught via the real per-candidate
        # `reportable` check below, not assumed correct.
        ag.apply_applicability(rec)
        n_adjudicated = ar.apply_known_adjudications(rec)
        se.enforce_staged_enablement(rec)
        va.attribute_record(rec)
        summary = agg.aggregate_record(rec, enabled_properties=se.ENABLED_PROPERTIES)
        rec["_six_property_summary"] = summary
        rec["_n_newly_adjudicated_step6_rerun"] = n_adjudicated

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

        v7_records.append(rec)
        with open(out_path, "a") as f:
            f.write(json.dumps(rec, sort_keys=True, default=str) + "\n")

    for rec in others:
        with open(out_path, "a") as f:
            f.write(json.dumps(rec, sort_keys=True, default=str) + "\n")

    funnel_before = {k: {"raw": 0, "reportable": 0} for k in ALL_PROPERTY_KEYS}
    funnel_after = {k: {"raw": 0, "reportable": 0} for k in ALL_PROPERTY_KEYS}
    for rec in v6_fresh:
        for k in ALL_PROPERTY_KEYS:
            for f in rec.get(k) or []:
                funnel_before[k]["raw"] += 1
                if f.get("reportable"):
                    funnel_before[k]["reportable"] += 1
    for rec in v7_records:
        for k in ALL_PROPERTY_KEYS:
            for f in rec.get(k) or []:
                funnel_after[k]["raw"] += 1
                if f.get("reportable"):
                    funnel_after[k]["reportable"] += 1

    delta = {
        "tier_transitions": {f"{b}->{a}": n for (b, a), n in sorted(tier_transitions.items())},
        "per_property_transitions": {
            key: {f"{b}->{a}": n for (b, a), n in sorted(v.items())}
            for key, v in per_property_transitions.items()},
        "newly_reportable_findings": newly_reportable,
        "funnel_before": funnel_before,
        "funnel_after": funnel_after,
        "total_adjudications_applied": sum(r.get("_n_newly_adjudicated_step6_rerun", 0)
                                            for r in v7_records),
    }
    with open(os.path.join(RESULTS_DIR, "step6_reachability_rerun_delta.json"), "w") as f:
        json.dump(delta, f, indent=2, sort_keys=True, default=str)

    print("TIER TRANSITIONS (before -> after, real counts):")
    for (b, a), n in sorted(tier_transitions.items(), key=lambda kv: -kv[1]):
        marker = "  <-- CHANGED" if b != a else ""
        print(f"  {b} -> {a}: {n}{marker}")
    print(f"\nTotal adjudications newly applied: {delta['total_adjudications_applied']}")
    print(f"Newly reportable findings from this rerun: {len(newly_reportable)}")
    for item in newly_reportable:
        print(f"  REPORTABLE: {item['package_name']}@{item['version']} {item['property']} "
              f"{item['function']} ({item['before_tier']} -> {item['after_tier']})")
    for k in ALL_PROPERTY_KEYS:
        b, a = funnel_before[k], funnel_after[k]
        changed = " <-- CHANGED" if b != a else ""
        print(f"  {k}: before raw={b['raw']} reportable={b['reportable']} | "
              f"after raw={a['raw']} reportable={a['reportable']}{changed}")


if __name__ == "__main__":
    main()
