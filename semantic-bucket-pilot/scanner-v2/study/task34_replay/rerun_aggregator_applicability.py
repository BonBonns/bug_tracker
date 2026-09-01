#!/usr/bin/env python3
"""Rerun step: applies the new applicability_gate.py (the real, missing affirmative-
applicability step) on top of results/replay_records_v2.jsonl (already reachability-corrected
and adjudicated -- task #32 reopened), then recomputes staged_enablement/vendored_attribution/
six_property_aggregator fresh. Still no Joern rebuild, no new download, no re-running R06 --
purely a recomputation of the applicability/staging/aggregation layers over already-preserved
records.

NOTE on where applicability_gate.py belongs in the real pipeline: it is NOT wired into
run_pipeline_one.py's own run_one() (unlike adjudication_registry.py) -- applicability_gate.py
depends on `reachability_status`, which run_one() never computes (reachability_tier.py is
applied in a separate, later post-processing stage, same as staged_enablement.py and
six_property_aggregator.py). It belongs in that same post-processing stage, applied by whatever
driver eventually runs the full corpus pipeline end-to-end -- today, that driver is this
replay's own rerun scripts; in the future, task #34's own eventual full-corpus-run orchestrator.

Real pipeline order this script follows: reachability_tier (already applied, v2) ->
applicability_gate -> adjudication_registry (re-applied; idempotent on an exact match, and
necessary in case applicability_gate's own recompute of reportable needs to be re-vetoed) ->
staged_enablement -> vendored_attribution -> six_property_aggregator.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER_V2 = os.path.dirname(os.path.dirname(HERE))
RESULTS_DIR = os.path.join(HERE, "results")
sys.path.insert(0, SCANNER_V2)
import applicability_gate as ag  # noqa: E402
import adjudication_registry as ar  # noqa: E402
import staged_enablement as se  # noqa: E402
import vendored_attribution as va  # noqa: E402
import six_property_aggregator as agg  # noqa: E402

ALL_PROPERTY_KEYS = agg.ALL_PROPERTY_KEYS


def load_v2():
    replayed, others = [], []
    with open(os.path.join(RESULTS_DIR, "replay_records_v2.jsonl")) as f:
        for line in f:
            d = json.loads(line)
            (replayed if d.get("outcome") == "REPLAYED" else others).append(d)
    return replayed, others


def main():
    replayed, others = load_v2()
    out_path = os.path.join(RESULTS_DIR, "replay_records_v3.jsonl")
    if os.path.exists(out_path):
        os.remove(out_path)

    total_applicability_applied = 0
    newly_reportable = []
    v3_records = []

    for rec in replayed:
        n = ag.apply_applicability(rec)
        total_applicability_applied += n
        ar.apply_known_adjudications(rec)  # idempotent re-apply -- exact match only
        se.enforce_staged_enablement(rec)
        va.attribute_record(rec)
        summary = agg.aggregate_record(rec, enabled_properties=se.ENABLED_PROPERTIES)
        rec["_six_property_summary"] = summary
        rec["_n_applicability_applied_this_rerun"] = n

        for key in ALL_PROPERTY_KEYS:
            for f in rec.get(key) or []:
                if f.get("reportable"):
                    newly_reportable.append({
                        "package_name": rec["package_name"], "version": rec["version"],
                        "property": key, "function": f.get("function") or f.get("method_name"),
                        "reachability_status": f.get("reachability_status"),
                        "applicability_status": f.get("applicability_status"),
                        "adjudication_status": f.get("adjudication_status"),
                    })

        v3_records.append(rec)
        with open(out_path, "a") as f:
            f.write(json.dumps(rec, sort_keys=True, default=str) + "\n")

    for rec in others:
        with open(out_path, "a") as f:
            f.write(json.dumps(rec, sort_keys=True, default=str) + "\n")

    funnel_v2 = {k: {"raw": 0, "reportable": 0} for k in ALL_PROPERTY_KEYS}
    funnel_v3 = {k: {"raw": 0, "reportable": 0} for k in ALL_PROPERTY_KEYS}
    v2_fresh, _ = load_v2()
    for rec in v2_fresh:
        for k in ALL_PROPERTY_KEYS:
            for f in rec.get(k) or []:
                funnel_v2[k]["raw"] += 1
                if f.get("reportable"):
                    funnel_v2[k]["reportable"] += 1
    for rec in v3_records:
        for k in ALL_PROPERTY_KEYS:
            for f in rec.get(k) or []:
                funnel_v3[k]["raw"] += 1
                if f.get("reportable"):
                    funnel_v3[k]["reportable"] += 1

    out = {
        "total_applicability_applied": total_applicability_applied,
        "newly_reportable_findings": newly_reportable,
        "funnel_v2": funnel_v2, "funnel_v3": funnel_v3,
    }
    with open(os.path.join(RESULTS_DIR, "applicability_rerun_delta.json"), "w") as f:
        json.dump(out, f, indent=2, sort_keys=True, default=str)

    print(f"Total applicability_status=APPLICABLE newly applied: {total_applicability_applied}")
    print(f"Total reportable=True findings, corpus-wide: {len(newly_reportable)}")
    for item in newly_reportable:
        print(f"  REPORTABLE: {item['package_name']}@{item['version']} {item['property']} "
              f"{item['function']} (reachability={item['reachability_status']})")
    for k in ALL_PROPERTY_KEYS:
        v2, v3 = funnel_v2[k], funnel_v3[k]
        changed = " <-- CHANGED" if v2 != v3 else ""
        print(f"  {k}: v2 raw={v2['raw']} reportable={v2['reportable']} | "
              f"v3 raw={v3['raw']} reportable={v3['reportable']}{changed}")


if __name__ == "__main__":
    main()
