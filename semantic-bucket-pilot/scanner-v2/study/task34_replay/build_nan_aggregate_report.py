#!/usr/bin/env python3
"""Regenerates the 97-package funnel (funnel_by_property_v6_nan.json), now including
`nan_findings` alongside every other property, from `results/replay_records_v6_nan.jsonl` --
the record set task 4's own `nan_replay_over_97.py` produced (provenance/applicability/
adjudication/staged_enablement/vendored_attribution/six_property_aggregator already applied
per-record). Pure recomputation over already-preserved records -- no Joern, no new scan.

Nan's own reachability model, disclosed explicitly here (roadmap step 4's own "apply ...
reachability ..." requirement): `nan_findings` does NOT go through `reachability_tier.py`'s
`classify_record_reachability()` -- that module classifies the STAGED properties (lock_balance,
protected_field, oob_*) via a real JS/native call-graph tier computed AFTER the fact.
`resource_guard_verdict_nan.py` computes its OWN reachability tier (`js_reachability_tier`,
"confirmed_call"/"exported_registration") INLINE, as part of verdict construction itself (a
real JS call chain or an unconditional whole-module re-export, traced during the same pass that
finds the acquisition call) -- `applicability_gate._nan_applicable()` gates on that field
directly. Running `reachability_tier.py` over `nan_findings` as well would be a category error:
that module's own field names (`reachability_status`) do not exist on a nan_finding and its own
STAGED_APPLICABILITY_KEYS list deliberately does not include `nan_findings` for this reason.
Reachability for Nan IS applied -- via its own, purpose-built mechanism, not the shared one.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(HERE, "results")

ALL_PROPERTY_KEYS = (
    "r04_findings", "r05_findings", "r06_findings", "nan_findings",
    "lock_balance_findings", "protected_field_findings",
    "oob_write_candidates", "oob_index_write_candidates", "oob_read_candidates",
    "oob_compare_candidates",
)


def main():
    with open(os.path.join(RESULTS_DIR, "replay_records_v6_nan.jsonl")) as f:
        recs = [json.loads(line) for line in f]

    funnel = {k: {"raw_count": 0, "reportable_count": 0} for k in ALL_PROPERTY_KEYS}
    per_package_nan = []
    replayed = 0
    inherited_failure = 0

    for r in recs:
        if r.get("outcome") == "REPLAYED":
            replayed += 1
        else:
            inherited_failure += 1
        for key in ALL_PROPERTY_KEYS:
            for f in r.get(key) or []:
                funnel[key]["raw_count"] += 1
                if f.get("reportable"):
                    funnel[key]["reportable_count"] += 1
        nan_raw = len(r.get("nan_findings") or [])
        nan_reportable = sum(1 for f in (r.get("nan_findings") or []) if f.get("reportable"))
        if nan_raw:
            per_package_nan.append({
                "package_name": r["package_name"], "version": r["version"],
                "nan_raw": nan_raw, "nan_reportable": nan_reportable,
                "nan_verdicts": sorted({f.get("verdict") for f in r["nan_findings"]}),
            })

    out = {
        "packages_total": len(recs),
        "packages_replayed": replayed,
        "packages_inherited_upstream_failure": inherited_failure,
        "funnel_by_property": funnel,
        "packages_with_any_raw_nan_finding": sorted(
            per_package_nan, key=lambda x: (-x["nan_reportable"], -x["nan_raw"])),
    }
    out_path = os.path.join(RESULTS_DIR, "funnel_by_property_v6_nan.json")
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
    print(json.dumps(out, indent=2, sort_keys=True))
    return out


if __name__ == "__main__":
    main()
