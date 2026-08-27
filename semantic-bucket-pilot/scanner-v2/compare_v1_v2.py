#!/usr/bin/env python3
"""v1-vs-v2 comparison on byte-identical inputs (steps 6-7).

Runs frozen v1 and v2 (v1 + single-object-copy capability) over the same cpp.json
inputs, deduplicates by the frozen operation fingerprint, and reports:
  - distinct operations by route, v1 vs v2
  - how many remain additional-evidence-required
  - how many become deterministically resolved
  - how many become ready for focused LLM review (should be 0: single-object is
    proven safe, not sent to review)
  - every operation that changes route, with the exact new evidence
  - a soundness check: v2 must ONLY move required_evidence_absent -> deterministic;
    it must never change a warning verdict, an open candidate, or any other route,
    and never move a case without single-object evidence.

Inputs default to the expansion scans (the broader population); pass paths to
override.
"""
import glob
import hashlib
import importlib.util
import json
import os
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.abspath(os.path.join(
    HERE, "..", "..", "tchecker-research-complete",
    "portable-engine-full-review-package", "tools"))
sys.path.insert(0, TOOLS)
sys.path.insert(0, HERE)
import single_object_pass as sop

EVIDENCE_RANK = {"deterministic_complete": 3, "open_candidate": 3,
                 "rerouted": 2, "abstained": 1}


def _load(m):
    s = importlib.util.spec_from_file_location(m, os.path.join(TOOLS, m + ".py"))
    mod = importlib.util.module_from_spec(s)
    s.loader.exec_module(mod)
    return mod


def _fp(rec):
    key = "|".join(str(x) for x in (
        rec.get("_source_label"), rec.get("file"), rec.get("function"),
        rec.get("line"), rec.get("dest")))
    return "op_" + hashlib.sha256(key.encode()).hexdigest()[:16]


def _route(r):
    return (None if r.get("analysis_status") == "deterministic_complete"
            else r.get("recommended_route"))


def _dedup(recs):
    g = defaultdict(list)
    for r in recs:
        g[_fp(r)].append(r)
    out = {}
    for fp, grp in g.items():
        out[fp] = sorted(grp, key=lambda r: -EVIDENCE_RANK.get(r["analysis_status"], 0))[0]
    return out


def main():
    inputs = sys.argv[1:] or sorted(glob.glob("/tmp/expansion/*/*/cpp.json"))
    rc = _load("oob_runtime_capacity_verdict")

    v1_all, v2_all, promo_all = [], [], []
    for p in inputs:
        label = "/".join(p.split("/")[-3:-1])
        v1 = rc.analyze_operations(p)
        v2, proms = sop.analyze_operations_v2(p)
        for r in v1:
            r["_source_label"] = label
        for r in v2:
            r["_source_label"] = label
        for pr in proms:
            pr["_source_label"] = label
        v1_all += v1
        v2_all += v2
        promo_all += proms

    v1d = _dedup(v1_all)
    v2d = _dedup(v2_all)

    v1_routes = Counter(str(_route(r)) for r in v1d.values())
    v2_routes = Counter(str(_route(r)) for r in v2d.values())

    # changes on the SAME fingerprint
    changed = []
    soundness_violations = []
    for fp, r1 in v1d.items():
        r2 = v2d.get(fp)
        if r2 is None:
            continue
        if _route(r1) != _route(r2) or r1.get("analysis_status") != r2.get("analysis_status"):
            changed.append((fp, r1, r2))
            # soundness: only required_evidence_absent -> deterministic_complete, with evidence
            ok = (r1.get("analysis_status") == "abstained"
                  and (r1.get("primary_reason_code") or r1.get("reason_code")) == "required_evidence_absent"
                  and r2.get("analysis_status") == "deterministic_complete"
                  and r2.get("v2_promoted") is True
                  and r2.get("evidence"))
            if not ok:
                soundness_violations.append((fp, r1, r2))

    n_v1_aer = v1_routes.get("additional_evidence_required", 0)
    n_v2_aer = v2_routes.get("additional_evidence_required", 0)
    n_v1_det = sum(1 for r in v1d.values() if r.get("analysis_status") == "deterministic_complete")
    n_v2_det = sum(1 for r in v2d.values() if r.get("analysis_status") == "deterministic_complete")
    n_v1_llm = v1_routes.get("semantic_relationship_review", 0) + v1_routes.get("semantic_contract_review", 0)
    n_v2_llm = v2_routes.get("semantic_relationship_review", 0) + v2_routes.get("semantic_contract_review", 0)

    report = {
        "inputs": len(inputs),
        "distinct_operations": len(v1d),
        "v1_routes": dict(v1_routes),
        "v2_routes": dict(v2_routes),
        "additional_evidence_required": {"v1": n_v1_aer, "v2": n_v2_aer, "reduced_by": n_v1_aer - n_v2_aer},
        "deterministically_resolved": {"v1": n_v1_det, "v2": n_v2_det, "gained": n_v2_det - n_v1_det},
        "ready_for_llm_review": {"v1": n_v1_llm, "v2": n_v2_llm, "gained": n_v2_llm - n_v1_llm},
        "operations_changed": len(changed),
        "soundness_violations": len(soundness_violations),
        "changes": [{
            "op_fingerprint": fp, "source": r2.get("_source_label"),
            "function": r2.get("function"), "line": r2.get("line"), "dest": r2.get("dest"),
            "from_route": _route(r1), "from_status": r1.get("analysis_status"),
            "from_reason": r1.get("primary_reason_code") or r1.get("reason_code"),
            "to_status": r2.get("analysis_status"),
            "evidence": r2.get("evidence"),
        } for fp, r1, r2 in changed],
    }
    with open(os.path.join(HERE, "compare_v1_v2_result.json"), "w") as fh:
        json.dump(report, fh, indent=2, sort_keys=True, default=str)

    print(f"inputs: {len(inputs)}   distinct operations: {len(v1d)}")
    print(f"additional_evidence_required : v1={n_v1_aer}  v2={n_v2_aer}  (-{n_v1_aer-n_v2_aer})")
    print(f"deterministically_resolved   : v1={n_v1_det}  v2={n_v2_det}  (+{n_v2_det-n_v1_det})")
    print(f"ready_for_llm_review         : v1={n_v1_llm}  v2={n_v2_llm}  (+{n_v2_llm-n_v1_llm})")
    print(f"operations changed route     : {len(changed)}")
    print(f"SOUNDNESS VIOLATIONS         : {len(soundness_violations)}  (must be 0)")
    if soundness_violations:
        for fp, r1, r2 in soundness_violations[:10]:
            print(f"   VIOLATION {r2.get('function')}:{r2.get('line')} "
                  f"{r1.get('analysis_status')}/{r1.get('reason_code')} -> {r2.get('analysis_status')}")
    print(f"\nsample changes (first 15):")
    for c in report["changes"][:15]:
        e = c["evidence"]
        print(f"   {c['source']:14} {c['function']}:{c['line']} dest={c['dest']} "
              f"{c['from_status']}/{c['from_reason']} -> {c['to_status']} "
              f"[{e['basis']}: {e.get('dest_type', e['form'])}]")


if __name__ == "__main__":
    main()
