#!/usr/bin/env python3
"""v1-vs-v2 (stack capability) over identical inputs. Archives every transition
and enforces: (a) only operations justified by newly-consumed stack_fixed_array
evidence changed; (b) zero unsupported promotions (every deterministic_complete
carries a type-matched, offset-0, k<=N comparison); (c) heap/other records
unchanged.
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
import oob_runtime_capacity_v2 as v2
V1 = v2.V1


def _fp(r, label):
    key = "|".join(str(x) for x in (label, r.get("file"), r.get("function"), r.get("line"), r.get("dest")))
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _state(r):
    return (r.get("analysis_status"),
            None if r.get("analysis_status") == "deterministic_complete" else r.get("recommended_route"),
            r.get("primary_reason_code") or r.get("reason_code"))


def main():
    inputs = sys.argv[1:] or sorted(glob.glob("/tmp/expansion/*/*/cpp.json"))
    all_tr = []
    changed = 0
    unjustified = []
    unsupported = []
    heap_touched = []
    by_disp = Counter()
    total_ops = 0
    for p in inputs:
        label = "/".join(p.split("/")[-3:-1])
        v1 = {(_fp(r, label)): r for r in V1.analyze_operations(p)}
        v2recs, trans = v2.analyze_operations_v2(p)
        v2m = {(_fp(r, label)): r for r in v2recs}
        total_ops += len(v1)
        for fp, r1 in v1.items():
            r2 = v2m.get(fp)
            if r2 is None:
                continue
            if _state(r1) == _state(r2):
                continue
            changed += 1
            ev = r2.get("_v2_evidence")
            disp = r2.get("_v2_disposition")
            by_disp[disp] += 1
            # (a) only justified by stack/object evidence -- TWO justified provenances now:
            # "stack_fixed_array" (bare destination, the original path) and
            # "stack_or_scalar_object" (V1's delegated_to_stack_capacity_v2 handoff for a
            # non-bare destination -- struct-member array, &scalar, array+offset -- adjudicated
            # by _adjudicate_delegated via the SAME compare()). Neither is heap evidence.
            if not ev or ev.get("provenance") not in ("stack_fixed_array", "stack_or_scalar_object"):
                unjustified.append((label, r2.get("function"), r2.get("line")))
            # (b) no unsupported promotion
            if r2.get("analysis_status") == "deterministic_complete":
                note = (ev or {}).get("note", "")
                if not ("<=" in note and ("type-matched" in note or "byte array" in note)):
                    unsupported.append((label, r2.get("function"), r2.get("line"), note))
            # (c) heap/other must not change: the only legitimate movers are
            # v1 abstained+required_evidence_absent (bare destination, original path) and
            # v1 rerouted+delegated_to_stack_capacity_v2 (non-bare destination, delegation path).
            # Anything else changing between V1-raw and V2-final IS a heap/other-domain leak.
            r1_moved = (
                (r1.get("analysis_status") == "abstained"
                 and (r1.get("primary_reason_code") or r1.get("reason_code")) == "required_evidence_absent")
                or
                (r1.get("analysis_status") == "rerouted"
                 and (r1.get("primary_reason_code") or r1.get("reason_code")) == "delegated_to_stack_capacity_v2")
            )
            if not r1_moved:
                heap_touched.append((label, r2.get("function"), r2.get("line")))
        for t in trans:
            t["source"] = label
        all_tr += trans

    report = {
        "inputs": len(inputs), "total_operations": total_ops,
        "operations_changed": changed,
        "by_disposition": dict(by_disp),
        "unjustified_changes": len(unjustified),
        "unsupported_promotions": len(unsupported),
        "heap_or_other_touched": len(heap_touched),
        "transitions": all_tr,
    }
    with open(os.path.join(HERE, "compare_v1_v2_stack.json"), "w") as fh:
        json.dump(report, fh, indent=2, sort_keys=True, default=str)

    print(f"inputs {len(inputs)}   total operations {total_ops}")
    print(f"operations changed: {changed}")
    print(f"  by disposition: {dict(by_disp)}")
    print(f"unjustified changes (no stack evidence): {len(unjustified)}  (must be 0)")
    print(f"unsupported deterministic promotions   : {len(unsupported)}  (must be 0)")
    print(f"heap/other records touched             : {len(heap_touched)}  (must be 0)")
    if unsupported:
        for u in unsupported[:8]:
            print("   UNSUPPORTED:", u)
    # deterministic promotions: unique functions
    det = [t for t in all_tr if t["disposition"] == "deterministic_complete"]
    print(f"deterministic promotions: {len(det)} ops across "
          f"{len({(t['source'].split('/')[0], t['function']) for t in det})} (cve,function) / "
          f"{len({t['function'] for t in det})} function names")
    assert len(unjustified) == 0 and len(unsupported) == 0 and len(heap_touched) == 0, \
        "v2 made an unjustified/unsupported/heap-affecting change"
    print("\nALL INVARIANTS HOLD: only stack-capacity-justified changes, 0 unsupported, heap unchanged.")


if __name__ == "__main__":
    main()
