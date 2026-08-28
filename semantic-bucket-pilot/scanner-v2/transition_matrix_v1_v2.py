#!/usr/bin/env python3
"""v1 -> v2 route transition matrix over the COMPLETE three-producer population.

Population: RUNTIME_CAPACITY + CURSOR + INTERPROCEDURAL over the expansion scans,
deduplicated to distinct physical operations with the FROZEN operation fingerprint
(imported from build_frozen_corpus, never reimplemented) and the frozen
evidence-monotone canonical rule (most evidence established wins; all producer
verdicts retained; genuine disagreement flagged dedup_conflict).

Two populations, identical except the runtime producer:
  v1: oob_runtime_capacity_verdict  (frozen)   + cursor + interproc
  v2: oob_runtime_capacity_v2       (augmented) + cursor + interproc
cursor and interproc are byte-identical between the two, so every route change is
attributable to the runtime stack-capacity capability alone.

Emits, per distinct operation, the (v1 route -> v2 route) transition, the v1 and
v2 route distributions, and the transition matrix — showing how much the frozen
88.8% additional-evidence distribution actually moves, and preserving reason-
specific routes (semantic_relationship_review / range_arithmetic_review /
additional_evidence_required) rather than collapsing them to "LLM review".
"""
import importlib.util
import json
import os
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
TOOLS = os.path.join(REPO, "tchecker-research-complete",
                     "portable-engine-full-review-package", "tools")
FROZEN = os.path.join(REPO, "semantic-bucket-pilot", "frozen-corpus")
sys.path.insert(0, TOOLS)
sys.path.insert(0, HERE)

# Import the FROZEN fingerprint + evidence rank — do not reimplement.
_bfc_spec = importlib.util.spec_from_file_location(
    "build_frozen_corpus", os.path.join(FROZEN, "build_frozen_corpus.py"))
bfc = importlib.util.module_from_spec(_bfc_spec)
_bfc_spec.loader.exec_module(bfc)
_fingerprint = bfc._fingerprint
EVIDENCE_RANK = bfc.EVIDENCE_RANK

import oob_runtime_capacity_v2 as v2
V1 = v2.V1

EXP = "/tmp/expansion"
CURSOR = "oob_cursor_write_verdict"
INTERPROC = "oob_interprocedural_verdict"


def _load(m):
    s = importlib.util.spec_from_file_location(m, os.path.join(TOOLS, m + ".py"))
    mod = importlib.util.module_from_spec(s)
    s.loader.exec_module(mod)
    return mod


def _tag(recs, label, producer):
    for r in recs:
        r["_source_label"] = label
        r["_producer"] = producer
        r["op_fingerprint"] = _fingerprint(r)
    return recs


def _canonical(group):
    """Frozen evidence-monotone canonical: most evidence wins; retain all producer
    verdicts; flag genuine disagreement. Producer order breaks ties (never
    privileges a producer over more evidence)."""
    order = (V1.__name__, CURSOR, INTERPROC)
    ordered = sorted(group, key=lambda r: (
        -EVIDENCE_RANK.get(r["analysis_status"], 0),
        order.index(r["_producer"]) if r["_producer"] in order else 9,
        str(r.get("operation_id"))))
    canon = dict(ordered[0])
    verdicts = [{"producer": r["_producer"], "analysis_status": r["analysis_status"],
                 "route": _route(r),
                 "primary_reason_code": r.get("primary_reason_code") or r.get("reason_code")}
                for r in ordered]
    canon["producer_verdicts"] = verdicts
    distinct = {(v["analysis_status"], v["route"]) for v in verdicts}
    canon["dedup_conflict"] = len(distinct) > 1
    return canon


def _route(r):
    if r["analysis_status"] == "deterministic_complete":
        return "deterministic_complete"
    return r.get("recommended_route") or "UNSET"


def _dedup(raw):
    groups = defaultdict(list)
    for r in raw:
        groups[r["op_fingerprint"]].append(r)
    return {fp: _canonical(g) for fp, g in groups.items()}


def build():
    cursor_mod = _load(CURSOR)
    interp_mod = _load(INTERPROC)
    v1_raw, v2_raw = [], []
    scans = 0
    for fid in sorted(os.listdir(EXP)):
        for side in ("vuln", "patched"):
            p = os.path.join(EXP, fid, side, "cpp.json")
            if not os.path.exists(p):
                continue
            scans += 1
            label = f"{fid}/{side}"
            # runtime: v1 frozen vs v2 augmented, from ONE V1 pass (the slow producer)
            rt_v1, rt_v2, _ = v2.analyze_operations_v1_and_v2(p)
            # cursor + interproc: identical in both populations
            cur = cursor_mod.analyze_operations(p)
            itp = interp_mod.analyze_operations(p)
            v1_raw += _tag(rt_v1, label, V1.__name__)
            v1_raw += _tag([dict(r) for r in cur], label, CURSOR)
            v1_raw += _tag([dict(r) for r in itp], label, INTERPROC)
            v2_raw += _tag(rt_v2, label, V1.__name__)
            v2_raw += _tag([dict(r) for r in cur], label, CURSOR)
            v2_raw += _tag([dict(r) for r in itp], label, INTERPROC)
    return scans, v1_raw, v2_raw


def main():
    scans, v1_raw, v2_raw = build()
    v1d = _dedup(v1_raw)
    v2d = _dedup(v2_raw)
    assert set(v1d) == set(v2d), "fingerprint universe changed between v1 and v2 (must not)"

    v1_routes = Counter(_route(r) for r in v1d.values())
    v2_routes = Counter(_route(r) for r in v2d.values())

    matrix = Counter()
    changed = []
    # a runtime promotion that did NOT surface because another producer dominated
    masked = []
    for fp in v1d:
        a, b = _route(v1d[fp]), _route(v2d[fp])
        matrix[(a, b)] += 1
        if a != b:
            changed.append({"fp": fp, "from": a, "to": b,
                            "function": v2d[fp].get("function"),
                            "file": v2d[fp].get("file"),
                            "dest": v2d[fp].get("dest"),
                            "source": v2d[fp].get("_source_label"),
                            "canonical_producer": v2d[fp].get("_producer"),
                            "in_conflict_group": bool(v2d[fp].get("dedup_conflict"))})

    # detect runtime ops v2 promoted but that stayed masked by a dominating producer
    for fp in v1d:
        if v2d[fp].get("_producer") != V1.__name__:
            # is there a runtime v2 verdict in the group with more/other evidence?
            for v in v2d[fp].get("producer_verdicts", []):
                if v["producer"] == V1.__name__ and v["route"] in (
                        "deterministic_complete", "semantic_relationship_review",
                        "range_arithmetic_review") and _route(v1d[fp]) == _route(v2d[fp]):
                    masked.append({"fp": fp, "runtime_route": v["route"],
                                   "canonical_producer": v2d[fp]["_producer"],
                                   "canonical_route": _route(v2d[fp])})
                    break

    total = len(v1d)
    v1_ae = v1_routes.get("additional_evidence_required", 0)
    v2_ae = v2_routes.get("additional_evidence_required", 0)

    # ---- (2) conflict sensitivity ----
    # Exclude every fingerprint whose v2 canonical group had a cross-producer
    # disagreement, then recompute the distribution and transition on what remains.
    # If the 24.5-point drop persists, it is not an artifact of the evidence-monotone
    # aggregation that resolves conflicts.
    conflict_fps = {fp for fp in v2d if v2d[fp].get("dedup_conflict")}
    changed_in_conflict = [c for c in changed if c["in_conflict_group"]]
    nc = [fp for fp in v1d if fp not in conflict_fps]
    nc_total = len(nc)
    nc_v1_ae = sum(1 for fp in nc if _route(v1d[fp]) == "additional_evidence_required")
    nc_v2_ae = sum(1 for fp in nc if _route(v2d[fp]) == "additional_evidence_required")
    nc_changed = sum(1 for fp in nc if _route(v1d[fp]) != _route(v2d[fp]))
    nc_matrix = Counter()
    for fp in nc:
        a, b = _route(v1d[fp]), _route(v2d[fp])
        if a != b:
            nc_matrix[(a, b)] += 1
    conflict_sensitivity = {
        "conflict_groups_total": len(conflict_fps),
        "changed_ops_in_conflict_groups": len(changed_in_conflict),
        "changed_ops_outside_conflict_groups": len(changed) - len(changed_in_conflict),
        "excluding_conflicts": {
            "distinct_operations": nc_total,
            "v1_additional_evidence": nc_v1_ae,
            "v2_additional_evidence": nc_v2_ae,
            "v1_additional_evidence_share": round(100 * nc_v1_ae / nc_total, 1),
            "v2_additional_evidence_share": round(100 * nc_v2_ae / nc_total, 1),
            "operations_changed": nc_changed,
            "transition_matrix": {f"{a} -> {b}": n
                                  for (a, b), n in sorted(nc_matrix.items(), key=lambda kv: -kv[1])},
        },
    }

    # ---- (3) generalization: 620 changes by function / file / case family ----
    fam = lambda c: c["source"].split("/")[0]           # E1..E5 (CVE/bug family)
    by_function = Counter(c["function"] for c in changed)
    by_file = Counter(c["file"] for c in changed)
    by_family = Counter(fam(c) for c in changed)
    by_family_function = Counter((fam(c), c["function"]) for c in changed)
    generalization = {
        "changed": len(changed),
        "distinct_functions": len(by_function),
        "distinct_files": len(by_file),
        "distinct_case_families": len(by_family),
        "distinct_family_function_pairs": len(by_family_function),
        "by_case_family": dict(by_family),
        "top_functions": by_function.most_common(15),
        "top_files": by_file.most_common(15),
        "share_in_top1_function": round(100 * by_function.most_common(1)[0][1] / len(changed), 1),
        "share_in_top3_functions": round(100 * sum(n for _, n in by_function.most_common(3)) / len(changed), 1),
    }

    report = {
        "scans": scans,
        "distinct_operations": total,
        "v1_route_distribution": dict(v1_routes),
        "v2_route_distribution": dict(v2_routes),
        "v1_additional_evidence_share": round(100 * v1_ae / total, 1),
        "v2_additional_evidence_share": round(100 * v2_ae / total, 1),
        "operations_changed": len(changed),
        "transition_matrix": {f"{a} -> {b}": n for (a, b), n in sorted(matrix.items(), key=lambda kv: -kv[1])},
        "dedup_conflicts_v2": sum(1 for r in v2d.values() if r.get("dedup_conflict")),
        "runtime_promotions_masked_by_other_producer": len(masked),
        "masked_examples": masked[:10],
        "conflict_sensitivity": conflict_sensitivity,
        "generalization": generalization,
        "changed": changed,
    }
    with open(os.path.join(HERE, "transition_matrix_v1_v2.json"), "w") as fh:
        json.dump(report, fh, indent=2, sort_keys=True, default=str)

    print(f"scans {scans}   distinct operations {total}")
    print(f"\nv1 additional_evidence_required : {v1_ae}  ({report['v1_additional_evidence_share']}%)")
    print(f"v2 additional_evidence_required : {v2_ae}  ({report['v2_additional_evidence_share']}%)")
    print(f"operations changed by runtime v2: {len(changed)}")
    print(f"dedup conflicts (v2 population)  : {report['dedup_conflicts_v2']}")
    print(f"runtime promotions masked by another producer: {len(masked)}")
    print("\nv1 route distribution:")
    for k, n in sorted(v1_routes.items(), key=lambda kv: -kv[1]):
        print(f"    {k:34} {n:5}  ({100*n/total:.1f}%)")
    print("\nv2 route distribution:")
    for k, n in sorted(v2_routes.items(), key=lambda kv: -kv[1]):
        print(f"    {k:34} {n:5}  ({100*n/total:.1f}%)")
    print("\ntransition matrix (v1 route -> v2 route), changed rows only:")
    for (a, b), n in sorted(matrix.items(), key=lambda kv: -kv[1]):
        if a != b:
            print(f"    {a:32} -> {b:32} {n:5}")

    cs = conflict_sensitivity
    ex = cs["excluding_conflicts"]
    print("\n--- (2) conflict sensitivity ---")
    print(f"conflict groups                       : {cs['conflict_groups_total']}")
    print(f"changed ops IN conflict groups        : {cs['changed_ops_in_conflict_groups']} / {len(changed)}")
    print(f"changed ops OUTSIDE conflict groups   : {cs['changed_ops_outside_conflict_groups']}")
    print(f"excluding conflicts: {ex['distinct_operations']} ops   "
          f"AE {ex['v1_additional_evidence_share']}% -> {ex['v2_additional_evidence_share']}%   "
          f"({ex['operations_changed']} changed)")

    g = generalization
    print("\n--- (3) generalization of the 620 changes ---")
    print(f"distinct functions {g['distinct_functions']}   distinct files {g['distinct_files']}   "
          f"case families {g['distinct_case_families']}   (family,function) pairs {g['distinct_family_function_pairs']}")
    print(f"by case family: {g['by_case_family']}")
    print(f"concentration: top-1 function {g['share_in_top1_function']}%   top-3 {g['share_in_top3_functions']}%")
    print("top functions:")
    for fn, n in g["top_functions"]:
        print(f"    {str(fn):40} {n}")


if __name__ == "__main__":
    main()
