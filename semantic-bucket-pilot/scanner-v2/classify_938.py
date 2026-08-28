#!/usr/bin/env python3
"""Divide the 938 local-destination operations into the four groups: is v1's
`required_evidence_absent` correct, or did it MISROUTE cases whose capacity and
write length are both established and only the RELATIONSHIP is unproven?

Groups (per the review):
  G1 identity_evidence_missing   capacity expr not bound to the actual destination
  G2 evidence_missing            write expr not bound to the sink argument
  G3 range_arithmetic_required   both bound, but one numeric value can't be evaluated
  G4 relationship_unresolved     both established, relationship can't be proven

Method (scoped to each op's function; the same name is a different array in
different functions):
  - destination capacity: the op's dest declared as a fixed array `T[N]` in the
    op's function -> capacity value N (literal, bound to dest, evaluable).
  - write length: the op's width_expr (runtime producer) or the count nature
    (cursor / identity group has width None -> a count relationship).
  - both present -> G3 if a numeric operand is symbolic (e.g. `count*sizeof(T)`
    with runtime count), else G4 (both evaluable, relationship not proven by v1).
  - capacity missing -> G1; width missing and capacity present -> (count-based)
    treated as relationship on the count (G4) unless nothing is bound (G2).

Fast: reads distinct_ops_v2.jsonl + caller_inspection.json + per-scan cpp.json.
No producers re-run.
"""
import json
import os
import re
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
EXP = "/tmp/expansion"
ARR = re.compile(r"\[\s*([0-9A-Za-z_]+)\s*\]")


def reason(r):
    return ("not_applicable_deterministic_complete"
            if r.get("analysis_status") == "deterministic_complete"
            else (r.get("primary_reason_code") or r.get("reason_code")))


def dest_capacity(d, method_ids, dest):
    """(capacity_token, is_fixed_array) for dest declared in these functions."""
    for l in d.get("locals", []):
        if l.get("name") == dest and l.get("method_id") in method_ids:
            code = l.get("code") or ""
            t = l.get("type_full_name") or ""
            m = ARR.search(code) or ARR.search(t)
            if m and ("*" not in code.split(dest)[0]):
                return m.group(1), True
    return None, False


def width_evaluable(width):
    """A width is numerically evaluable if it is a pure literal or sizeof of a
    concrete thing with no runtime variable multiplier."""
    if width is None:
        return None
    w = str(width)
    # strip sizeof(...) -> treat as a constant token
    s = re.sub(r"sizeof\s*\([^()]*\)", "C", w)
    s = re.sub(r"sizeof\s+\*?\s*[\w\[\].]+", "C", s)
    # remaining identifiers (not C, not digits) => runtime variable present
    ids = [t for t in re.findall(r"[A-Za-z_]\w*", s) if t != "C"]
    return len(ids) == 0


def main():
    recs = [json.loads(l) for l in open(os.path.join(HERE, "distinct_ops_v2.jsonl"))]
    ci = json.load(open(os.path.join(HERE, "caller_inspection.json")))
    local_keys = {(o["source"], o["function"], o["dest"])
                  for o in ci["per_op"] if o["caller_class"] == "dest_not_a_parameter"}
    # index op records by (source, function, dest); keep first
    rec_by_key = {}
    for r in recs:
        k = (r["_source_label"], r.get("function"), r.get("dest"))
        if k in local_keys and k not in rec_by_key:
            rec_by_key[k] = r

    facts = {}  # source_label -> (cpp.json dict, fn_by_name)
    groups = Counter()
    detail = []
    cap_available = 0
    for (src, func, dest), r in rec_by_key.items():
        fid, side = src.split("/")
        if src not in facts:
            p = os.path.join(EXP, fid, side, "cpp.json")
            d = json.load(open(p))
            fbn = defaultdict(set)
            for f in d.get("functions", []):
                fbn[f.get("full_name")].add(f.get("id"))
            facts[src] = (d, fbn)
        d, fbn = facts[src]
        mids = fbn.get(func, set())
        cap_tok, is_arr = dest_capacity(d, mids, dest)
        width = r.get("width_expr")
        rn = reason(r)

        cap_bound = is_arr
        width_bound = (width is not None) or (rn == "destination_identity_ambiguous")
        if cap_bound:
            cap_available += 1

        if not cap_bound:
            g = "G1_identity_evidence_missing"
        elif not width_bound:
            g = "G2_evidence_missing"
        else:
            # both bound; is a numeric operand unevaluable?
            if rn == "destination_identity_ambiguous":
                # count-based write into a known-capacity array: relationship on the count
                g = "G4_relationship_unresolved"
            else:
                ev = width_evaluable(width)
                cap_literal = bool(re.fullmatch(r"\d+", str(cap_tok)))
                if ev and cap_literal:
                    g = "G4_relationship_unresolved"   # both evaluable, v1 still didn't resolve
                else:
                    g = "G3_range_arithmetic_required"  # a symbolic operand blocks arithmetic
        groups[g] += 1
        detail.append({"source": src, "function": func, "dest": dest,
                       "v1_reason": rn, "capacity_token": cap_tok,
                       "capacity_bound": cap_bound, "width_expr": width,
                       "group": g})

    report = {
        "n_local_ops": len(rec_by_key),
        "capacity_available_locally": cap_available,
        "capacity_available_pct": round(100 * cap_available / max(1, len(rec_by_key)), 1),
        "four_group_split": dict(groups),
        "misrouted_estimate": groups["G3_range_arithmetic_required"] + groups["G4_relationship_unresolved"],
    }
    with open(os.path.join(HERE, "classify_938.json"), "w") as fh:
        json.dump({"summary": report, "detail": detail}, fh, indent=2, sort_keys=True, default=str)

    print(f"local-destination ops examined: {report['n_local_ops']}")
    print(f"capacity available locally (dest is a fixed array): "
          f"{cap_available} ({report['capacity_available_pct']}%)")
    print("\nFOUR-GROUP SPLIT:")
    for g, n in groups.most_common():
        print(f"    {g:34} {n}")
    print(f"\nMISROUTED (both established, relationship/arithmetic -> NOT required_evidence_absent): "
          f"{report['misrouted_estimate']}")
    print("\nsample G4 (relationship_unresolved) — capacity + width both present:")
    for x in [x for x in detail if x['group'].startswith('G4')][:8]:
        print(f"   {x['source']:12} {x['function']}:{x['dest']} cap=[{x['capacity_token']}] "
              f"width={x['width_expr']} (v1={x['v1_reason']})")


if __name__ == "__main__":
    main()
