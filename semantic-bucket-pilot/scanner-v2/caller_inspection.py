#!/usr/bin/env python3
"""Caller inspection for pointer-parameter destinations (issue #2).

"Absent from source" was too strong. For a pointer-parameter destination the
capacity usually lives in the CALLER. This inspects callers (from the call-graph
facts) of the out-parameter / pointer destinations and splits them into:

  capacity_visible_in_caller   caller passes a local array / alloc with a known
                               size -> capacity is present and exported, just NOT
                               propagated across the call (RECOVERABLE by
                               interprocedural propagation).
  caller_propagates_param      caller passes its OWN parameter through -> the
                               capacity is one frame further up.
  caller_outside_scope         no in-scope caller (API entry / called from
                               outside the scanned module).
  conflicting_capacities       different callers pass different-capacity buffers.
  genuinely_unavailable        caller passes something with no capacity anywhere
                               in the available source.

Works from the cached cpp.json + raw/parameters.tsv; does NOT re-run producers.
Targets: the required_evidence_absent N*sizeof array writes and the
destination_identity_ambiguous pointer destinations (from distinct_ops_v2.jsonl).
"""
import base64
import json
import os
import re
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
EXP = "/tmp/expansion"


def _b64(s):
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except Exception:
        return ""


def param_index(scan_dir):
    """(method_id, name) -> index, and (method_id, index) -> name."""
    p = os.path.join(scan_dir, "raw", "parameters.tsv")
    by_name, by_idx = {}, {}
    if os.path.exists(p):
        for line in open(p, errors="replace"):
            f = line.rstrip("\n").split("\t")
            if len(f) >= 4:
                try:
                    mid, idx, nm = int(f[1]), int(f[2]), _b64(f[3])
                    by_name[(mid, nm)] = idx
                    by_idx[(mid, idx)] = nm
                except Exception:
                    pass
    return by_name, by_idx


def local_has_capacity(d, method_ids, name):
    """Does a local `name` in these functions have a locally-visible capacity
    (fixed array `T x[N]` or an allocation assignment)? Returns a class string
    or None."""
    for l in d.get("locals", []):
        if l.get("name") == name and l.get("method_id") in method_ids:
            code = l.get("code") or ""
            t = l.get("type_full_name") or ""
            if re.search(r"\[\s*\d+\s*\]", code) or re.search(r"\[\s*\d+\s*\]", t):
                return "local_array"
            if code and "*" not in code.split(name)[0] and "[" in code:
                return "local_array"
    # allocation assignment
    lid = {l.get("id"): (l.get("method_id"), l.get("name")) for l in d.get("locals", [])}
    for a in d.get("assignments", []):
        tgt = a.get("target_local_id")
        if tgt in lid and lid[tgt][1] == name and lid[tgt][0] in method_ids:
            if re.search(r"alloc|malloc|calloc", str(a.get("derivation") or ""), re.I):
                return "local_alloc"
    return None


def classify_op(d, by_name, by_idx, fn_by_name, func, dest):
    mids = fn_by_name.get(func, set())
    # is dest a parameter of func? get its index
    idx = None
    for mid in mids:
        if (mid, dest) in by_name:
            idx = by_name[(mid, dest)]
            break
    if idx is None:
        return "dest_not_a_parameter"  # local dest: capacity should be local
    # find call sites to func
    targets = set()
    callsites = []
    for c in d.get("calls", []):
        nm = c.get("name") or c.get("method_full_name")
        cand = c.get("candidate_target_full_names") or []
        if nm == func or func in cand:
            callsites.append(c)
    if not callsites:
        return "caller_outside_scope"
    classes = set()
    for c in callsites:
        args = c.get("arguments") or []
        arg = next((a for a in args if a.get("index") == idx), None)
        if arg is None:
            continue
        vr = arg.get("value_ref") or {}
        if vr.get("kind") == "PARAMETER":
            classes.add("caller_propagates_param")
            continue
        anm = arg.get("name") or ""
        enclosing = {c.get("enclosing_function_id")}
        cap = local_has_capacity(d, enclosing, anm) if anm else None
        if cap:
            classes.add("capacity_visible_in_caller")
        else:
            classes.add("genuinely_unavailable")
    if not classes:
        return "caller_outside_scope"
    if len(classes) > 1 and "capacity_visible_in_caller" in classes and "genuinely_unavailable" in classes:
        return "conflicting_capacities"
    # priority: recoverable signal wins the label if present
    for pref in ("capacity_visible_in_caller", "caller_propagates_param",
                 "genuinely_unavailable"):
        if pref in classes:
            return pref
    return "caller_outside_scope"


def main():
    recs = [json.loads(l) for l in open(os.path.join(HERE, "distinct_ops_v2.jsonl"))]

    def reason(r):
        return ("not_applicable_deterministic_complete"
                if r.get("analysis_status") == "deterministic_complete"
                else (r.get("primary_reason_code") or r.get("reason_code")))

    def has_mult(w):
        s = re.sub(r"sizeof\s*\([^()]*\)", "SZ", str(w))
        s = re.sub(r"sizeof\s+\*?\s*[\w\[\].]+", "SZ", s)
        return any(o in s for o in ("*", "+", "-"))

    targets = defaultdict(list)  # source_label -> [(reason_group, func, dest)]
    for r in recs:
        rn = reason(r)
        if rn == "destination_identity_ambiguous":
            targets[r["_source_label"]].append(("identity_ambiguous_ptr", r.get("function"), r.get("dest")))
        elif rn == "required_evidence_absent" and "sizeof" in str(r.get("width_expr")) and has_mult(r.get("width_expr")):
            targets[r["_source_label"]].append(("array_out_param", r.get("function"), r.get("dest")))

    results = defaultdict(Counter)
    per_op = []
    for label, ops in sorted(targets.items()):
        fid, side = label.split("/")
        p = os.path.join(EXP, fid, side, "cpp.json")
        if not os.path.exists(p):
            continue
        d = json.load(open(p))
        by_name, by_idx = param_index(os.path.join(EXP, fid, side))
        fn_by_name = defaultdict(set)
        for f in d.get("functions", []):
            fn_by_name[f.get("full_name")].add(f.get("id"))
        for grp, func, dest in ops:
            cls = classify_op(d, by_name, by_idx, fn_by_name, func, dest)
            results[grp][cls] += 1
            per_op.append({"source": label, "group": grp, "function": func,
                           "dest": dest, "caller_class": cls})

    report = {"by_group": {g: dict(c) for g, c in results.items()},
              "n_ops": len(per_op)}
    with open(os.path.join(HERE, "caller_inspection.json"), "w") as fh:
        json.dump({"summary": report, "per_op": per_op}, fh, indent=2, sort_keys=True, default=str)

    for grp, c in results.items():
        tot = sum(c.values())
        print(f"\n== {grp}: {tot} ops ==")
        for k, v in c.most_common():
            print(f"    {k:32} {v:5}  ({100*v/tot:.0f}%)")


if __name__ == "__main__":
    main()
