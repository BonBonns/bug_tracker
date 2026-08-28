#!/usr/bin/env python3
"""Per-operation evidence trace for the local-destination cases.

Distinguishes the THREE levels the review insists on:
  L1 source declaration    (the `T buf[N]` exists in the .c/.h)
  L2 normalized fact        (cpp.json `locals` carries `T[N]` for dest in fn)
  L3 producer binding       (compute_allocation_extents ESTABLISHED an extent for
                             (fn, dest) -- i.e. the producer actually consumed it)

Only L3 proves a pure routing mistake. The 544 "capacity in source" cases split
by the defect they actually reveal:

  router_misclassification     L2 yes AND L3 yes, yet reason=required_evidence_absent
  producer_consumer_gap        L2 yes AND L3 no  (fact present, never consumed)
  normalizer_evidence_loss     L2 no  AND raw-locals yes (Joern exported, dropped)
  frontend_evidence_loss       L2 no  AND raw-locals no (source has it, not exported)
                               [source presence spot-checked separately]
  audit_identity_error         capacity matched a same-named var in another function

Also accounts for the 938->738 collapse (200 additional write-ops to the same
destinations) as an explicit accounting group, and marks every G4 candidate for
per-operation validation (identity/offset/type/lifetime/remaining capacity).
"""
import base64
import importlib.util
import json
import os
import re
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.abspath(os.path.join(
    HERE, "..", "..", "tchecker-research-complete",
    "portable-engine-full-review-package", "tools"))
import sys
sys.path.insert(0, TOOLS)
EXP = "/tmp/expansion"
ARR = re.compile(r"\[\s*([0-9A-Za-z_]+)\s*\]")


def _load(m):
    s = importlib.util.spec_from_file_location(m, os.path.join(TOOLS, m + ".py"))
    mod = importlib.util.module_from_spec(s)
    s.loader.exec_module(mod)
    return mod


AE = _load("allocation_extent")


def _b64(s):
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except Exception:
        return ""


def raw_local_is_array(scan_dir, method_ids, dest):
    """Does raw/locals.tsv carry `dest` as a fixed-array IN one of these functions
    (method-id scoped, to avoid a same-named array in another function -- an
    identity error)? Returns True/False, plus whether a same-named array exists in
    a DIFFERENT function (identity-collision signal)."""
    p = os.path.join(scan_dir, "raw", "locals.tsv")
    if not os.path.exists(p):
        return None, False
    in_fn = False
    other_fn_array = False
    for line in open(p, errors="replace"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 5 and _b64(f[2]) == dest:
            try:
                mid = int(f[1])
            except Exception:
                continue
            code, typ = _b64(f[3]), _b64(f[4])
            is_arr = bool(ARR.search(code) or ARR.search(typ))
            if is_arr:
                if mid in method_ids:
                    in_fn = True
                else:
                    other_fn_array = True
    return in_fn, other_fn_array


def l2_capacity(d, method_ids, dest):
    for l in d.get("locals", []):
        if l.get("name") == dest and l.get("method_id") in method_ids:
            code = l.get("code") or ""
            t = l.get("type_full_name") or ""
            m = ARR.search(code) or ARR.search(t)
            if m and "*" not in code.split(dest)[0]:
                return m.group(1)
    return None


def main():
    recs = [json.loads(l) for l in open(os.path.join(HERE, "distinct_ops_v2.jsonl"))]
    ci = json.load(open(os.path.join(HERE, "caller_inspection.json")))
    local_ops = [o for o in ci["per_op"] if o["caller_class"] == "dest_not_a_parameter"]
    local_keys = {(o["source"], o["function"], o["dest"]) for o in local_ops}

    # operation-level records for those destinations
    op_recs = [r for r in recs
               if (r["_source_label"], r.get("function"), r.get("dest")) in local_keys]

    # accounting: ops vs destinations
    accounting = {
        "local_operations_reported_by_caller_inspection": len(local_ops),
        "distinct_destinations": len(local_keys),
        "collapsed_extra_operations": len(local_ops) - len(local_keys),
        "operation_level_records_traced": len(op_recs),
    }

    facts = {}
    trace = []
    for r in op_recs:
        src = r["_source_label"]
        fid, side = src.split("/")
        scan_dir = os.path.join(EXP, fid, side)
        if src not in facts:
            d = json.load(open(os.path.join(scan_dir, "cpp.json")))
            fbn = defaultdict(set)
            for f in d.get("functions", []):
                fbn[f.get("full_name")].add(f.get("id"))
            ext = AE.compute_allocation_extents(d)
            facts[src] = (d, fbn, ext)
        d, fbn, ext = facts[src]
        func, dest = r.get("function"), r.get("dest")
        mids = fbn.get(func, set())
        l2 = l2_capacity(d, mids, dest)
        l3 = any((fn, dest) in ext and ext[(fn, dest)].get("establishment_status") == "ESTABLISHED"
                 for fn in mids)
        reason = (r.get("primary_reason_code") or r.get("reason_code"))
        # classify defect
        if l2 is not None and l3:
            defect = "router_misclassification" if reason == "required_evidence_absent" else "l3_bound_ok"
        elif l2 is not None and not l3:
            defect = "producer_consumer_gap"
        else:  # l2 is None (no fixed-array capacity for dest in this function)
            raw_in_fn, other_fn = raw_local_is_array(scan_dir, mids, dest)
            if raw_in_fn is None:
                defect = "raw_unavailable"
            elif raw_in_fn:
                defect = "normalizer_evidence_loss"  # raw has it in THIS fn, cpp.json dropped it
            elif other_fn:
                defect = "audit_identity_collision"  # array exists only in a DIFFERENT function
            else:
                defect = "frontend_or_genuinely_absent"
        trace.append({
            "source": src, "function": func, "line": r.get("line"), "dest": dest,
            "reason": reason, "width_expr": r.get("width_expr"),
            "L2_normalized_capacity": l2, "L3_producer_bound": l3,
            "defect_category": defect,
        })

    by_defect = Counter(t["defect_category"] for t in trace)
    report = {"accounting": accounting, "by_defect_category": dict(by_defect),
              "n_traced": len(trace)}
    with open(os.path.join(HERE, "evidence_trace.json"), "w") as fh:
        json.dump({"summary": report, "trace": trace}, fh, indent=2, sort_keys=True, default=str)

    print("ACCOUNTING:", json.dumps(accounting))
    print("\nDEFECT CATEGORY SPLIT (per operation):")
    for k, v in by_defect.most_common():
        print(f"    {k:34} {v}")
    # sanity: any router_misclassification? show them (these would be true routing bugs)
    rm = [t for t in trace if t["defect_category"] == "router_misclassification"]
    print(f"\nrouter_misclassification (L3-bound yet required_evidence_absent): {len(rm)}")
    for t in rm[:8]:
        print(f"   {t['source']} {t['function']}:{t['line']} dest={t['dest']} cap={t['L2_normalized_capacity']}")


if __name__ == "__main__":
    main()
