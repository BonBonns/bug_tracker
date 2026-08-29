#!/usr/bin/env python3
"""Proc B: delegation V1+V2 verification over the immutable cache.
Args: <sv_dir> <tools_dir> <cache_dir> <out.json>
Runs analyze_operations_v1_and_v2 (single V1 pass; V2 adjudicates delegated
handoffs), captures pre/post identities, validates EVERY emitted record (V1 frozen
and V2 canonical) under analysis_record.validate_record (schema v2), and records
v1_provenance / V2 disposition at each delegated site."""
import glob, json, os, re, sys, importlib.util
sv_dir, tools_dir, cache_dir, out_path = sys.argv[1:5]
sys.path.insert(0, sv_dir)
sys.path.insert(0, tools_dir)

import analysis_record as AR
import oob_runtime_capacity_v2 as V2
from callee_contracts import CALLEE_CONTRACTS
BARE = re.compile(r'[A-Za-z_]\w*')

print("SCHEMA_VERSION =", AR.SCHEMA_VERSION)
print("delegated registered:", "delegated_to_stack_capacity_v2" in AR.REASON_DEFINITIONS)
print("write_exceeds registered:", "write_exceeds_stack_capacity" in AR.REASON_DEFINITIONS)


def nonbare_sites(d):
    keys = set()
    for c in d.get('calls', []):
        callee = c.get('method_full_name') or c.get('name')
        contract = CALLEE_CONTRACTS.get(callee)
        if contract is None:
            continue
        args = sorted(c.get('arguments', []), key=lambda a: a.get('index', 0))
        da, wa = contract['dest_arg'], contract['width_arg']
        if da >= len(args) or wa >= len(args):
            continue
        dest = (args[da].get('code') or '').strip()
        if dest and not re.fullmatch(BARE, dest):
            keys.add((dest, c.get('line')))
    return keys


result = {
    "v1_records_total": 0, "v2_records_total": 0,
    "v1_invalid": [], "v2_invalid": [],
    "delegated_sites": [],           # per-site pre/post identity
    "v2_disposition_counts": {},     # at delegated sites
    "v2_safe_promotions": 0, "v2_oversized_promotions": 0,
    "v1_provenance_missing": [],     # delegated sites missing v1_provenance in V2 out
    "nonbare_v1_by_reason": {},      # V1 reason at non-bare sites (delegation branch)
    "nonbare_v1_by_status": {},
}

for cpp in sorted(glob.glob(os.path.join(cache_dir, "*.cpp.json"))):
    sid = os.path.basename(cpp).split('.')[0]
    d = json.load(open(cpp))
    nb = nonbare_sites(d)
    v1_frozen, v2_out, transitions = V2.analyze_operations_v1_and_v2(cpp)
    result["v1_records_total"] += len(v1_frozen)
    result["v2_records_total"] += len(v2_out)

    # validate EVERY emitted record under schema v2
    for r in v1_frozen:
        try:
            AR.validate_record(r)
        except Exception as e:
            result["v1_invalid"].append({"sid": sid, "fn": r.get("function"),
                                         "line": r.get("line"), "err": str(e)})
    for r in v2_out:
        try:
            AR.validate_record(r)
        except Exception as e:
            result["v2_invalid"].append({"sid": sid, "fn": r.get("function"),
                                         "line": r.get("line"), "err": str(e)})

    # V1 non-bare reason/status distribution (delegation branch)
    v1_by_key = {(r.get("dest"), r.get("line")): r for r in v1_frozen}
    for k in nb:
        r = v1_by_key.get(k)
        if not r:
            continue
        rc = r.get("reason_code")
        st = r.get("analysis_status")
        result["nonbare_v1_by_reason"][rc] = result["nonbare_v1_by_reason"].get(rc, 0) + 1
        result["nonbare_v1_by_status"][st] = result["nonbare_v1_by_status"].get(st, 0) + 1

    # delegated sites: pre (V1 rerouted) / post (V2 canonical)
    v2_by_key = {(r.get("dest"), r.get("line")): r for r in v2_out}
    for k in nb:
        v1r = v1_by_key.get(k)
        if not v1r or v1r.get("reason_code") != "delegated_to_stack_capacity_v2":
            continue
        v2r = v2_by_key.get(k)
        disp = v2r.get("_v2_disposition") if v2r else None
        result["v2_disposition_counts"][disp] = result["v2_disposition_counts"].get(disp, 0) + 1
        if v2r and v2r.get("analysis_status") == "deterministic_complete":
            result["v2_safe_promotions"] += 1
        if v2r and v2r.get("proven_oversized"):
            result["v2_oversized_promotions"] += 1
        if not (v2r and v2r.get("v1_provenance")):
            result["v1_provenance_missing"].append({"sid": sid, "dest": k[0], "line": k[1]})
        result["delegated_sites"].append({
            "sid": sid, "function": v1r.get("function"), "dest": k[0], "line": k[1],
            "v1": {"analysis_status": v1r.get("analysis_status"),
                   "reason_code": v1r.get("reason_code"),
                   "recommended_route": v1r.get("recommended_route"),
                   "candidate_class": v1r.get("candidate_class"),
                   "destination_form": v1r.get("destination_form")},
            "v2": {"analysis_status": v2r.get("analysis_status") if v2r else None,
                   "reason_code": v2r.get("reason_code") if v2r else None,
                   "disposition": disp,
                   "has_v1_provenance": bool(v2r and v2r.get("v1_provenance")),
                   "v2_evidence": (v2r or {}).get("_v2_evidence")},
        })

json.dump(result, open(out_path, "w"), indent=1, sort_keys=True)
print(f"v1_total={result['v1_records_total']} v2_total={result['v2_records_total']}")
print(f"v1_invalid={len(result['v1_invalid'])} v2_invalid={len(result['v2_invalid'])}")
print("nonbare_v1_by_reason:", result["nonbare_v1_by_reason"])
print("delegated sites:", len(result["delegated_sites"]),
      "dispositions:", result["v2_disposition_counts"])
print("v2 safe promotions:", result["v2_safe_promotions"],
      "v2 oversized:", result["v2_oversized_promotions"])
print("v1_provenance missing:", len(result["v1_provenance_missing"]))
