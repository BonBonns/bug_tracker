#!/usr/bin/env python3
"""Full tally of EVERY deterministic_complete / proven_oversized in V2's canonical
output across the whole cache, categorized by capacity provenance, so no promotion
(delegated OR pre-existing bare-stack path) is hidden. Args: <sv> <tools> <cache> <out>."""
import glob, json, os, sys
sv, tools, cache, out_path = sys.argv[1:5]
sys.path.insert(0, sv); sys.path.insert(0, tools)
import oob_runtime_capacity_v2 as V2
import analysis_record as AR

promos = []
oversized = []
for cpp in sorted(glob.glob(os.path.join(cache, "*.cpp.json"))):
    sid = os.path.basename(cpp).split('.')[0]
    _v1, v2_out, _tr = V2.analyze_operations_v1_and_v2(cpp)
    for r in v2_out:
        st = r.get("analysis_status")
        if st == "deterministic_complete":
            ev = r.get("_v2_evidence") or {}
            promos.append({"sid": sid, "function": r.get("function"), "dest": r.get("dest"),
                           "line": r.get("line"), "delegated": bool(r.get("v1_provenance")),
                           "provenance": ev.get("provenance"), "basis": r.get("capacity_basis"),
                           "note": ev.get("note"), "elem": ev.get("element_type"),
                           "count": ev.get("element_count"), "off": ev.get("offset_elements"),
                           "width": ev.get("width"),
                           "established_property": r.get("established_property")})
        if r.get("proven_oversized"):
            oversized.append({"sid": sid, "function": r.get("function"), "dest": r.get("dest"),
                              "line": r.get("line"), "delegated": bool(r.get("v1_provenance"))})

res = {"deterministic_complete_total": len(promos), "proven_oversized_total": len(oversized),
       "promotions": promos, "oversized": oversized}
json.dump(res, open(out_path, "w"), indent=1, sort_keys=True)
print("deterministic_complete total:", len(promos),
      " (delegated:", sum(p["delegated"] for p in promos),
      " bare-stack:", sum(not p["delegated"] for p in promos), ")")
print("proven_oversized total:", len(oversized))
for p in promos:
    print("  DC", "DELEG" if p["delegated"] else "bare ", p["sid"], p["function"], repr(p["dest"]),
          "L%s" % p["line"], "|", p["provenance"], p["elem"], "cnt", p["count"], "off", p["off"], "w", p["width"], "|", p["note"])
