#!/usr/bin/env python3
"""Trace every expected CWE131 safe counterpart through the six pipeline stages, to test
whether the one-sided byte/element-mismatch topology is legitimate (safe side resolves
deterministically) or a pipeline artifact. NO model calls.

Stages per (file, function): (1) source case exists; (2) copy op recognized; (3) capacity
+ length facts generated; (4) producer status/reason; (5) route; (6) sanitizer+inclusion.

Usage: cwe131_safeside_audit.py <scan_out_dir> <src_dir>
"""
import json
import os
import re
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.abspath(os.path.join(HERE, "..", "..", "tchecker-research-complete",
                                     "portable-engine-full-review-package", "tools"))
sys.path.insert(0, TOOLS); sys.path.insert(0, HERE)
import allocation_extent as AE
import oob_runtime_capacity_v2 as v2
import build_juliet_corpus as B
import juliet_sanitize as san

SINKS = {"memcpy", "memmove", "strcpy", "strncpy", "wcscpy", "wcsncpy", "strcat", "wcscat"}


def main():
    scan_out, src_dir = sys.argv[1], sys.argv[2]
    cpp = os.path.join(scan_out, "cpp.json")
    d = json.load(open(cpp))
    ext = AE.compute_allocation_extents(d)
    sink_at = defaultdict(list)
    for c in d.get("calls", []):
        if c.get("name") in SINKS:
            a0 = next((a for a in c.get("arguments", []) if a.get("index") == 0), None)
            a2 = next((a for a in c.get("arguments", []) if a.get("index") == 2), None)
            sink_at[(os.path.basename(c.get("file") or ""), c.get("line"))].append(
                (c.get("enclosing_function_id"), a0.get("name") if a0 else None,
                 (a2.get("code") if a2 else None)))
    recs, _ = v2.analyze_operations_v2(cpp)
    franges = B.func_ranges(cpp)

    by_oracle = {"vulnerable": Counter(), "safe": Counter()}
    route_by_oracle = {"vulnerable": Counter(), "safe": Counter()}
    reason_by_oracle = {"vulnerable": Counter(), "safe": Counter()}
    examples = {"vulnerable": [], "safe": []}
    for r in recs:
        oc = B.oracle(r.get("function") or "")
        if oc is None:
            continue
        base = os.path.basename(r.get("file") or "")
        line, dest = r.get("line"), r.get("dest")
        st = by_oracle[oc]
        st["0_source_op_seen"] += 1
        # (2) copy op recognized on the flaw/fix line
        lines = B.src_lines(src_dir, base)
        stmt = lines[line - 1].strip() if (lines and line and 1 <= line <= len(lines)) else ""
        if not (re.search(r"\b(?:memcpy|memmove|strcpy|strncpy|wcscpy|wcsncpy|strcat|wcscat)\b", stmt)):
            st["stop_no_copy_op_recognized"] += 1; continue
        st["2_copy_op_recognized"] += 1
        # (3) capacity + length facts
        sites = sink_at.get((base, line), [])
        fn_dest = next(((f, dn, w) for (f, dn, w) in sites if dn == dest), (None, None, None))
        ev = r.get("_v2_evidence") or {}
        stack_cap = isinstance(ev.get("element_count"), int)
        heap_fact = ext.get((fn_dest[0], fn_dest[1])) if fn_dest[0] is not None else None
        heap_cap = bool(heap_fact and heap_fact.get("establishment_status") == "ESTABLISHED")
        width = fn_dest[2]
        if (stack_cap or heap_cap) and width:
            st["3_capacity_and_length_facts"] += 1
        else:
            st["stop_missing_facts"] += 1
        # (4)(5) producer status + route
        route = r.get("recommended_route")
        route_by_oracle[oc][str(route)] += 1
        reason_by_oracle[oc][str(r.get("primary_reason_code") or r.get("analysis_status"))] += 1
        if len(examples[oc]) < 4 and "131" in base:
            examples[oc].append({"file": base[:52], "line": line, "dest": dest,
                                 "width": width,
                                 "heap_size": (heap_fact or {}).get("size_expression") if heap_cap else None,
                                 "stack_ec": ev.get("element_count"),
                                 "route": route,
                                 "status": r.get("analysis_status"),
                                 "reason": r.get("primary_reason_code")})

    report = {"model_calls": 0,
              "stage_funnel": {k: dict(v) for k, v in by_oracle.items()},
              "route_by_oracle": {k: dict(v) for k, v in route_by_oracle.items()},
              "reason_by_oracle": {k: dict(v) for k, v in reason_by_oracle.items()},
              "examples": examples}
    outp = os.path.join(HERE, "study", "juliet", "cwe131_safeside_audit.json")
    with open(outp, "w") as fh:
        json.dump(report, fh, indent=2, sort_keys=True, default=str)
    for oc in ("vulnerable", "safe"):
        print(f"=== {oc} ===")
        print("  stage funnel:", dict(by_oracle[oc]))
        print("  routes:", dict(route_by_oracle[oc]))
        print("  reasons:", dict(reason_by_oracle[oc]))
    print("\nexamples (CWE131):")
    for oc in ("vulnerable", "safe"):
        for e in report["examples"][oc]:
            print(f"  [{oc[:4]}] {e['file']:54} width={e['width']} "
                  f"heap_size={e['heap_size']} stack_ec={e['stack_ec']} -> {e['route']} ({e['reason']})")
    print(f"report -> {outp}")


if __name__ == "__main__":
    main()
