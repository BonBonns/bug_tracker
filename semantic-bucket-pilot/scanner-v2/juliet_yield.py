#!/usr/bin/env python3
"""Yield study over a scanned Juliet buffer-overflow batch: run frozen V2, match each
highlighted write to a labeled flaw with a known oracle outcome, apply the strict
inclusion rule, and count exact-matched vulnerable/safe pairs. NO model calls.

Usage: juliet_yield.py <scan_out_dir_with_cpp.json> <juliet_src_dir>
"""
import importlib.util
import json
import os
import re
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.abspath(os.path.join(HERE, "..", "..", "tchecker-research-complete",
                                     "portable-engine-full-review-package", "tools"))
sys.path.insert(0, TOOLS)
sys.path.insert(0, HERE)
import oob_runtime_capacity_v2 as v2

SINK = re.compile(r"\b(memcpy|memmove|strcpy|strncpy|wcscpy|wcsncpy|strcat|memset)\s*\(")
_SRC = {}


def src_lines(src_dir, relfile):
    # cpp.json 'file' is often a basename or partial path; resolve within src_dir
    base = os.path.basename(relfile)
    if base not in _SRC:
        for dp, _, fs in os.walk(src_dir):
            if base in fs:
                _SRC[base] = open(os.path.join(dp, base), errors="replace").read().splitlines()
                break
        else:
            _SRC[base] = None
    return _SRC[base]


def oracle(function):
    f = function.lower()
    if "bad" in f and "good" not in f:
        return "vulnerable"
    if "good" in f:               # goodG2B / goodB2G / _good
        return "safe"
    return None


def main():
    out_dir, src_dir = sys.argv[1], sys.argv[2]
    recs, _ = v2.analyze_operations_v2(os.path.join(out_dir, "cpp.json"))

    rows = []
    for r in recs:
        fn = r.get("function") or ""
        oc = oracle(fn)
        if oc is None:
            continue
        rel, line, dest = r.get("file"), r.get("line"), r.get("dest")
        lines = src_lines(src_dir, rel or "")
        stmt = lines[line - 1].strip() if (lines and line and 1 <= line <= len(lines)) else ""
        # inclusion checks
        is_sink = bool(SINK.search(stmt)) and (dest and dest in stmt)
        # POTENTIAL FLAW marker within 2 lines above
        flaw = bool(lines and any("POTENTIAL FLAW" in lines[k]
                    for k in range(max(0, line - 3), min(len(lines), line)))) if lines else False
        cap_bound = r.get("recommended_route") in (
            "semantic_relationship_review", "range_arithmetic_review") or \
            r.get("analysis_status") == "deterministic_complete"
        rows.append({"file": os.path.basename(rel or ""), "function": fn, "line": line,
                     "dest": dest, "stmt": stmt, "oracle": oc,
                     "exact_sink": is_sink, "flaw_marked": flaw,
                     "capacity_bound": cap_bound,
                     "route": r.get("recommended_route"),
                     "included": is_sink and flaw and cap_bound})

    inc = [r for r in rows if r["included"]]
    # pair vulnerable + safe within the same source file
    by_file = defaultdict(lambda: {"vulnerable": 0, "safe": 0})
    for r in inc:
        by_file[r["file"]][r["oracle"]] += 1
    pairs = sum(min(v["vulnerable"], v["safe"]) for v in by_file.values())
    n_vuln = sum(1 for r in inc if r["oracle"] == "vulnerable")
    n_safe = sum(1 for r in inc if r["oracle"] == "safe")

    report = {
        "scanned_operations_with_oracle": len(rows),
        "included_after_inclusion_rule": len(inc),
        "included_vulnerable": n_vuln, "included_safe": n_safe,
        "matched_vulnerable_safe_pairs": pairs,
        "files_with_both_sides": sum(1 for v in by_file.values() if v["vulnerable"] and v["safe"]),
        "route_distribution": {k: sum(1 for r in inc if r["route"] == k)
                               for k in {r["route"] for r in inc}},
        "rows": rows,
    }
    with open(os.path.join(out_dir, "juliet_yield.json"), "w") as fh:
        json.dump(report, fh, indent=2, sort_keys=True, default=str)

    print(f"operations with an oracle : {len(rows)}")
    print(f"included (exact sink + flaw marker + capacity bound): {len(inc)}")
    print(f"  vulnerable {n_vuln} | safe {n_safe}")
    print(f"MATCHED vulnerable/safe PAIRS: {pairs}   (files with both sides: {report['files_with_both_sides']})")
    print(f"route distribution (included): {report['route_distribution']}")
    for r in inc[:6]:
        print(f"    [{r['oracle'][:4]}] {r['file'][:46]:48} L{r['line']} {r['dest']}  {r['stmt'][:44]}")


if __name__ == "__main__":
    main()
