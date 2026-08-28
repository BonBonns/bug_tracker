#!/usr/bin/env python3
"""Level-3 heap-capacity check (NO model calls). element_count is the STACK-array
representation; heap capacity is bound by V1's compute_allocation_extents() as an
AllocationExtentFact (extent_in_bytes / size_expression / provenance direct_allocation).
For every eligible heap destination, query the internal extent directly and record its
establishment status + provenance, per producer, BEFORE any cross-producer dedup.

Usage: heap_extent_check.py <cpp.json> [<cpp.json> ...]
"""
import json
import os
import re
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.abspath(os.path.join(HERE, "..", "..", "tchecker-research-complete",
                                     "portable-engine-full-review-package", "tools"))
sys.path.insert(0, TOOLS)
sys.path.insert(0, HERE)
import allocation_extent as AE
import oob_runtime_capacity_v2 as v2
import build_juliet_corpus as B

SINKS = {"memcpy", "memmove", "strcpy", "strncpy", "wcscpy", "wcsncpy", "strcat", "wcscat"}


def main():
    tally = Counter()
    prov = Counter()
    examples = []
    for cpp in sys.argv[1:]:
        d = json.load(open(cpp))
        ext = AE.compute_allocation_extents(d)          # {(fn_id, ptr): fact}
        stack_ext = v2.compute_stack_fixed_array_extents(d)  # {(fn_id, decl_id): extent}
        # sink call index: (basename, line) -> (enclosing_fn_id, dest_arg0_name)
        sink_at = {}
        for c in d.get("calls", []):
            if c.get("name") in SINKS:
                a0 = next((a for a in c.get("arguments", []) if a.get("index") == 0), None)
                if a0:
                    sink_at[(os.path.basename(c.get("file") or ""), c.get("line"))] = \
                        (c.get("enclosing_function_id"), a0.get("name"))
        recs, _ = v2.analyze_operations_v2(cpp)
        for r in recs:
            if B.oracle(r.get("function") or "") is None:
                continue
            if r.get("recommended_route") != "semantic_relationship_review":
                continue
            base = os.path.basename(r.get("file") or "")
            fn_id, dest = sink_at.get((base, r.get("line")), (None, None))
            if fn_id is None or dest is None:
                tally["no_sink_call_resolved"] += 1
                continue
            fact = ext.get((fn_id, dest))
            ev = r.get("_v2_evidence") or {}
            has_stack_ec = isinstance(ev.get("element_count"), int)
            if fact is not None:
                st = fact.get("establishment_status")
                tally[f"heap_extent_{st}"] += 1
                prov[fact.get("provenance")] += 1
                if len(examples) < 8 and st == "ESTABLISHED":
                    examples.append({"file": base, "line": r.get("line"), "dest": dest,
                                     "extent_bytes": fact.get("extent_in_bytes"),
                                     "size_expr": fact.get("size_expression"),
                                     "provenance": fact.get("provenance"),
                                     "allocation_site": fact.get("allocation_site"),
                                     "packet_element_count": ev.get("element_count")})
            elif has_stack_ec:
                tally["stack_extent_bound"] += 1
            else:
                tally["no_extent_either_producer"] += 1

    report = {
        "model_calls": 0,
        "note": "heap capacity queried via V1 compute_allocation_extents (extent facts); "
                "element_count is only the stack-array field. Per-producer, pre-dedup.",
        "tally": dict(tally),
        "heap_extent_provenance": dict(prov),
        "established_heap_examples": examples,
    }
    outp = os.path.join(HERE, "study", "juliet", "heap_extent_check.json")
    with open(outp, "w") as fh:
        json.dump(report, fh, indent=2, sort_keys=True, default=str)
    print("LEVEL-3 HEAP-CAPACITY CHECK (per producer, pre-dedup):")
    for k, v in sorted(tally.items(), key=lambda kv: -kv[1]):
        print(f"  {k:32} {v}")
    print(f"heap-extent provenance: {dict(prov)}")
    for e in examples[:5]:
        print(f"  ESTABLISHED heap: {e['file'][:44]:46} dest={e['dest']} "
              f"extent={e['extent_bytes']}B expr={e['size_expr']!r} prov={e['provenance']} "
              f"(packet element_count={e['packet_element_count']})")
    print(f"report -> {outp}")


if __name__ == "__main__":
    main()
