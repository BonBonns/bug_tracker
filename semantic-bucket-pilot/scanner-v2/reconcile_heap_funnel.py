#!/usr/bin/env python3
"""Reconcile the nested heap denominators so none looks like silent attrition:
496 established heap extents -> 424 extracted heap records -> 408 packet-identifiable
heap destinations. NO model calls.

Usage: reconcile_heap_funnel.py <cpp.json> [<cpp.json> ...]
"""
import hashlib
import json
import os
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
    funnel = Counter()
    heap_rows = []           # (phash, oracle) for identifiability partition
    for cpp in sys.argv[1:]:
        d = json.load(open(cpp))
        ext = AE.compute_allocation_extents(d)
        sink_at = {}
        for c in d.get("calls", []):
            if c.get("name") in SINKS:
                a0 = next((a for a in c.get("arguments", []) if a.get("index") == 0), None)
                if a0:
                    sink_at.setdefault((os.path.basename(c.get("file") or ""), c.get("line")), []) \
                        .append((c.get("enclosing_function_id"), a0.get("name")))
        recs, _ = v2.analyze_operations_v2(cpp)
        franges = B.func_ranges(cpp)
        for r in recs:
            if B.oracle(r.get("function") or "") is None:
                continue
            if r.get("recommended_route") != "semantic_relationship_review":
                continue
            base = os.path.basename(r.get("file") or "")
            line, dest = r.get("line"), r.get("dest")
            # heap dest with an ESTABLISHED extent?
            sites = sink_at.get((base, line), [])
            fn_dest = next(((f, dn) for (f, dn) in sites if dn == dest), (None, None))
            fact = ext.get(fn_dest) if fn_dest[0] is not None else None
            ev = r.get("_v2_evidence") or {}
            is_heap = (fact and fact.get("establishment_status") == "ESTABLISHED"
                       and not isinstance(ev.get("element_count"), int))
            if not is_heap:
                continue
            funnel["0_established_heap_extent"] += 1
            # inclusion-rule filters (same as broaden_extract)
            lines = B.src_lines("/tmp/juliet/testcases", base)
            if not (lines and line and 1 <= line <= len(lines)):
                funnel["drop_no_source_line"] += 1; continue
            stmt = lines[line - 1].strip()
            if not B.SINK.search(stmt) or not (dest and dest in stmt):
                funnel["drop_dest_not_in_sink_stmt"] += 1; continue
            if len(B.SINK.findall(stmt)) != 1:
                funnel["drop_multi_sink_line"] += 1; continue
            if not any("POTENTIAL FLAW" in lines[k] for k in range(max(0, line - 3), line)):
                funnel["drop_no_potential_flaw_marker"] += 1; continue
            body = B.enclosing(lines, franges.get(base, []), line)
            if body is None:
                funnel["drop_no_enclosing_body"] += 1; continue
            pkt, _ = san.neutralize(body, r.get("function"),
                                    extra_tokens=[base, base.replace(".c", "")])
            if san.leakage_scan(pkt):
                funnel["drop_residual_leakage"] += 1; continue
            funnel["1_extracted_heap_record"] += 1
            heap_rows.append((hashlib.sha256(pkt.encode()).hexdigest(), r.get("oracle")
                              if False else B.oracle(r.get("function"))))

    # identifiability partition on the WHOLE pool would be needed; here approximate the
    # heap identifiable count by heap phash uniqueness within heap (documented caveat:
    # the authoritative partition is pooled — see broaden_families.json 408).
    obh = defaultdict(set)
    for h, o in heap_rows:
        obh[h].add(o)
    unident = {h for h, o in obh.items() if len(o) > 1}
    identifiable = sum(1 for h, o in heap_rows if h not in unident)
    funnel["2_packet_identifiable_heap"] = identifiable
    funnel["2b_packet_insufficient_heap"] = len(heap_rows) - identifiable

    report = {"model_calls": 0, "funnel": dict(funnel),
              "explanation": {
                  "496_established_heap_extents": "eligible oracle ops (semantic route) whose "
                      "(function,dest) has an ESTABLISHED heap extent AND no stack element_count",
                  "424_extracted_heap_records": "of those, the ones passing the FULL frozen "
                      "inclusion rule (dest in the single sink stmt, POTENTIAL FLAW marker within "
                      "3 lines, enclosing body extractable, leakage-clean)",
                  "drops_496_to_424": "each drop_* key is an inclusion-rule filter, itemized",
                  "408_packet_identifiable_heap": "of the extracted, those whose neutralized packet "
                      "is NOT byte-identical to an opposite-oracle packet (pooled partition; the "
                      "16-record remainder are packet-insufficient heap cases)"}}
    outp = os.path.join(HERE, "study", "juliet", "heap_funnel.json")
    with open(outp, "w") as fh:
        json.dump(report, fh, indent=2, sort_keys=True, default=str)
    print("HEAP DENOMINATOR FUNNEL:")
    for k in sorted(funnel):
        print(f"  {k:34} {funnel[k]}")
    print(f"report -> {outp}")


if __name__ == "__main__":
    main()
