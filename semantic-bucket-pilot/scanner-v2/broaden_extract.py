#!/usr/bin/env python3
"""Extract eligible instances from one scanned batch and append to a pooled JSONL.
Applies the FROZEN inclusion rule (see PREREGISTER_BROADENING.md), builds the
leakage-safe baseline packet, and records capacity + write-length + relationship
(structure-only) for the sufficiency proof. NO model calls.

Usage: broaden_extract.py <scan_out_dir> <src_dir> <pooled_jsonl>
"""
import hashlib
import json
import os
import re
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import build_juliet_corpus as B
import juliet_sanitize as san
import juliet_packet_expansion as E
import oob_runtime_capacity_v2 as v2


def intra_source_length(calls_in, fid, src_var):
    """Concrete write length set on src_var WITHIN function fid (memset/wmemset fill, or
    a string-literal assignment length). Returns int or None. Structure-only."""
    for c in calls_in.get(fid, []):
        if c.get("name") in san._SETS:
            a0 = next((a for a in c.get("arguments", []) if a.get("index") == 0), None)
            a2 = next((a for a in c.get("arguments", []) if a.get("index") == 2), None)
            if a0 and a0.get("name") == src_var and a2:
                L = E._safe_int_expr(a2.get("code"))
                if L is not None:
                    return L
    return None


def main():
    scan_out, src_dir, pooled = sys.argv[1], sys.argv[2], sys.argv[3]
    cpp = os.path.join(scan_out, "cpp.json")
    recs, _ = v2.analyze_operations_v2(cpp)
    franges = B.func_ranges(cpp)
    fns_by_id, callers_of, calls_in = E.build_indexes(cpp)

    out = []
    for r in recs:
        oc = B.oracle(r.get("function") or "")
        if oc is None:
            continue
        base = os.path.basename(r.get("file") or "")
        lines = B.src_lines(src_dir, base)
        line, dest = r.get("line"), r.get("dest")
        if not (lines and line and 1 <= line <= len(lines)):
            continue
        stmt = lines[line - 1].strip()
        if not B.SINK.search(stmt) or not (dest and dest in stmt):
            continue
        if len(B.SINK.findall(stmt)) != 1:
            continue
        if not any("POTENTIAL FLAW" in lines[k] for k in range(max(0, line - 3), line)):
            continue
        if r.get("recommended_route") != "semantic_relationship_review":
            continue
        body = B.enclosing(lines, franges.get(base, []), line)
        if body is None:
            continue
        pkt, _ = san.neutralize(body, r.get("function"),
                                extra_tokens=[base, base.replace(".c", "")])
        if san.leakage_scan(pkt):
            continue
        # locate enclosing function id
        fid = None
        for f in fns_by_id.values():
            if os.path.basename(f.get("file") or "") == base and f.get("line") \
                    and f.get("line_end") and f["line"] <= line <= f["line_end"] \
                    and f.get("name") == r.get("function"):
                fid = f["id"]; break
        ev = r.get("_v2_evidence") or {}
        cap = ev.get("element_count")
        cap = cap if isinstance(cap, int) else None
        # intra-function write length (packet-identifiable cases have it in-packet)
        wl = None
        if fid is not None:
            sv, _ = E.sink_source_operand(calls_in, fid, line)
            if sv:
                wl = intra_source_length(calls_in, fid, sv)
        suite = base.split("__")[0] if "__" in base else base.split("_")[0]
        out.append({"file": base, "suite": suite, "oracle": oc, "line": line,
                    "sink": B.SINK.search(stmt).group(1),
                    "element_type": ev.get("element_type"), "capacity": cap,
                    "write_len": wl, "packet": pkt,
                    "phash": hashlib.sha256(pkt.encode()).hexdigest()})

    with open(pooled, "a") as fh:
        for rec in out:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
    print(f"  extracted {len(out)} eligible instances -> {pooled}")


if __name__ == "__main__":
    main()
