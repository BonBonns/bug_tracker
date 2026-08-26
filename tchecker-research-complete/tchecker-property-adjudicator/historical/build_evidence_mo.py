#!/usr/bin/env python3
"""R-next: multi-origin / path-set preservation at the canonical evidence seam.

Fixes the information-loss bug (SourceFact MULTI[...] -> adapter -> single origin).
The evidence set now carries input_origins[] with PER-ORIGIN provenance, identity,
and transform path -- never merged into one generic path, never flattened to a
family list that discards node identity.

Semantic closure is per-alternative: a security question is SEMANTICALLY_CLOSED only
when the required property is resolved for EVERY established origin. Resolving one
branch must not silently clear another.
"""
import collections, json, sys
from pathlib import Path

RAW = Path(sys.argv[1] if len(sys.argv) > 1 else "mo-out/raw")


def rows(name, n):
    p = RAW / name
    return [ln.split("\t") for ln in p.read_text().splitlines() if ln.strip() and len(ln.split("\t")) == n] if p.exists() else []


# import identity (R23b): local -> module spec
imp = {r[3]: r[1] for r in rows("import_bindings.tsv", 6) if len(r) >= 4 and r[3]}
imp2 = {r[3]: r[1] for r in rows("import_bindings.tsv", 4) if len(r) >= 4 and r[3]}
imp.update(imp2)

# propagation: per (sink_node, source_node) -> ordered transforms
prop = collections.defaultdict(dict)
for r in rows("propagation_relations.tsv", 9):
    if r[2] != "ESTABLISHED":
        continue
    trs = []
    for seg in (r[6].split(" ; ") if r[6] else []):
        if not seg:
            continue
        _, node, callee = seg.split(":", 2)
        trs.append({"transform": callee, "call_node": node,
                    "identity": ("RESOLVED:" + imp[callee]) if callee in imp else "UNRESOLVED"})
    prop[(r[0], r[3])] = {"transforms": trs, "qualification": r[7], "provenance": r[8]}

# source facts: per sink_node -> list of origins
srcby = collections.defaultdict(list)
for r in rows("source_facts.tsv", 12):
    srcby[r[0]].append(r)


def build_multi_origin_evidence(sink_node, sink_line):
    origins = []
    for r in srcby.get(sink_node, []):
        if r[4] != "ESTABLISHED":
            continue
        src_node = r[2]
        path = prop.get((sink_node, src_node), {"transforms": [], "qualification": "ESTABLISHED_DATAFLOW(may)", "provenance": ""})
        origins.append({
            "origin_family": r[3],
            "source_node_id": src_node,          # stable identity, per origin
            "status": "ESTABLISHED",
            "established_by": r[5],               # STATIC_PROVENANCE
            "provenance": r[7],
            "qualification": path["qualification"],   # never MUST
            "path": path["transforms"],          # per-origin transform chain
        })
    # lexical-hint-only origins (recognized but not established) preserved separately
    hints = [{"lexical_hint_node": r[8], "established_by": "LEXICAL_HINT"}
             for r in srcby.get(sink_node, []) if r[4] == "UNKNOWN" and r[5] == "LEXICAL_HINT" and r[8]]
    cardinality = "MULTIPLE" if len(origins) > 1 else ("SINGLE" if origins else "NONE")
    return {
        "sink_node": sink_node, "sink_line": sink_line,
        "input_origins": origins,
        "origin_cardinality": cardinality,
        "lexical_hints": hints,
    }


if __name__ == "__main__":
    seen = set()
    for sink_node, rs in srcby.items():
        if sink_node in seen:
            continue
        seen.add(sink_node)
        ev = build_multi_origin_evidence(sink_node, rs[0][1])
        print(f"sink_node={sink_node} L{ev['sink_line']}  cardinality={ev['origin_cardinality']}")
        for o in ev["input_origins"]:
            chain = " -> ".join(t["transform"] + f"[{t['identity']}]" for t in o["path"]) or "(direct)"
            print(f"   origin {o['origin_family']:10s} node={o['source_node_id']:14s} "
                  f"by={o['established_by']:16s} path: {chain}")
        for h in ev["lexical_hints"]:
            print(f"   lexical-hint-only node={h['lexical_hint_node']} (NOT authoritative)")
