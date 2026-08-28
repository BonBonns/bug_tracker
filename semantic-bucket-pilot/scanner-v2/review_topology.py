#!/usr/bin/env python3
"""Expose heap capacity in the packet, validate it against source, and cluster the
packet-identifiable cases by their PROOF OBLIGATION (the actual question a reviewer must
discharge), kept separate from scanner evidence-provenance. Symbolic sizeof(T) is
preserved -- no ABI byte size is assumed. NO model calls.

Reports two DIFFERENT counts:
  capacity_provenance_families  -- scanner evidence provenance (stack decl vs heap malloc)
  independent_review_topologies -- distinct proof obligations (e.g. "strlen(src) fits a
                                   known element capacity" vs "N*sizeof(T) bytes fit a
                                   malloc(M)-byte buffer" -- a byte/element unit mismatch)

Usage: review_topology.py <instances_prov.jsonl>
"""
import json
import os
import re
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import juliet_packet_expansion as E   # _safe_int_expr

_SINK = re.compile(r"\b(memcpy|memmove|strcpy|strncpy|wcscpy|wcsncpy|strcat|wcscat)\s*\(")
_SIZEOF = re.compile(r"sizeof\s*\(\s*([A-Za-z_]\w*)\s*\)")


def parse_terms(expr):
    """Structure of a length/capacity expression, sizeof(T) preserved symbolically."""
    if expr is None:
        return None
    e = expr.strip()
    mz = _SIZEOF.search(e)
    sizeof_type = mz.group(1) if mz else None
    has_strlen = bool(re.search(r"\b(?:strlen|wcslen)\b", e))
    plus_off = bool(re.search(r"\+\s*\d+", e)) or bool(re.search(r"\d+\s*\+", e))
    # coefficient: strip the sizeof factor, eval the remaining constant if any
    coeff = None
    if not has_strlen:
        core = _SIZEOF.sub("1", e)
        coeff = E._safe_int_expr(core)
    return {"has_strlen": has_strlen, "plus_offset": plus_off,
            "sizeof_type": sizeof_type, "coeff": coeff, "raw": e}


def sink_length_expr(pkt):
    m = _SINK.search(pkt)
    if not m:
        return None
    name = m.group(1)
    # 3-arg copy sinks: explicit length is arg2; strcpy/strcat: implicit strlen(source)
    lm = re.search(r"\b(?:memcpy|memmove|strncpy|wcsncpy)\s*\([^,]*,[^,]*,([^;]*)\)\s*;", pkt)
    if lm:
        return lm.group(1).strip()
    return "IMPLICIT_strlen"


def capacity_expr(x):
    """Expose the capacity fact for BOTH producers, symbolic sizeof preserved."""
    if x.get("capacity_provenance") == "stack_fixed_array" and isinstance(x.get("capacity"), int):
        t = x.get("element_type") or "char"
        return {"provenance": "stack_fixed_array",
                "size_expression": f"{x['capacity']}*sizeof({t})",
                "element_count": x["capacity"], "element_width": f"sizeof({t})"}
    if x.get("capacity_provenance") == "heap_direct_allocation" and x.get("heap_size_expr"):
        se = x["heap_size_expr"]
        pt = parse_terms(se)
        return {"provenance": "heap_direct_allocation", "size_expression": se,
                "element_count": pt["coeff"],
                "element_width": (f"sizeof({pt['sizeof_type']})" if pt["sizeof_type"] else "1(byte)")}
    return None


def obligation(x):
    """The proof obligation: normalized (write shape, capacity shape, unit relation),
    abstracting integer values and names but KEEPING strlen-vs-const, +offset, and the
    sizeof(T) unit relation (elements vs bytes vs unit-mismatch)."""
    w = parse_terms(sink_length_expr(x["packet"]) or "")
    cap = capacity_expr(x)
    if w is None or cap is None:
        return None
    cp = parse_terms(cap["size_expression"])
    w_shape = ("STRLEN" if w["has_strlen"] else "CONST") + ("+OFF" if w["plus_offset"] else "")
    c_shape = "CAP_elems" if cp["sizeof_type"] else "CAP_bytes"
    # unit relation between write and capacity (do NOT assume a byte size for sizeof)
    if w["sizeof_type"] and cp["sizeof_type"]:
        unit = "same_sizeof" if w["sizeof_type"] == cp["sizeof_type"] else "diff_sizeof"
    elif w["sizeof_type"] and not cp["sizeof_type"]:
        unit = "write_sizeof_vs_cap_bytes"     # CWE131-style byte/element MISMATCH
    elif not w["sizeof_type"] and cp["sizeof_type"]:
        unit = "write_bytes_vs_cap_sizeof"
    else:
        unit = "no_sizeof"
    return f"{w_shape} vs {c_shape} [{unit}]"


def main():
    rows = [json.loads(l) for l in open(sys.argv[1])]
    obh = defaultdict(set)
    for x in rows:
        obh[x["phash"]].add(x["oracle"])
    un = {h for h, o in obh.items() if len(o) > 1}
    ident = [x for x in rows if x["phash"] not in un]

    # attach + validate capacity fact; re-run sufficiency with capacity PRESENT
    validated = 0
    fact_missing = 0
    unvalidated_class = Counter()
    suff = Counter()
    topo = defaultdict(lambda: Counter())
    prov_families = set()
    for x in ident:
        cap = capacity_expr(x)
        if cap is None:
            fact_missing += 1
            continue
        prov_families.add(cap["provenance"])
        # validate the capacity fact against the source in the packet (independent parse)
        ok = False
        if cap["provenance"] == "heap_direct_allocation":
            msrc = re.search(rf"{re.escape(x['dest'])}\s*=\s*\(?[^;]*\bmalloc\s*\(\s*([^;]*?)\s*\)\s*;",
                             x["packet"])
            ok = bool(msrc and msrc.group(1).replace(" ", "") == cap["size_expression"].replace(" ", ""))
        else:
            ok = bool(re.search(rf"\b{re.escape(x['dest'])}\s*\[\s*{cap['element_count']}\s*\]", x["packet"]))
        if ok:
            validated += 1
        else:
            # classify the miss: allocation/declaration NOT in the sink packet because the
            # capacity was established interprocedurally (propagated from a caller) -> an
            # EXPECTED EXCLUSION from packet-local validation, not an invalid/unresolved fact.
            has_alloc = bool(re.search(r"\b(malloc|calloc|realloc|alloca|ALLOCA)\b", x["packet"]))
            if not has_alloc:
                unvalidated_class["expected_exclusion_out_of_packet_propagated"] += 1
            else:
                unvalidated_class["unresolved_in_packet_mismatch"] += 1
        ob = obligation(x)
        if ob:
            topo[ob][x["oracle"]] += 1
        # sufficiency with capacity present: capacity element_count known + write length
        cap_n = cap["element_count"]
        wl = x.get("write_len")
        if isinstance(cap_n, int) and isinstance(wl, int):
            suff["provable"] += 1
        else:
            suff["symbolic_capacity_or_length"] += 1

    both_topos = {k: v for k, v in topo.items() if v["vulnerable"] and v["safe"]}
    # coarser granularity: treat the +offset (null-terminator off-by-one) as the SAME
    # reasoning -- "does a strlen-derived length fit a known capacity" -- to expose
    # whether the two both-sided topologies are really one core question.
    coarse = defaultdict(lambda: Counter())
    for k, v in topo.items():
        ck = k.replace("STRLEN+OFF", "STRLEN")
        for o, n in v.items():
            coarse[ck][o] += n
    both_coarse = {k: v for k, v in coarse.items() if v["vulnerable"] and v["safe"]}

    report = {
        "model_calls": 0,
        "capacity_provenance_families": len(prov_families),
        "capacity_provenances": sorted(prov_families),
        "independent_review_topologies": len(both_topos),
        "independent_review_topologies_offset_abstracted": len(both_coarse),
        "review_topologies_offset_abstracted_both_sided": {k: dict(v) for k, v in both_coarse.items()},
        "review_topologies_all": {k: dict(v) for k, v in
                                  sorted(topo.items(), key=lambda kv: -sum(kv[1].values()))},
        "review_topologies_both_sided": {k: dict(v) for k, v in both_topos.items()},
        "capacity_fact_validated_against_source": validated,
        "capacity_fact_missing": fact_missing,
        "capacity_unvalidated_classification": dict(unvalidated_class),
        "sufficiency_with_capacity_present": dict(suff),
        "note": "sizeof(T) preserved symbolically; unit relation (same_sizeof / "
                "write_sizeof_vs_cap_bytes) distinguishes 'strlen fits capacity' from "
                "CWE131 byte/element unit-mismatch obligations. Two counts are reported "
                "separately: scanner provenance vs reviewer proof obligation.",
    }
    outp = os.path.join(HERE, "study", "juliet", "review_topology.json")
    with open(outp, "w") as fh:
        json.dump(report, fh, indent=2, sort_keys=True, default=str)

    print(f"identifiable {len(ident)}   capacity fact validated/against-source {validated}"
          f"   fact missing {fact_missing}")
    print(f"\ncapacity_provenance_families      = {len(prov_families)}  {sorted(prov_families)}")
    print(f"independent_review_topologies     = {len(both_topos)} (both-sided; keeps +offset)")
    print(f"  offset-abstracted (off-by-one same reasoning) = {len(both_coarse)}: "
          f"{[k for k in both_coarse]}")
    print("\nreview topologies (proof obligation -> oracle counts):")
    for k, v in sorted(topo.items(), key=lambda kv: -sum(kv[1].values())):
        bs = "both" if (v["vulnerable"] and v["safe"]) else "one "
        print(f"  [{bs}] {k:44} {dict(v)}")
    print(f"\nsufficiency with capacity present: {dict(suff)}")
    print(f"report -> {outp}")


if __name__ == "__main__":
    main()
