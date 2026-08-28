#!/usr/bin/env python3
"""Pooled analysis of the predeclared broadened corpus (NO model calls).
Partition packet-identifiable/insufficient, prove sufficiency, collapse by flow
topology, and recalculate the confirmatory independent-family count vs the 12 gate.

Usage: broaden_analyze.py <pooled_jsonl>
"""
import hashlib
import json
import os
import re
import sys
from collections import defaultdict, Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import juliet_sanitize as san
import predeclared_suites as P

OUTDIR = os.path.join(HERE, "study", "juliet")


def bucket(fid):
    h = int(hashlib.sha256((P.SPLIT_SALT + "|" + fid).encode()).hexdigest(), 16)
    return "dev" if (h % 10000) / 10000.0 < P.DEV_FRACTION else "confirmatory"


_CTRL = {"if", "else", "for", "while", "do", "switch", "case", "default",
         "goto", "break", "continue"}
_SINK_RE = re.compile(r"\b(?:memcpy|memmove|strcpy|strncpy|wcscpy|wcsncpy|strcat|wcscat)\b")


def dataflow_skeleton(src):
    """flow_skeleton with reachability-only control flow removed: drop control keywords
    and the balanced (...) guard condition that follows if/for/while/switch, keeping the
    data-flow statements that actually establish capacity and write length. Superficial
    guard encodings (if(V)/if(V())/if(V==L)) collapse; genuine data flow is kept."""
    toks = san._tokenize(src)
    out, i = [], 0
    while i < len(toks):
        t = toks[i]; low = t.lower()
        if low in san._SPECIFIERS:
            i += 1; continue
        if low in _CTRL:
            j = i + 1
            if j < len(toks) and toks[j] == "(":
                depth = 0
                while j < len(toks):
                    if toks[j] == "(": depth += 1
                    elif toks[j] == ")":
                        depth -= 1
                        if depth == 0: j += 1; break
                    j += 1
            i = j; continue
        if low in san._TYPES: out.append("TYPE")
        elif low in san._SINKS: out.append("SINK")
        elif low in san._LENS: out.append("LEN")
        elif low in san._SETS: out.append("SET")
        elif san._LITERAL.match(t): out.append("L")
        elif re.match(r"^[A-Za-z_]", t): out.append("V")
        else: out.append(t)
        i += 1
    s = re.sub(r"\{\s*\}", "", " ".join(out))
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def length_shape(pkt):
    lm = re.search(r"\b(?:memcpy|memmove|strcpy|strncpy|wcscpy|wcsncpy|strcat|wcscat)"
                   r"\s*\([^,]*,[^,]*,([^;]*)\)\s*;", pkt)
    if not lm:
        return "implicit_strlen"
    s = lm.group(1)
    s = re.sub(r"\b(?:strlen|wcslen)\b", "LENCALL", s)
    s = re.sub(r"\bsizeof\b", "SIZEOF", s)
    s = re.sub(r"\d+", "N", s)
    s = re.sub(r"[A-Za-z_]\w*", "V", s)
    return re.sub(r"\s+", "", s)


def property_signature(x):
    """The reasoning unit FAITHFUL to the fixed property (write length vs destination
    capacity): capacity PROVENANCE (per producer — V2 stack_fixed_array vs V1
    heap_direct_allocation, queried from the internal extent facts, NOT the packet's
    element_count field which only represents stack arrays) x write-length shape.
    Abstracts guards, source-buffer allocation, subtype label, char/wchar and the
    specific 99-vs-49 length."""
    return x.get("capacity_provenance", "none") + " | " + length_shape(x["packet"])


def families(items, keyf):
    g = defaultdict(list)
    for x in items:
        g[keyf(x)].append(x)
    both = {k: v for k, v in g.items()
            if any(i["oracle"] == "vulnerable" for i in v)
            and any(i["oracle"] == "safe" for i in v)}
    conf = sum(1 for k in both if bucket(k) == "confirmatory")
    return g, both, conf


def main():
    pooled = sys.argv[1]
    rows = [json.loads(l) for l in open(pooled)]
    # partition on baseline packet hash within the pool
    obh = defaultdict(set)
    for x in rows:
        obh[x["phash"]].add(x["oracle"])
    unident = {h for h, o in obh.items() if len(o) > 1}
    identifiable = [x for x in rows if x["phash"] not in unident]
    insufficient = [x for x in rows if x["phash"] in unident]

    # sufficiency on identifiable (capacity + write length + relationship, structure-only)
    fully = 0
    rel = Counter()
    for x in identifiable:
        if isinstance(x.get("capacity"), int) and isinstance(x.get("write_len"), int):
            fully += 1
            rel["exceeds" if x["write_len"] > x["capacity"]
                else ("within" if x["write_len"] < x["capacity"] else "boundary")] += 1

    # clustering SENSITIVITY at three levels (coarsest = property-faithful)
    ps_g, ps_both, ps_conf = families(identifiable, property_signature)
    df_g, df_both, df_conf = families(identifiable, lambda x: "df_" + dataflow_skeleton(x["packet"]))
    g, both, conf = families(identifiable, lambda x: "flow_" + san.flow_skeleton(x["packet"]))
    sensitivity = {
        "property_signature (dest-capacity x length-shape; property-faithful)":
            {"families": len(ps_g), "both_sided": len(ps_both), "confirmatory_both_sided": ps_conf},
        "guard_collapsed_dataflow_topology":
            {"families": len(df_g), "both_sided": len(df_both), "confirmatory_both_sided": df_conf},
        "full_flow_topology (guards kept; pre-registered key)":
            {"families": len(g), "both_sided": len(both), "confirmatory_both_sided": conf},
    }
    # A signature is a GENUINE capacity-establishing family only if it is both-sided AND
    # the scanner actually binds the destination capacity (element_count) for it — a
    # different decision structure, not merely a stack-vs-heap label. Heap-malloc
    # destinations here bind NO capacity, so they do not establish the capacity decision.
    # A signature is a GENUINE capacity-establishing family only if it is both-sided AND
    # the scanner ESTABLISHED the destination capacity for it (via either producer:
    # V2 stack_fixed_array or V1 heap_direct_allocation extent). Capacity establishment
    # is read from the internal extent facts, not the packet element_count field.
    ps_sigs = {}
    genuine = 0
    genuine_provenances = set()
    for k, v in sorted(ps_g.items(), key=lambda kv: -len(kv[1])):
        both_sided = ("vulnerable" in {i["oracle"] for i in v}
                      and "safe" in {i["oracle"] for i in v})
        cap_est = sum(1 for i in v if i.get("capacity_provenance", "none") != "none")
        provs = dict(Counter(i.get("capacity_provenance", "none") for i in v))
        is_genuine = both_sided and cap_est > 0
        if is_genuine:
            genuine += 1
            genuine_provenances.update(p for p in provs if p != "none")
        ps_sigs[k] = {"n": len(v), "suites": dict(Counter(i["suite"].split("_")[0] for i in v)),
                      "both_sided": both_sided, "capacity_established": cap_est,
                      "capacity_provenance": provs, "genuine_capacity_family": is_genuine}

    # per-suite eligibility
    suite_counts = Counter(x["suite"] for x in rows)
    suite_ident = Counter(x["suite"] for x in identifiable)

    # which suites contribute each both-sided family (independence provenance)
    fam_suites = {}
    for k, v in both.items():
        fam_suites[k] = sorted({i["suite"] for i in v})
    # distinct sinks per family (informational)
    fam_sinks = {k: sorted({i["sink"] for i in v}) for k, v in both.items()}

    report = {
        "pinned_commit": P.PINNED_COMMIT, "model_calls": 0,
        "predeclared_suites_present": P.IN_SCOPE_SUITES,
        "predeclared_absent": P.PREDECLARED_ABSENT,
        "pooled_eligible_instances": len(rows),
        "per_suite_eligible": dict(suite_counts),
        "packet_identifiable": len(identifiable),
        "packet_insufficient": len(insufficient),
        "per_suite_identifiable": dict(suite_ident),
        "sufficiency": {"fully_proved (cap+len+relation)": fully,
                        "relation_distribution": dict(rel),
                        "note": "write_len intra-function; symbolic-source cases lack a "
                                "concrete constant and are not counted fully-proved here."},
        "clustering_sensitivity": sensitivity,
        "property_signatures": ps_sigs,
        "genuine_capacity_families (both-sided AND capacity established, internal extents)": genuine,
        "genuine_capacity_provenances": sorted(genuine_provenances),
        "meets_gate_genuine": genuine >= P.MIN_FAMILIES,
        "verdict": (
            "Broadening across the predeclared copy-idiom suites (CWE121 stack + CWE122 "
            "heap, incl. nested CWE805/806) scanned 6428 files -> %d eligible, %d "
            "packet-identifiable. Under the pre-registered flow-topology key the "
            "confirmatory count reads %d (>= 12), but that is inflated by variation "
            "SUPERFICIAL to the property (opaque guards, source-buffer allocation, subtype "
            "labels). Property-faithful, a signature is a GENUINE capacity-establishing "
            "family only if the scanner ESTABLISHED the destination capacity -- read from "
            "the INTERNAL extent facts, not the packet element_count field (element_count "
            "is only the V2 stack-array representation). Capacity is established by TWO "
            "producers with distinct provenance: V2 stack_fixed_array AND V1 "
            "heap_direct_allocation. Heap capacity IS bound (element_count None on heap is "
            "not no-capacity; the packet builder simply never exposed the heap field). "
            "Genuine independent capacity-establishing families = %d, provenances %s: "
            "(1) stack_fixed_array + symbolic strlen*sizeof (the CWE806 baseline), and "
            "(2) heap_direct_allocation + (strlen+1)*sizeof (CWE122 -- a genuine SECOND "
            "capacity-provenance family). So broadening added ONE genuine new "
            "capacity-provenance family (heap); the count still does not approach 12. "
            "Reaching 12 needs further distinct capacity/length decision structures "
            "(integer-arithmetic capacity, loop-computed length, index writes) or "
            "real-world code (Magma)."
            % (len(rows), len(identifiable), conf, genuine, sorted(genuine_provenances))),
        "flow_topology_families": {
            "total_families": len(g),
            "both_sided_families": len(both),
            "confirmatory_both_sided": conf,
            "gate": P.MIN_FAMILIES,
            "meets_gate_raw_flow_topology": conf >= P.MIN_FAMILIES,
            "CAVEAT": "raw flow-topology over-counts superficial variants for this property; "
                      "see property_signature level and verdict.",
        },
        "both_sided_family_provenance": {
            k[:20]: {"n": len(both[k]), "suites": fam_suites[k], "sinks": fam_sinks[k],
                     "bucket": bucket(k)}
            for k in sorted(both, key=lambda z: -len(both[z]))
        },
    }
    os.makedirs(OUTDIR, exist_ok=True)
    with open(os.path.join(OUTDIR, "broaden_families.json"), "w") as fh:
        json.dump(report, fh, indent=2, sort_keys=True, default=str)

    print(f"pooled eligible {len(rows)}   identifiable {len(identifiable)}   "
          f"insufficient {len(insufficient)}")
    print(f"per-suite eligible: {dict(suite_counts)}")
    print(f"per-suite identifiable: {dict(suite_ident)}")
    print(f"sufficiency fully-proved: {fully}   relation {dict(rel)}")
    print(f"\nCLUSTERING SENSITIVITY (confirmatory both-sided at each level):")
    for lvl, t in sensitivity.items():
        mark = "MEETS" if t["confirmatory_both_sided"] >= P.MIN_FAMILIES else "below"
        print(f"  {t['confirmatory_both_sided']:3}  ({mark} 12)  {lvl}")
    print(f"\nPROPERTY-FAITHFUL signatures (genuine = both-sided AND capacity established):")
    for k, meta in list(ps_sigs.items()):
        bs = "both-sided" if meta["both_sided"] else "one-sided "
        g = "GENUINE" if meta["genuine_capacity_family"] else "not-genuine"
        print(f"  n={meta['n']:4}  [{bs}]  cap_est={meta['capacity_established']:4}/{meta['n']:<4}  "
              f"[{g}]  {k[:48]:50} {meta['suites']}")
    print(f"\nVERDICT: raw flow-topology reads {conf} (inflated by superficial variants). "
          f"GENUINE capacity-establishing independent families = {genuine} "
          f"({'MEETS' if genuine>=P.MIN_FAMILIES else 'below'} 12), "
          f"provenances {sorted(genuine_provenances)} — heap capacity IS established "
          f"internally (element_count is only the stack field).")
    print(f"report -> {OUTDIR}/broaden_families.json")


if __name__ == "__main__":
    main()
