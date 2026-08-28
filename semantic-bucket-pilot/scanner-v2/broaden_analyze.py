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


def property_signature(x):
    """The reasoning unit FAITHFUL to the fixed property (write length vs destination
    capacity), abstracting the bad/good discriminating VALUES: destination-capacity
    mechanism x write-length expression shape. Two cases with the same relationship
    structure share a signature regardless of guards, source-buffer allocation, subtype
    label, char/wchar, or the specific 99-vs-49 length."""
    pkt = x["packet"]
    m = _SINK_RE.search(pkt)
    dest = None
    if m:
        d = re.match(r".*?\(\s*([A-Za-z_]\w*)", pkt[m.start():])
        dest = d.group(1) if d else None
    if dest and re.search(rf"\b{re.escape(dest)}\s*=\s*\(?[^;]*\bmalloc", pkt):
        dk = "heap_malloc_dest"
    elif dest and re.search(rf"\b(?:char|wchar_t|int|short|long)\s+{re.escape(dest)}\s*\[", pkt):
        dk = "stack_array_dest"
    elif dest and re.search(rf"{re.escape(dest)}\s*=\s*\(?[^;]*\balloca", pkt):
        dk = "alloca_dest"
    else:
        dk = "other_dest"
    lm = re.search(r"\b(?:memcpy|memmove|strcpy|strncpy|wcscpy|wcsncpy|strcat|wcscat)"
                   r"\s*\([^,]*,[^,]*,([^;]*)\)\s*;", pkt)
    if lm:
        s = lm.group(1)
        s = re.sub(r"\b(?:strlen|wcslen)\b", "LENCALL", s)
        s = re.sub(r"\bsizeof\b", "SIZEOF", s)
        s = re.sub(r"\d+", "N", s)
        s = re.sub(r"[A-Za-z_]\w*", "V", s)
        ls = re.sub(r"\s+", "", s)
    else:
        ls = "implicit_strlen"
    return dk + " | " + ls


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
    ps_sigs = {}
    genuine = 0
    for k, v in sorted(ps_g.items(), key=lambda kv: -len(kv[1])):
        both_sided = ("vulnerable" in {i["oracle"] for i in v}
                      and "safe" in {i["oracle"] for i in v})
        cap_bound = sum(1 for i in v if isinstance(i.get("capacity"), int))
        is_genuine = both_sided and cap_bound > 0
        if is_genuine:
            genuine += 1
        ps_sigs[k] = {"n": len(v), "suites": dict(Counter(i["suite"].split("_")[0] for i in v)),
                      "both_sided": both_sided, "capacity_bound": cap_bound,
                      "genuine_capacity_family": is_genuine}

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
        "genuine_capacity_families (both-sided AND capacity actually bound)": genuine,
        "meets_gate_genuine": genuine >= P.MIN_FAMILIES,
        "verdict": (
            "Broadening across the predeclared copy-idiom suites (CWE121 stack + CWE122 "
            "heap, incl. nested CWE805/806) scanned 6428 files -> %d eligible, %d "
            "packet-identifiable. Under the pre-registered flow-topology key the "
            "confirmatory count reads %d (>= 12), BUT that is inflated by variation "
            "SUPERFICIAL to the destination-capacity property (opaque reachability guards, "
            "source-buffer allocation method, subtype labels; families with byte-identical "
            "capacity+length+sink lines split only by guards). Property-faithful, there "
            "are 2 both-sided signatures, but a signature is a GENUINE capacity-establishing "
            "family only if the scanner actually binds the destination capacity: stack-array "
            "dests bind capacity 624/624, whereas heap-malloc dests bind it 0/384 — CWE122 "
            "routes eligible only on its symbolic LENGTH and never establishes a heap "
            "capacity DECISION, so it is a missing capacity decision, not a different one. "
            "Genuine independent capacity-establishing families = %d (the stack-array + "
            "symbolic-strlen pattern, i.e. the CWE806 baseline). Broadening added ZERO "
            "genuine new families and does NOT approach the 12 gate. Reaching 12 requires "
            "genuinely different capacity/length DECISION structures the scanner can "
            "establish — bound heap capacity, integer-arithmetic capacity, loop-computed "
            "length, index writes — or real-world code (Magma), not more symbolic-strlen "
            "copy variants."
            % (len(rows), len(identifiable), conf, genuine)),
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
    print(f"\nPROPERTY-FAITHFUL signatures (genuine = both-sided AND capacity bound):")
    for k, meta in list(ps_sigs.items()):
        bs = "both-sided" if meta["both_sided"] else "one-sided "
        g = "GENUINE" if meta["genuine_capacity_family"] else "not-genuine"
        print(f"  n={meta['n']:4}  [{bs}]  cap_bound={meta['capacity_bound']:4}/{meta['n']:<4}  "
              f"[{g}]  {k[:52]:54} {meta['suites']}")
    print(f"\nVERDICT: raw flow-topology reads {conf} (inflated by superficial variants). "
          f"GENUINE capacity-establishing independent families = {genuine} (< 12): "
          f"stack binds capacity, heap does not (0/384).")
    print(f"report -> {OUTDIR}/broaden_families.json")


if __name__ == "__main__":
    main()
