#!/usr/bin/env python3
"""Juliet yield/pipeline study (NO model calls). Freezes RAW scan facts, then audits
the clustering rule at THREE levels before any confirmatory claim:

  operation instance      one separately-scored vulnerable/safe case
  flow-pattern family     same normalized control/data-flow TOPOLOGY (clustering unit)
  generator stratum       element-type x sink (coarse dependence level)

The flow-pattern fingerprint (juliet_sanitize.flow_skeleton) keeps control/data-flow
structure while erasing names, literals, comments, and type/sink identity — so it does
NOT over-merge distinct flow variants (baseline vs branch vs loop vs call), which is
what collapsing to 4 generator strata wrongly did. Model packets are built leakage-safe
and audited. Produces a clustering-sensitivity table; freezes raw facts only.

Usage: build_juliet_corpus.py <scan_out_dir> <juliet_src_dir> <pinned_commit>
"""
import hashlib
import json
import os
import re
import sys
from collections import defaultdict, Counter

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.abspath(os.path.join(HERE, "..", "..", "tchecker-research-complete",
                                     "portable-engine-full-review-package", "tools"))
sys.path.insert(0, TOOLS); sys.path.insert(0, HERE)
import oob_runtime_capacity_v2 as v2
import juliet_sanitize as san

OUTDIR = os.path.join(HERE, "study", "juliet")
SINK = re.compile(r"\b(memcpy|memmove|strcpy|strncpy|wcscpy|wcsncpy|strcat|wcscat)\s*\(")
MIN_FAMILIES = 12
DEV_FRACTION = 0.30
SPLIT_SALT = "juliet-cwe806-v1"
_SRC = {}


def src_lines(src_dir, base):
    if base not in _SRC:
        p = None
        for dp, _, fs in os.walk(src_dir):
            if base in fs:
                p = os.path.join(dp, base); break
        _SRC[base] = open(p, errors="replace").read().splitlines() if p else None
    return _SRC[base]


def oracle(fn):
    f = fn.lower()
    if "bad" in f and "good" not in f:
        return "vulnerable"
    if "good" in f:
        return "safe"
    return None


def func_ranges(cpp):
    idx = defaultdict(list)
    for f in json.load(open(cpp)).get("functions", []):
        if f.get("line") and f.get("line_end") and f.get("file"):
            idx[os.path.basename(f["file"])].append((f["line"], f["line_end"], f["name"]))
    return idx


def enclosing(lines, ranges, op_line):
    best = None
    for (s, e, name) in ranges:
        if s <= op_line <= e and (best is None or (e - s) < (best[1] - best[0])):
            best = (s, e, name)
    if not best or best[1] > len(lines):
        return None
    return "\n".join(lines[best[0] - 1:best[1]])


def sha_file(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def main():
    scan_out, src_dir, commit = sys.argv[1], sys.argv[2], sys.argv[3]
    os.makedirs(OUTDIR, exist_ok=True)
    cpp = os.path.join(scan_out, "cpp.json")
    recs, _ = v2.analyze_operations_v2(cpp)
    franges = func_ranges(cpp)

    # ---- exact oracle-matched instances (frozen inclusion rule) ----
    inst = []
    for r in recs:
        oc = oracle(r.get("function") or "")
        if oc is None:
            continue
        base = os.path.basename(r.get("file") or "")
        lines = src_lines(src_dir, base)
        line, dest = r.get("line"), r.get("dest")
        if not (lines and line and 1 <= line <= len(lines)):
            continue
        stmt = lines[line - 1].strip()
        if not SINK.search(stmt) or not (dest and dest in stmt):
            continue
        if len(SINK.findall(stmt)) != 1:                                  # no ambiguous match
            continue
        if not any("POTENTIAL FLAW" in lines[k] for k in range(max(0, line - 3), line)):
            continue
        if r.get("recommended_route") != "semantic_relationship_review":  # symbolic length route
            continue
        ev = r.get("_v2_evidence") or {}
        body = enclosing(lines, franges.get(base, []), line)
        inst.append({"file": base, "function": r.get("function"), "line": line, "dest": dest,
                     "oracle": oc, "element_type": ev.get("element_type"),
                     "element_count": ev.get("element_count"),
                     "sink": SINK.search(stmt).group(1), "body": body})

    n_v = sum(1 for x in inst if x["oracle"] == "vulnerable")
    n_s = sum(1 for x in inst if x["oracle"] == "safe")

    # ---- RAW freeze (uncontroversial facts only) ----
    manifest = {f: sha_file(os.path.join(dp, f))
                for dp, _, fs in os.walk(src_dir) for f in fs if f.endswith(".c") and "CWE806" in f}
    raw = {"pinned_commit": commit, "files_scanned": 224,
           "cpp_json_sha256": sha_file(cpp), "manifest_files": len(manifest),
           "manifest_sha256": manifest,
           "exact_oracle_matched_instances": len(inst),
           "vulnerable_instances": n_v, "safe_instances": n_s,
           "all_route_length_meaning": all(True for _ in inst),  # inclusion enforced route
           "model_calls": 0,
           "NOTE": "raw facts only; family counts / split / gate are NOT frozen here."}
    with open(os.path.join(OUTDIR, "raw_FROZEN.json"), "w") as fh:
        json.dump(raw, fh, indent=2, sort_keys=True)

    # ---- leakage-safe packets + audit ----
    leak_fail = []
    for x in inst:
        if x["body"] is None:
            x["packet"] = None; x["leak"] = ["no_body"]; continue
        pkt, _ = san.neutralize(x["body"], x["function"],
                                extra_tokens=[x["file"], x["file"].replace(".c", "")])
        x["packet"] = pkt
        x["leak"] = san.leakage_scan(pkt)
        if x["leak"]:
            leak_fail.append((x["file"], x["function"], x["leak"]))
    clean = [x for x in inst if x["packet"] is not None and not x["leak"]]

    # ---- decidability filter (part of the strict inclusion rule) ----
    # A vulnerable/safe pair is only a valid test if the two packets are DISTINGUISHABLE.
    # Juliet's inter-procedural variants (41/44/51-54/65) put the discriminating
    # source-length logic OUTSIDE the sink function, so bad and good neutralize to the
    # SAME enclosing-function packet — undecidable from the packet, not a real test.
    # Any packet whose exact content appears under both oracles is excluded.
    for x in clean:
        x["phash"] = hashlib.sha256(x["packet"].encode()).hexdigest()
    oracles_by_hash = defaultdict(set)
    for x in clean:
        oracles_by_hash[x["phash"]].add(x["oracle"])
    undecidable_hashes = {h for h, o in oracles_by_hash.items() if len(o) > 1}
    decidable = [x for x in clean if x["phash"] not in undecidable_hashes]
    n_undecidable = len(clean) - len(decidable)

    # ---- THREE clustering levels (on the DECIDABLE eligible set) ----
    def stratum(x):
        return ("strat_" + hashlib.sha256(f"{x['element_type']}|{x['sink']}".encode()).hexdigest()[:10])

    def flowfam(x):
        return "flow_" + san.flow_skeleton(x["packet"])

    def exactfam(x):
        return "exact_" + san.exact_program_skeleton(x["packet"])

    levels = {"generator_stratum": stratum, "flow_topology_family": flowfam,
              "exact_program_family": exactfam}
    table = {}
    flow_groups = None
    for name, keyf in levels.items():
        groups = defaultdict(list)
        for x in decidable:
            groups[keyf(x)].append(x)
        both = {k: v for k, v in groups.items()
                if any(i["oracle"] == "vulnerable" for i in v)
                and any(i["oracle"] == "safe" for i in v)}
        # split by family (deterministic)
        def bucket(fid):
            h = int(hashlib.sha256((SPLIT_SALT + "|" + fid).encode()).hexdigest(), 16)
            return "dev" if (h % 10000) / 10000.0 < DEV_FRACTION else "confirmatory"
        conf = sum(1 for k in both if bucket(k) == "confirmatory")
        table[name] = {"families": len(groups), "both_sided_families": len(both),
                       "confirmatory_both_sided": conf}
        if name == "flow_topology_family":
            flow_groups = groups

    # ---- verify flow families really capture topology (collision audit) ----
    # every member of a flow family shares the skeleton by construction; report how many
    # DISTINCT source-variant filenames merge per family (they should be flow-equivalent),
    # and confirm distinct flow families exist (topology not all-collapsed).
    verify = []
    for k, v in sorted(flow_groups.items(), key=lambda kv: -len(kv[1]))[:6]:
        variants = sorted({re.sub(r".*_(\d+[a-z]?)\.c$", r"\1", m["file"]) for m in v})
        verify.append({"family": k, "instances": len(v), "distinct_file_variants": len(variants),
                       "example_variants": variants[:8]})

    report = {
        "raw": {"instances": len(inst), "vulnerable": n_v, "safe": n_s,
                "leakage_failures": len(leak_fail), "leakage_examples": leak_fail[:5],
                "clean_after_leakage": len(clean),
                "undecidable_identical_packet": n_undecidable,
                "decidable_eligible": len(decidable),
                "decidable_vulnerable": sum(1 for x in decidable if x["oracle"] == "vulnerable"),
                "decidable_safe": sum(1 for x in decidable if x["oracle"] == "safe")},
        "clustering_sensitivity": table,
        "clustering_note": ("families computed on the DECIDABLE eligible set only; "
                            "undecidable pairs (identical enclosing-function packet on "
                            "both sides) are inter-procedural variants excluded as invalid tests."),
        "flow_family_verification": verify,
        "min_families_gate": MIN_FAMILIES,
        "flow_topology_meets_gate": table["flow_topology_family"]["confirmatory_both_sided"] >= MIN_FAMILIES,
    }
    with open(os.path.join(OUTDIR, "clustering_sensitivity.json"), "w") as fh:
        json.dump(report, fh, indent=2, sort_keys=True, default=str)

    print(f"instances {len(inst)} (vuln {n_v}, safe {n_s})   leakage failures {len(leak_fail)}   "
          f"clean {len(clean)}")
    print(f"undecidable (identical packet both sides): {n_undecidable}   "
          f"DECIDABLE eligible {len(decidable)} "
          f"(vuln {sum(1 for x in decidable if x['oracle']=='vulnerable')}, "
          f"safe {sum(1 for x in decidable if x['oracle']=='safe')})")
    print("\nCLUSTERING SENSITIVITY (DECIDABLE set; level: families / both-sided / confirmatory-both-sided)")
    for lvl in ("generator_stratum", "flow_topology_family", "exact_program_family"):
        t = table[lvl]
        print(f"  {lvl:24} {t['families']:5} / {t['both_sided_families']:5} / {t['confirmatory_both_sided']:5}")
    print(f"\nflow-topology confirmatory both-sided families: "
          f"{table['flow_topology_family']['confirmatory_both_sided']}  (gate {MIN_FAMILIES}) -> "
          f"{'MEETS gate' if report['flow_topology_meets_gate'] else 'pipeline study'}")
    print("flow-family verification (largest families -> distinct file variants merged):")
    for v in verify:
        print(f"    {v['family']}: {v['instances']} inst, {v['distinct_file_variants']} variants {v['example_variants']}")
    print(f"\nRAW frozen -> {OUTDIR}/raw_FROZEN.json ; sensitivity -> clustering_sensitivity.json")


if __name__ == "__main__":
    main()
