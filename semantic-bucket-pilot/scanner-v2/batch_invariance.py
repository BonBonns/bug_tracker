#!/usr/bin/env python3
"""Batch-invariance control (NO model calls). Prove that batching does not change the
scanner's per-operation results — in particular that combining a batch with its
neighbor (1000 files, with Juliet's reused helper names / conflicting definitions and
possibly split cross-file chains) yields byte-identical results for the
packet-identifiable population.

Compares every oracle-bearing operation's (candidate status, reason codes, route,
capacity, write-length/width, element type, dest, unresolved property, uncertainty)
keyed by (file, function, line), between the SEPARATE per-batch scans and a COMBINED
rescan. Requires identical for the eligible (packet-identifiable-candidate) ops.

Usage: batch_invariance.py <sep_cpp_1> <sep_cpp_2> ... -- <combined_cpp> <src_dir>
"""
import json
import os
import re
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import build_juliet_corpus as B
import oob_runtime_capacity_v2 as v2

FIELDS = ("recommended_route", "analysis_status", "primary_reason_code",
          "all_reason_codes", "width_expr", "element_count", "element_type",
          "dest", "unresolved_property", "uncertainty_bucket")

# c2cpg appends a "<duplicate>N" suffix to functions whose name recurs across files
# (Juliet reuses goodG2B/bad/badSink/printLine everywhere); N depends on how many prior
# definitions the CPG holds, so it differs between a 500-file batch and a 1000-file
# combined scan. It is cosmetic — it changes no decision and is stripped by
# neutralization — so the invariance key is (file, line), stable under it. The oracle
# (bad/good) is preserved because the base name survives the suffix.
_DUP = re.compile(r"\d*<duplicate>\d+$")


def dump(cpp):
    """key (basename, line, dest, site_ordinal) -> (comparison tuple, is_eligible, oracle).
    A bare (file, line) is NOT assumed unique — multiple sink calls can share a line — so
    the key adds the highlighted destination and a per-(file,line,dest) site ordinal, and
    we ASSERT no key is silently overwritten."""
    recs, _ = v2.analyze_operations_v2(cpp)
    out = {}
    seen_ord = defaultdict(int)
    for r in recs:
        fn = r.get("function") or ""
        orc = B.oracle(fn)
        if orc is None:
            continue
        base = os.path.basename(r.get("file") or "")
        ev = r.get("_v2_evidence") or {}
        arc = r.get("all_reason_codes")
        arc = tuple(sorted(arc)) if isinstance(arc, list) else arc
        tup = (r.get("recommended_route"), r.get("analysis_status"),
               r.get("primary_reason_code"), arc, r.get("width_expr"),
               ev.get("element_count"), ev.get("element_type"), r.get("dest"),
               r.get("unresolved_property"), r.get("uncertainty_bucket"))
        elig = r.get("recommended_route") == "semantic_relationship_review"
        stem = (base, r.get("line"), r.get("dest"))
        key = stem + (seen_ord[stem],)
        seen_ord[stem] += 1
        assert key not in out, f"duplicate operation key {key} — key not unique"
        out[key] = (tup, elig, orc)
    return out


def main():
    argv = sys.argv[1:]
    sep_cpps = argv[:argv.index("--")]
    combined_cpp = argv[argv.index("--") + 1]

    sep = {}
    for c in sep_cpps:
        sep.update(dump(c))
    comb = dump(combined_cpp)

    common = sorted(set(sep) & set(comb))
    only_sep = set(sep) - set(comb)
    only_comb = set(comb) - set(sep)

    diffs, elig_diffs = [], []
    elig_common = 0
    oracle_mismatch = 0
    for k in common:
        (ts, es, orcs), (tc, ec, orcc) = sep[k], comb[k]
        if orcs != orcc:
            oracle_mismatch += 1
        if es or ec:
            elig_common += 1
        if ts != tc:
            rec = {"key": list(k),
                   "fields_changed": [FIELDS[i] for i in range(len(FIELDS)) if ts[i] != tc[i]],
                   "separate": {FIELDS[i]: ts[i] for i in range(len(FIELDS)) if ts[i] != tc[i]},
                   "combined": {FIELDS[i]: tc[i] for i in range(len(FIELDS)) if ts[i] != tc[i]}}
            diffs.append(rec)
            if es or ec:
                elig_diffs.append(rec)

    report = {
        "model_calls": 0,
        "control": "separate 500-file batches (batch5, batch6) vs combined 1000-file rescan",
        "key": "(file, line, dest, site_ordinal) — asserted unique; stable under c2cpg "
               "<duplicate>N helper-name suffixes (which change only the function name)",
        "separate_ops": len(sep), "combined_ops": len(comb),
        "common_ops_compared": len(common),
        "eligible_ops_compared": elig_common,
        "ops_only_in_separate": len(only_sep),
        "ops_only_in_combined": len(only_comb),
        "oracle_mismatches": oracle_mismatch,
        "total_diffs": len(diffs),
        "eligible_diffs": len(elig_diffs),
        "PASS_all_identical": (len(diffs) == 0 and len(only_sep) == 0
                               and len(only_comb) == 0 and oracle_mismatch == 0),
        "PASS_eligible_identical": (len(elig_diffs) == 0 and len(only_sep) == 0
                                    and len(only_comb) == 0 and oracle_mismatch == 0),
        "note": "compared fields: candidate status, reason codes, route, capacity "
                "(element_count), write-length (width_expr), element type, dest, "
                "unresolved property, uncertainty. The <duplicate>N function-name suffix "
                "is cosmetic (different N in a bigger CPG); it changes no compared field, "
                "preserves the bad/good oracle, and is erased by neutralization, so it "
                "cannot affect the flow-family analysis.",
        "diff_examples": diffs[:8],
        "eligible_diff_examples": elig_diffs[:8],
    }
    outp = os.path.join(HERE, "study", "juliet", "batch_invariance.json")
    with open(outp, "w") as fh:
        json.dump(report, fh, indent=2, sort_keys=True, default=str)

    print(f"separate ops {len(sep)}  combined ops {len(comb)}  common {len(common)}")
    print(f"only-in-separate {len(only_sep)}  only-in-combined {len(only_comb)}  "
          f"oracle mismatches {oracle_mismatch}")
    print(f"eligible ops compared {elig_common}")
    print(f"total diffs {len(diffs)}   eligible diffs {len(elig_diffs)}")
    print(f"PASS all ops byte-identical: {report['PASS_all_identical']}")
    print(f"PASS eligible (packet-identifiable) byte-identical: {report['PASS_eligible_identical']}")
    for d in diffs[:6]:
        print(f"  DIFF {d['key']} changed {d['fields_changed']}")
    print(f"report -> {outp}")


if __name__ == "__main__":
    main()
