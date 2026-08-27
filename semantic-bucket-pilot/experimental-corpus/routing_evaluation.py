#!/usr/bin/env python3
"""Routing evaluation (PRIMARY empirical result).

Where does the frozen v1 scanner actually send real recognized operations? This
evaluates the recommended_route over the frozen corpus's distinct operations,
and — as a broader sample — over the whole-module expansion scans. It is the
separate routing experiment the plan called for, and (given the A/B/C
accuracy experiment cannot be powered, see EXPANSION_RESULTS.md) the primary
empirical characterization of the scanner's behavior.

Meta-route grouping (from the frozen taxonomy):
  DETERMINISTIC_COMPLETE     proven safe, no review needed
  LLM_SEMANTIC_REVIEW        semantic_relationship_review / semantic_contract_review
                             / range_arithmetic_review / path_feasibility_review
  ADDITIONAL_EVIDENCE_REQUIRED  the scanner lacks a fact; needs evidence, not review
  LIFETIME_ANALYSIS          rerouted to a dedicated lifetime layer
"""
import importlib.util
import json
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
FROZEN = os.path.join(HERE, "..", "frozen-corpus", "distinct_operations.jsonl")
TOOLS = os.path.abspath(os.path.join(
    HERE, "..", "..", "tchecker-research-complete",
    "portable-engine-full-review-package", "tools"))
sys.path.insert(0, TOOLS)

META = {
    None: "DETERMINISTIC_COMPLETE",
    "semantic_relationship_review": "LLM_SEMANTIC_REVIEW",
    "semantic_contract_review": "LLM_SEMANTIC_REVIEW",
    "range_arithmetic_review": "LLM_SEMANTIC_REVIEW",
    "path_feasibility_review": "LLM_SEMANTIC_REVIEW",
    "additional_evidence_required": "ADDITIONAL_EVIDENCE_REQUIRED",
    "lifetime_analysis": "LIFETIME_ANALYSIS",
}
REASON = ("oob_runtime_capacity_verdict", "oob_cursor_write_verdict",
          "oob_interprocedural_verdict")


def meta_of(rec):
    if rec.get("analysis_status") == "deterministic_complete":
        return "DETERMINISTIC_COMPLETE"
    return META.get(rec.get("recommended_route"), "OTHER:" + str(rec.get("recommended_route")))


def eval_frozen():
    recs = [json.loads(l) for l in open(FROZEN)]
    metac = Counter(meta_of(r) for r in recs)
    routec = Counter(r.get("recommended_route") for r in recs)
    return len(recs), metac, routec


def _load(m):
    s = importlib.util.spec_from_file_location(m, os.path.join(TOOLS, m + ".py"))
    mod = importlib.util.module_from_spec(s)
    s.loader.exec_module(mod)
    return mod


def eval_expansion():
    """Broader sample: run producers over every expansion scan, count meta-routes
    over ALL records (not just llm-eligible). Deduplicates per (side,file) is not
    attempted here — this is a coarse population view, reported as such."""
    mods = {n: _load(n) for n in REASON}
    metac = Counter()
    n = 0
    base = "/tmp/expansion"
    if not os.path.isdir(base):
        return 0, metac
    for fid in sorted(os.listdir(base)):
        for side in ("vuln", "patched"):
            p = os.path.join(base, fid, side, "cpp.json")
            if not os.path.exists(p):
                continue
            for name, mod in mods.items():
                try:
                    for r in mod.analyze_operations(p):
                        metac[meta_of(r)] += 1
                        n += 1
                except Exception:
                    pass
    return n, metac


def pct(c, tot):
    return f"{100*c/tot:.1f}%" if tot else "0%"


def main():
    fn, fmeta, froute = eval_frozen()
    result = {"frozen_corpus": {"n": fn, "by_meta_route": dict(fmeta),
                                "by_route": {str(k): v for k, v in froute.items()}}}
    print(f"=== Routing evaluation — FROZEN corpus ({fn} distinct operations) ===")
    for m, c in fmeta.most_common():
        print(f"  {m:30} {c:4}  {pct(c, fn)}")
    llm = fmeta.get("LLM_SEMANTIC_REVIEW", 0)
    print(f"  -> LLM semantic review share: {pct(llm, fn)}")

    if "--with-expansion" in sys.argv:
        en, emeta = eval_expansion()
        result["expansion_population"] = {"n": en, "by_meta_route": dict(emeta)}
        print(f"\n=== Broader sample — expansion whole-module scans "
              f"({en} records, coarse population) ===")
        for m, c in emeta.most_common():
            print(f"  {m:30} {c:5}  {pct(c, en)}")
        print(f"  -> LLM semantic review share: "
              f"{pct(emeta.get('LLM_SEMANTIC_REVIEW', 0), en)}")

    with open(os.path.join(HERE, "routing_evaluation_result.json"), "w") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)


if __name__ == "__main__":
    main()
