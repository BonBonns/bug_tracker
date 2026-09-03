#!/usr/bin/env python3
"""Bucket the bounded npm pilot's outcomes into the required categories.

Buckets (per the pilot protocol):
  PREFILTER_SELECTED                          -- chosen by the pre-registered selection
  PIPELINE_ANALYZED                           -- compiled and analysed end to end
  INFRASTRUCTURE_FAILURE                      -- download/extract/compile/producer failure
  NO_PARSER_CANDIDATE                         -- analysed, no incomplete boundary rule
  ESCAPE_PARITY_PARSER_CANDIDATE              -- >=1 incomplete boundary rule
  DELAYED_STRUCTURED_TEXT_CONSUMER_REACHABLE  -- >=1 candidate with a proven chain
  ABSTAINED                                   -- >=1 abstention recorded

A package can appear in more than one outcome bucket (e.g. it can hold both a candidate
and an abstention); the counts below are therefore per-package presence counts, and the
site-level totals are reported separately.

PARSE COVERAGE. A package counts as PIPELINE_ANALYZED only when the JS frontend actually
parsed at least COVERAGE_THRESHOLD of its EXECUTABLE source files into the CPG. TypeScript
.d.ts declaration files carry no executable code and legitimately produce no CPG nodes,
so they are excluded from the denominator. Below the threshold the analyzer ran but too
little of the package reached it for a negative to carry meaning, so the package is
bucketed INFRASTRUCTURE_FAILURE rather than counted as a clean negative. The canonical
bucketed record for the pilot is study/PILOT_OUTCOMES.json, built with this rule.
"""
COVERAGE_THRESHOLD = 0.80
import json
import sys
from pathlib import Path

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
status = [json.loads(l) for l in (OUT / "pilot_status.jsonl").read_text().splitlines() if l.strip()]

buckets = {k: [] for k in ("PREFILTER_SELECTED", "PIPELINE_ANALYZED", "INFRASTRUCTURE_FAILURE",
                           "NO_PARSER_CANDIDATE", "ESCAPE_PARITY_PARSER_CANDIDATE",
                           "DELAYED_STRUCTURED_TEXT_CONSUMER_REACHABLE", "ABSTAINED")}
site_totals = {"records": 0, "ESCAPE_PARITY_PARSER_CANDIDATE": 0,
               "DELAYED_STRUCTURED_TEXT_CONSUMER_REACHABLE": 0, "NEGATIVE": 0, "ABSTAINED": 0}
per_package = []
candidates = []

for s in status:
    name = f"{s['package']}@{s['version']}"
    buckets["PREFILTER_SELECTED"].append(name)
    if s["status"] != "PIPELINE_ANALYZED":
        buckets["INFRASTRUCTURE_FAILURE"].append(f"{name} ({s.get('stage')}: {s.get('detail','')[:80]})")
        per_package.append({"package": name, "status": s["status"], "stage": s.get("stage")})
        continue
    buckets["PIPELINE_ANALYZED"].append(name)
    slug = s["package"].replace("/", "__").replace("@", "_")
    res = json.loads((OUT / f"{slug}.json").read_text())
    counts = {}
    for f in res["findings"]:
        counts[f["classification"]] = counts.get(f["classification"], 0) + 1
        site_totals["records"] += 1
        site_totals[f["classification"]] = site_totals.get(f["classification"], 0) + 1
        if f["classification"] in ("ESCAPE_PARITY_PARSER_CANDIDATE",
                                   "DELAYED_STRUCTURED_TEXT_CONSUMER_REACHABLE"):
            candidates.append({"package": name, **{k: f.get(k) for k in
                ("file", "method", "line", "site_kind", "site_node_id", "boundary_rule",
                 "pattern", "classification")},
                "chain_status": f["chain"]["status"],
                "chain_reasons": sorted(set(f["chain"]["reasons"])),
                "chain_abstention_reason": f.get("chain_abstention_reason", [])})
    if counts.get("ESCAPE_PARITY_PARSER_CANDIDATE"):
        buckets["ESCAPE_PARITY_PARSER_CANDIDATE"].append(name)
    if counts.get("DELAYED_STRUCTURED_TEXT_CONSUMER_REACHABLE"):
        buckets["DELAYED_STRUCTURED_TEXT_CONSUMER_REACHABLE"].append(name)
    if counts.get("ABSTAINED"):
        buckets["ABSTAINED"].append(name)
    if not counts.get("ESCAPE_PARITY_PARSER_CANDIDATE") and not counts.get(
            "DELAYED_STRUCTURED_TEXT_CONSUMER_REACHABLE"):
        buckets["NO_PARSER_CANDIDATE"].append(name)
    per_package.append({"package": name, "status": s["status"],
                        "n_records": len(res["findings"]), "classifications": counts,
                        "producer_line": s.get("producer_line", ""),
                        "n_source_files": s.get("n_source_files_extracted")})

summary = {"buckets": {k: {"count": len(v), "packages": v} for k, v in buckets.items()},
           "site_level_totals": site_totals,
           "per_package": per_package,
           "candidate_sites": candidates}
print(json.dumps(summary, indent=2))
