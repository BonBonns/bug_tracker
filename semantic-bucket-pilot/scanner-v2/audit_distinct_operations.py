#!/usr/bin/env python3
"""v2 evidence-expansion — STEP 2: dedup the broader population by the frozen
operation fingerprint and report DISTINCT operations by producer, reason code,
bucket, and route.

Reads ONLY frozen v1 producers and the expansion scans; writes nothing under any
v1 path. The 3,246 figure was RAW producer records (one per producer per op);
this counts distinct physical operations using the EXACT frozen fingerprint
(_source_label|file|function|line|dest), producer-independent, so a write seen
by two producers is one operation. When producers disagree on a fingerprint, the
canonical record is chosen evidence-monotone (most evidence established), mirroring
the frozen corpus builder — all producer verdicts retained for the audit.
"""
import hashlib
import importlib.util
import json
import os
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.abspath(os.path.join(
    HERE, "..", "..", "tchecker-research-complete",
    "portable-engine-full-review-package", "tools"))
sys.path.insert(0, TOOLS)
REASON = ("oob_runtime_capacity_verdict", "oob_cursor_write_verdict",
          "oob_interprocedural_verdict")
EXP = "/tmp/expansion"
EVIDENCE_RANK = {"deterministic_complete": 3, "open_candidate": 3,
                 "rerouted": 2, "abstained": 1}


def _load(m):
    s = importlib.util.spec_from_file_location(m, os.path.join(TOOLS, m + ".py"))
    mod = importlib.util.module_from_spec(s)
    s.loader.exec_module(mod)
    return mod


def _fingerprint(rec):
    key = "|".join(str(x) for x in (
        rec.get("_source_label"), rec.get("file"), rec.get("function"),
        rec.get("line"), rec.get("dest")))
    return "op_" + hashlib.sha256(key.encode()).hexdigest()[:16]


def collect():
    mods = {n: _load(n) for n in REASON}
    raw = []
    for fid in sorted(os.listdir(EXP)):
        for side in ("vuln", "patched"):
            p = os.path.join(EXP, fid, side, "cpp.json")
            if not os.path.exists(p):
                continue
            label = f"{fid}/{side}"
            for name, mod in mods.items():
                try:
                    recs = mod.analyze_operations(p)
                except Exception:
                    continue
                for r in recs:
                    r["_source_label"] = label
                    r["_producer"] = name
                    r["op_fingerprint"] = _fingerprint(r)
                    raw.append(r)
    return raw


def canonicalize(raw):
    groups = defaultdict(list)
    for r in raw:
        groups[r["op_fingerprint"]].append(r)
    distinct = []
    for g in groups.values():
        c = sorted(g, key=lambda r: (-EVIDENCE_RANK.get(r["analysis_status"], 0),
                                     REASON.index(r["_producer"])))[0]
        distinct.append(c)
    return distinct


def main():
    raw = collect()
    distinct = canonicalize(raw)
    route = lambda r: (None if r["analysis_status"] == "deterministic_complete"
                       else r.get("recommended_route"))
    # cache distinct canonical records so later inspection steps need not re-run
    # the (slow) producers.
    with open(os.path.join(HERE, "distinct_ops.jsonl"), "w") as fh:
        for r in distinct:
            fh.write(json.dumps(r, sort_keys=True, default=str) + "\n")
    rep = {
        "raw_records": len(raw),
        "distinct_operations": len(distinct),
        "by_producer": dict(Counter(r["_producer"].split("_")[1] for r in distinct)),
        "by_status": dict(Counter(r["analysis_status"] for r in distinct)),
        "by_reason": dict(Counter(str(r.get("primary_reason_code") or r.get("reason_code"))
                                  for r in distinct)),
        "by_bucket": dict(Counter(str(r.get("uncertainty_bucket")) for r in distinct)),
        "by_route": dict(Counter(str(route(r)) for r in distinct)),
        # additional-evidence-required operations broken down by exact reason
        "additional_evidence_by_reason": dict(Counter(
            str(r.get("primary_reason_code") or r.get("reason_code"))
            for r in distinct
            if route(r) == "additional_evidence_required")),
    }
    with open(os.path.join(HERE, "audit_distinct_operations.json"), "w") as fh:
        json.dump(rep, fh, indent=2, sort_keys=True)

    print(f"raw producer records : {rep['raw_records']}")
    print(f"DISTINCT operations   : {rep['distinct_operations']}")
    print(f"by producer  : {rep['by_producer']}")
    print(f"by status    : {rep['by_status']}")
    print(f"by bucket    : {rep['by_bucket']}")
    print(f"by route     : {rep['by_route']}")
    print(f"\nby reason code (distinct ops):")
    for k, v in sorted(rep["by_reason"].items(), key=lambda kv: -kv[1]):
        print(f"    {str(k):40} {v}")
    print(f"\nADDITIONAL_EVIDENCE_REQUIRED distinct ops by exact reason:")
    for k, v in sorted(rep["additional_evidence_by_reason"].items(), key=lambda kv: -kv[1]):
        print(f"    {str(k):40} {v}")


if __name__ == "__main__":
    main()
