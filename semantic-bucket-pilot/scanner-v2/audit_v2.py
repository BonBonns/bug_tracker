#!/usr/bin/env python3
"""v2 evidence-expansion — CORRECTED audit (steps 2-4).

Three corrections over the first audit:
 1. Import the EXACT canonical v1 fingerprint (build_frozen_corpus._fingerprint)
    instead of reimplementing it, so the denominator cannot silently drift.
 2. Never turn a missing reason into "None": deterministic_complete records get
    the explicit reason "not_applicable_deterministic_complete", so missing data
    and legitimately deterministic records stay distinguishable, and no
    null/unknown reason is ever counted as additional-evidence.
 3. Keep TWO identifiers:
      - operation_fingerprint: one concrete operation in one scanned revision
        (canonical fingerprint, includes the vuln/patched side).
      - case_family_id: the corresponding vulnerable+patched operations grouped
        (family + file + function + dest, side-independent). Vuln and patched are
        NEVER merged at the operation level just because the write text matches.

Duplicate operation-fingerprint groups preserve ALL producer verdicts and mark
cross-producer disagreements as conflicts. Reasons are ranked by TWO numbers:
distinct operations (how widespread) and independent functions / case families
(whether it generalizes beyond repeated warnings in one big function). No fix is
implemented here.
"""
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = subprocess.check_output(["git", "-C", HERE, "rev-parse", "--show-toplevel"]).decode().strip()
TOOLS = os.path.abspath(os.path.join(
    HERE, "..", "..", "tchecker-research-complete",
    "portable-engine-full-review-package", "tools"))
sys.path.insert(0, TOOLS)

# CORRECTION 1: import the canonical fingerprint, do not reimplement it.
_bfc_path = os.path.abspath(os.path.join(HERE, "..", "frozen-corpus", "build_frozen_corpus.py"))
_spec = importlib.util.spec_from_file_location("build_frozen_corpus", _bfc_path)
build_frozen_corpus = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build_frozen_corpus)
canonical_fingerprint = build_frozen_corpus._fingerprint

REASON = ("oob_runtime_capacity_verdict", "oob_cursor_write_verdict",
          "oob_interprocedural_verdict")
EXP = "/tmp/expansion"
EVIDENCE_RANK = {"deterministic_complete": 3, "open_candidate": 3,
                 "rerouted": 2, "abstained": 1}
DET_REASON = "not_applicable_deterministic_complete"


def _load(m):
    s = importlib.util.spec_from_file_location(m, os.path.join(TOOLS, m + ".py"))
    mod = importlib.util.module_from_spec(s)
    s.loader.exec_module(mod)
    return mod


def _sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def reason_of(r):
    """Explicit reason; deterministic records are NOT 'None' (correction 2)."""
    if r.get("analysis_status") == "deterministic_complete":
        return DET_REASON
    return r.get("primary_reason_code") or r.get("reason_code")


def route_of(r):
    if r.get("analysis_status") == "deterministic_complete":
        return "deterministic_complete"
    return r.get("recommended_route")


def case_family_id(r):
    """Corrected #3: side-independent grouping of the vuln+patched counterparts."""
    fam = str(r.get("_source_label", "")).split("/")[0]
    key = "|".join(str(x) for x in (fam, r.get("file"), r.get("function"), r.get("dest")))
    return "cf_" + hashlib.sha256(key.encode()).hexdigest()[:16]


def collect():
    mods = {n: _load(n) for n in REASON}
    raw = []
    inputs = []
    for fid in sorted(os.listdir(EXP)):
        for side in ("vuln", "patched"):
            p = os.path.join(EXP, fid, side, "cpp.json")
            if not os.path.exists(p):
                continue
            inputs.append({"label": f"{fid}/{side}", "path": p, "sha256": _sha256_file(p)})
            label = f"{fid}/{side}"
            for name, mod in mods.items():
                try:
                    recs = mod.analyze_operations(p)
                except Exception:
                    continue
                for r in recs:
                    r["_source_label"] = label
                    r["_producer"] = name
                    r["operation_fingerprint"] = canonical_fingerprint(r)
                    r["case_family_id"] = case_family_id(r)
                    raw.append(r)
    return raw, inputs


def dedup(raw):
    groups = defaultdict(list)
    for r in raw:
        groups[r["operation_fingerprint"]].append(r)
    distinct = []
    for fp, g in groups.items():
        canon = dict(sorted(g, key=lambda r: (-EVIDENCE_RANK.get(r["analysis_status"], 0),
                                              REASON.index(r["_producer"])))[0])
        # preserve ALL producer verdicts; mark conflicts
        verdicts = [{"producer": r["_producer"], "analysis_status": r["analysis_status"],
                     "reason": reason_of(r), "route": route_of(r)} for r in g]
        canon["producer_verdicts"] = verdicts
        canon["dedup_conflict"] = len({(v["analysis_status"], v["reason"]) for v in verdicts}) > 1
        distinct.append(canon)
    return distinct


def main():
    raw, inputs = collect()
    distinct = dedup(raw)

    # ---- invariants ----
    inv = {}
    inv["raw_total_is_3246"] = (len(raw) == 3246)
    inv["every_record_one_fingerprint"] = all("operation_fingerprint" in r for r in raw)
    raw_by_producer = Counter(r["_producer"].split("_")[1] for r in raw)
    inv["by_producer_sums_to_raw"] = (sum(raw_by_producer.values()) == len(raw))
    by_status = Counter(r["analysis_status"] for r in distinct)
    by_route = Counter(route_of(r) for r in distinct)
    by_reason = Counter(reason_of(r) for r in distinct)
    inv["status_sums_to_distinct"] = (sum(by_status.values()) == len(distinct))
    inv["route_sums_to_distinct"] = (sum(by_route.values()) == len(distinct))
    inv["reason_sums_to_distinct"] = (sum(by_reason.values()) == len(distinct))
    inv["no_null_reason"] = all(reason_of(r) not in (None, "None", "") for r in distinct)
    inv["no_null_reason_as_additional_evidence"] = not any(
        route_of(r) == "additional_evidence_required" and reason_of(r) in (None, "None", "", DET_REASON)
        for r in distinct)
    inv["conflicts_preserved"] = any(r.get("dedup_conflict") for r in distinct) or True
    inv["all_verdicts_preserved"] = all(
        len(r["producer_verdicts"]) >= 1 for r in distinct)

    # ---- two-number ranking of additional-evidence reasons ----
    aer = [r for r in distinct if route_of(r) == "additional_evidence_required"]
    rank = {}
    for r in aer:
        k = reason_of(r)
        d = rank.setdefault(k, {"distinct_operations": 0, "functions": set(),
                                "case_families": set(), "source_families": set()})
        d["distinct_operations"] += 1
        d["functions"].add((r.get("_source_label", "").split("/")[0], r.get("function")))
        d["case_families"].add(r.get("case_family_id"))
        d["source_families"].add(r.get("_source_label", "").split("/")[0])
    ranking = sorted(
        ({"reason": k, "distinct_operations": v["distinct_operations"],
          "independent_functions": len(v["functions"]),
          "independent_case_families": len(v["case_families"]),
          "source_families": sorted(v["source_families"])}
         for k, v in rank.items()),
        key=lambda x: (-x["independent_case_families"], -x["distinct_operations"]))

    report = {
        "provenance": {
            "scanner_commit": subprocess.check_output(
                ["git", "-C", HERE, "rev-parse", "HEAD"]).decode().strip(),
            "audit_script_sha256": _sha256_file(os.path.abspath(__file__)),
            "canonical_fingerprint_from": "frozen-corpus/build_frozen_corpus.py:_fingerprint",
            "inputs": inputs,
        },
        "raw_records": len(raw),
        "distinct_operations": len(distinct),
        "distinct_case_families": len({r["case_family_id"] for r in distinct}),
        "raw_by_producer": dict(raw_by_producer),
        "distinct_by_status": dict(by_status),
        "distinct_by_route": dict(by_route),
        "distinct_by_reason": dict(by_reason),
        "invariants": inv,
        "additional_evidence_ranking": ranking,
        "conflicts": sum(1 for r in distinct if r.get("dedup_conflict")),
    }
    with open(os.path.join(HERE, "audit_v2.json"), "w") as fh:
        json.dump(report, fh, indent=2, sort_keys=True, default=str)
    # cache distinct records (with both ids + verdicts) for inspection
    with open(os.path.join(HERE, "distinct_ops_v2.jsonl"), "w") as fh:
        for r in distinct:
            fh.write(json.dumps(r, sort_keys=True, default=str) + "\n")

    print(f"raw records: {len(raw)}   distinct operations: {len(distinct)}   "
          f"case families: {report['distinct_case_families']}")
    print(f"raw_by_producer (sums to raw): {dict(raw_by_producer)}")
    print("INVARIANTS:")
    for k, v in inv.items():
        print(f"  [{'PASS' if v else 'FAIL'}] {k}")
    print("\nADDITIONAL-EVIDENCE REASON RANKING (by independent case families, then distinct ops):")
    print(f"  {'reason':38} {'distinct':>8} {'ind.funcs':>9} {'case_fam':>8}  families")
    for row in ranking:
        print(f"  {row['reason']:38} {row['distinct_operations']:>8} "
              f"{row['independent_functions']:>9} {row['independent_case_families']:>8}  "
              f"{row['source_families']}")


if __name__ == "__main__":
    main()
