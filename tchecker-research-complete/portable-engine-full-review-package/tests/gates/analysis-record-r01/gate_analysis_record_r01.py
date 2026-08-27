#!/usr/bin/env python3
"""ANALYSIS-RECORD-R01 gate. Validates that TChecker's reason-emission layer
assigns HETEROGENEOUS candidate-review buckets from EXPLICIT machine-derived
reason codes -- not the tautological "candidate emitted -> relationship_unresolved".

Each function below is an independently-constructed example of one implemented
candidate-review bucket; the gate asserts the auto-assigned bucket + reason code
per function, requires >=3 examples for every implemented bucket, and checks each
record against the analysis_record schema (reason<->bucket<->route consistency).
It also corroborates on the independently-built oob-runtimecap-r01 fixture that
the same layer yields >=3 distinct candidate-review buckets there too."""
import sys, pathlib, importlib.util, collections
H = pathlib.Path(__file__).resolve().parent
TOOLS = H.parent.parent.parent / "tools"
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location("rc", TOOLS / "oob_runtime_capacity_verdict.py")
rc = importlib.util.module_from_spec(spec); spec.loader.exec_module(rc)
import analysis_record as ar

ok = tot = 0
def ck(name, cond):
    global ok, tot; tot += 1; ok += bool(cond); print(("PASS " if cond else "FAIL ") + name)

FIX = str(H / "fixtures" / "controls.program.json")
recs = rc.analyze_operations(FIX)
by_fn = {r["function"]: r for r in recs}

EXPECT = {
    "conflict_two_mallocs":   ("conflicting_definitions", "conflicting_allocations"),
    "conflict_malloc_calloc": ("conflicting_definitions", "conflicting_allocations"),
    "conflict_three_sizes":   ("conflicting_definitions", "conflicting_allocations"),
    "unknown_alloc_custom":   ("external_contract_unknown", "unknown_allocator"),
    "unknown_alloc_vendor":   ("external_contract_unknown", "unknown_allocator"),
    "unknown_alloc_pool":     ("external_contract_unknown", "unknown_allocator"),
    "sym_calloc_count":       ("insufficient_evidence", "multiplication_overflow_not_ruled_out"),
    "sym_calloc_width":       ("insufficient_evidence", "multiplication_overflow_not_ruled_out"),
    "sym_calloc_both":        ("insufficient_evidence", "multiplication_overflow_not_ruled_out"),
    "rel_symbolic_malloc":    ("relationship_unresolved", "capacity_relation_not_established"),
    "rel_literal_malloc":     ("relationship_unresolved", "capacity_relation_not_established"),
    "rel_port_alloc":         ("relationship_unresolved", "capacity_relation_not_established"),
}
for fn, (bucket, reason) in EXPECT.items():
    r = by_fn.get(fn)
    ck(f"{fn} -> {bucket} (reason {reason})",
       r is not None and r.get("uncertainty_bucket") == bucket and r.get("reason_code") == reason
       and r.get("analysis_status") in ("open_candidate", "abstained"))

for fn in ("det_exact_match", "det_literal_fits"):
    r = by_fn.get(fn)
    ck(f"{fn} -> deterministic_complete (no bucket, resolved safe)",
       r is not None and r.get("analysis_status") == "deterministic_complete"
       and r.get("uncertainty_bucket") is None)

# every record is schema-consistent (reason <-> bucket <-> route)
ck("all records pass analysis_record.validate_record",
   all(ar.validate_record(r) for r in recs))

# >=3 examples for every implemented candidate-review bucket
counts = collections.Counter(r["uncertainty_bucket"] for r in recs if r.get("uncertainty_bucket"))
IMPLEMENTED = ("relationship_unresolved", "external_contract_unknown",
               "conflicting_definitions", "insufficient_evidence")
for b in IMPLEMENTED:
    ck(f"bucket {b} has >=3 independently-constructed examples", counts.get(b, 0) >= 3)

# the reason-emission layer is NOT the tautological rule: >=4 distinct buckets here
distinct = set(counts)
ck("emits >=4 DISTINCT candidate-review buckets (not just relationship_unresolved)",
   len(distinct) >= 4)

# corroboration on the independently-built runtimecap fixture: >=3 distinct buckets
rc_fix = str(H.parent / "oob-runtimecap-r01" / "fixtures" / "controls.program.json")
rc_recs = rc.analyze_operations(rc_fix)
rc_buckets = {r["uncertainty_bucket"] for r in rc_recs if r.get("uncertainty_bucket")}
ck("runtimecap fixture also yields >=3 distinct candidate-review buckets",
   len(rc_buckets) >= 3)

print(f"ANALYSIS_RECORD_R01={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
