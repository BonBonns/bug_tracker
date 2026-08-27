#!/usr/bin/env python3
"""ANALYSIS-RECORD-R01 gate. Validates TChecker's reason-emission layer against
the FROZEN decision table in analysis_record.py: recognized operations receive
an explicit machine-derived reason_code, the router translates reason -> bucket
(never candidate presence), the earliest-failed-prerequisite precedence picks the
primary reason among several, and the free/lifetime cases split correctly.

Covers the four IMPLEMENTED candidate-review buckets with >=3 independently-
constructed examples each, plus the deterministic lifetime finding and the two
free-path outcomes (via the independent runtimecap-cfg fixture). identity_ambiguous
is intentionally NOT tested: no instrumented producer detects it yet, and examples
must not be manufactured to populate a category."""
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

# (reason_code, bucket) expected per function
EXPECT = {
    "rel_symbolic_malloc": ("capacity_relation_not_established", "relationship_unresolved"),
    "rel_literal_malloc":  ("capacity_relation_not_established", "relationship_unresolved"),
    "rel_port_alloc":      ("capacity_relation_not_established", "relationship_unresolved"),
    "overflow_calloc_count": ("allocation_overflow_relation_unresolved", "relationship_unresolved"),
    "overflow_calloc_width": ("allocation_overflow_relation_unresolved", "relationship_unresolved"),
    "overflow_calloc_both":  ("allocation_overflow_relation_unresolved", "relationship_unresolved"),
    "unknown_alloc_custom": ("unknown_allocator_contract", "external_contract_unknown"),
    "unknown_alloc_vendor": ("unknown_allocator_contract", "external_contract_unknown"),
    "unknown_alloc_pool":   ("unknown_allocator_contract", "external_contract_unknown"),
    "conflict_two_mallocs":   ("conflicting_reaching_allocations", "conflicting_definitions"),
    "conflict_malloc_calloc": ("conflicting_reaching_allocations", "conflicting_definitions"),
    "conflict_three_sizes":   ("conflicting_reaching_allocations", "conflicting_definitions"),
    "no_alloc_param":  ("required_evidence_absent", "insufficient_evidence"),
    "no_alloc_global": ("required_evidence_absent", "insufficient_evidence"),
    "no_alloc_extern": ("required_evidence_absent", "insufficient_evidence"),
}
for fn, (reason, bucket) in EXPECT.items():
    r = by_fn.get(fn)
    ck(f"{fn} -> {reason} / {bucket}",
       r is not None and r.get("reason_code") == reason and r.get("uncertainty_bucket") == bucket
       and r.get("recommended_route") == ar.route_for_reason(reason))

for fn in ("det_exact_match", "det_literal_fits"):
    r = by_fn.get(fn)
    ck(f"{fn} -> deterministic_complete (proven safe, no bucket)",
       r is not None and r.get("analysis_status") == "deterministic_complete"
       and r.get("uncertainty_bucket") is None)

# PRECEDENCE: conflict + overflow both detected; primary is the earliest failed
# prerequisite (conflicting), never iteration order.
p = by_fn.get("precedence_conflict_over_overflow")
ck("precedence: conflict beats overflow as primary reason",
   p is not None and p.get("reason_code") == "conflicting_reaching_allocations")
ck("precedence: all_reason_codes records BOTH detected reasons",
   p is not None and set(p.get("all_reason_codes", [])) ==
   {"conflicting_reaching_allocations", "allocation_overflow_relation_unresolved"})

# relationship_unresolved is reached by TWO distinct reason codes (not one label)
rel_reasons = {r["reason_code"] for r in recs if r.get("uncertainty_bucket") == "relationship_unresolved"}
ck("relationship_unresolved spans >=2 distinct reason codes",
   {"capacity_relation_not_established", "allocation_overflow_relation_unresolved"} <= rel_reasons)

# ROUTE BY REASON: two reasons in the SAME bucket get DIFFERENT focused routes.
ck("same bucket, different routes: capacity relation -> semantic_relationship_review",
   ar.route_for_reason("capacity_relation_not_established") == "semantic_relationship_review")
ck("same bucket, different routes: allocation overflow -> range_arithmetic_review",
   ar.route_for_reason("allocation_overflow_relation_unresolved") == "range_arithmetic_review")
ck("free may reach -> path_feasibility_review",
   ar.route_for_reason("free_may_reach_sink") == "path_feasibility_review")
ck("external contract -> distinct semantic_contract_review (NOT generic llm), llm_eligible",
   ar.route_for_reason("unknown_allocator_contract") == "semantic_contract_review"
   and ar.llm_eligible_for_reason("unknown_allocator_contract"))
ck("abstain reasons are not llm_eligible",
   not ar.llm_eligible_for_reason("conflicting_reaching_allocations")
   and not ar.llm_eligible_for_reason("required_evidence_absent"))

# >=3 independently-constructed examples per IMPLEMENTED candidate-review bucket
counts = collections.Counter(r["uncertainty_bucket"] for r in recs if r.get("uncertainty_bucket"))
for b in ("relationship_unresolved", "external_contract_unknown",
          "conflicting_definitions", "insufficient_evidence"):
    ck(f"bucket {b} has >=3 examples", counts.get(b, 0) >= 3)

ck("emits >=4 DISTINCT candidate-review buckets", len(set(counts)) >= 4)
ck("all supplementary records pass schema validation", all(ar.validate_record(r) for r in recs))

# FREE / LIFETIME split, validated on the independent runtimecap-cfg fixture
cfg_fix = str(H.parent / "oob-runtimecap-cfg-r01" / "fixtures" / "controls.program.json")
cfg_recs = {r["function"]: r for r in rc.analyze_operations(cfg_fix)}
r = cfg_recs.get("invalid_free_then_write")
ck("free dominates sink -> REROUTED handoff to lifetime_analysis (not a capacity verdict)",
   r is not None and r.get("analysis_status") == "rerouted"
   and r.get("reason_code") == "free_dominates_sink" and r.get("uncertainty_bucket") is None
   and r.get("recommended_route") == "lifetime_analysis"
   and r.get("candidate_class") == "lifetime_use_after_invalidation"
   and r.get("established_facts"))
r = cfg_recs.get("ambiguous_conditional_free_joined_write")
ck("free may reach sink (some paths) -> relationship_unresolved",
   r is not None and r.get("reason_code") == "free_may_reach_sink"
   and r.get("uncertainty_bucket") == "relationship_unresolved")
r = cfg_recs.get("established_write_then_free")
ck("free after the write -> open candidate (capacity relation)",
   r is not None and r.get("analysis_status") == "open_candidate"
   and r.get("reason_code") == "capacity_relation_not_established")
ck("all cfg-fixture records pass schema validation",
   all(ar.validate_record(r) for r in cfg_recs.values()))

# CROSS-PRODUCER v1 emission: cursor and interprocedural producers emit explicit
# v1 reasons for their open candidates (no candidate-presence fallback).
def _load(modname):
    s = importlib.util.spec_from_file_location(modname, TOOLS / f"{modname}.py")
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m

cw = _load("oob_cursor_write_verdict")
cw_fix = str(H.parent / "oob-cursor-r01" / "fixtures" / (
    [p.name for p in (H.parent / "oob-cursor-r01" / "fixtures").glob("*.json")][0]))
cw_recs = cw.analyze_operations(cw_fix)
cw_open = [r for r in cw_recs if r["analysis_status"] == "open_candidate"]
ck("cursor producer emits open candidates as write_count_bound_not_established",
   len(cw_open) >= 1 and all(r["reason_code"] == "write_count_bound_not_established"
                             and r["recommended_route"] == "semantic_relationship_review"
                             for r in cw_open))
ck("cursor records pass v1 schema validation", all(ar.validate_record(r) for r in cw_recs))

ipm = _load("oob_interprocedural_verdict")
ip_fix = str(H.parent / "oob-interproc-r01" / "fixtures" / (
    [p.name for p in (H.parent / "oob-interproc-r01" / "fixtures").glob("*.json")][0]))
ip_recs = ipm.analyze_operations(ip_fix)
ip_open = [r for r in ip_recs if r["analysis_status"] == "open_candidate"]
ck("interproc producer emits open candidates as capacity_relation_not_established",
   len(ip_open) >= 1 and all(r["reason_code"] == "capacity_relation_not_established"
                             for r in ip_open))
ck("interproc records pass v1 schema validation", all(ar.validate_record(r) for r in ip_recs))

def _accounting_ok(recs, emit_open):
    from collections import Counter
    sc = Counter(r["analysis_status"] for r in recs)
    total = sc["deterministic_complete"] + sc["open_candidate"] + sc["abstained"] + sc.get("rerouted", 0)
    return total == len(recs) and sc["open_candidate"] == emit_open

# --- CURSOR accounting + new reasons (dedicated synthetic controls) ----------
cwfix = str(H / "fixtures" / "cursor_accounting.program.json")
cw_recs = cw.analyze_operations(cwfix)
cw_by = {r["function"]: r for r in cw_recs}
CW_EXPECT = {
    "ident_multi_alias":        ("destination_identity_ambiguous", "identity_ambiguous", "abstained"),
    "ident_unresolved":         ("destination_identity_ambiguous", "identity_ambiguous", "abstained"),
    "cap_missing_symbolic":     ("required_evidence_absent", "insufficient_evidence", "abstained"),
    "cap_missing_single_alias": ("required_evidence_absent", "insufficient_evidence", "abstained"),
    "count_open":               ("write_count_bound_not_established", "relationship_unresolved", "open_candidate"),
}
for f, (reason, bucket, status) in CW_EXPECT.items():
    r = cw_by.get(f)
    ck(f"cursor {f} -> {reason}", r is not None and r["reason_code"] == reason
       and r.get("uncertainty_bucket") == bucket and r["analysis_status"] == status)
ck("cursor bounded_guarded -> deterministic_complete (negative control, no bucket)",
   cw_by.get("bounded_guarded", {}).get("analysis_status") == "deterministic_complete"
   and cw_by.get("bounded_guarded", {}).get("uncertainty_bucket") is None)
ck("cursor identity_ambiguous is emitted (real emitter now exists) and specific",
   sum(1 for r in cw_recs if r["reason_code"] == "destination_identity_ambiguous") == 2)
ck("cursor accounting equality holds (recognized = det+open+abstained+rerouted)",
   _accounting_ok(cw_recs, len(cw.emit_candidates(cwfix))))
ck("cursor records all valid v1", all(ar.validate_record(r) for r in cw_recs))

# --- INTERPROC accounting + conflicting_reaching_allocations -----------------
ip_recs2 = ipm.analyze_operations(ip_fix)
ip_by = {r["function"]: r for r in ip_recs2}
ck("interproc helper_conflict -> conflicting_reaching_allocations / conflicting_definitions",
   ip_by.get("helper_conflict", {}).get("reason_code") == "conflicting_reaching_allocations"
   and ip_by.get("helper_conflict", {}).get("uncertainty_bucket") == "conflicting_definitions")
ck("interproc unresolved-target/missing-binding -> required_evidence_absent (NOT conflicting)",
   ip_by.get("helper_unresolved_target", {}).get("reason_code") == "required_evidence_absent"
   and ip_by.get("helper_field", {}).get("reason_code") == "required_evidence_absent")
ck("interproc accounting equality holds",
   _accounting_ok(ip_recs2, len(ipm.emit_candidates(ip_fix))))

# --- determinism: identical output across repeated runs ----------------------
import json as _json
def _sig(rs): return _json.dumps([{k: r[k] for k in sorted(r)} for r in rs], sort_keys=True)
ck("cursor analyze_operations deterministic", _sig(cw.analyze_operations(cwfix)) == _sig(cw_recs))
ck("interproc analyze_operations deterministic", _sig(ipm.analyze_operations(ip_fix)) == _sig(ip_recs2))

print(f"ANALYSIS_RECORD_R01={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
