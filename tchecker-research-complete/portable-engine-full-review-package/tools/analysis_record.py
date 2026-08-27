#!/usr/bin/env python3
"""Analysis-record taxonomy for TChecker's automatic bucket layer.

This schema is a CROSS-PRODUCER INTERFACE: every producer's reason-emission layer
must speak it, so the reason codes, bucket mappings, routes, and precedence are
defined ONCE here and frozen before producers are extended. Getting a mapping
wrong here is expensive to unwind after it is baked into several producers.

TWO DISTINCT bucket families that must not be mixed:

1. CANDIDATE-REVIEW buckets -- assigned when TChecker RECOGNIZED an operation and
   produced an analysis record. Derivable at scan time from the producer's own
   reason code; decide whether/how a case reaches an LLM. A/B/C-relevant.
2. COVERAGE-GAP categories -- assigned when a KNOWN-POSITIVE case produced no
   candidate. Need an external oracle; scanner-coverage evaluation only, never
   A/B/C. Listed at the bottom, not emitted during an ordinary scan.

DECISION TABLE (reason_code -> exact condition -> bucket -> route). The route is
determined by the BUCKET (BUCKET_ROUTE); the per-reason `resolution_hint`
records the finer "how could this be resolved" flavor from the review without
fragmenting the top-level routing.

  capacity_relation_not_established
      capacity and width known; the inequality width<=capacity is unproven
      -> relationship_unresolved   (llm_semantic_review)
  allocation_overflow_relation_unresolved
      allocation expression known (e.g. count*width); no-overflow / operand
      range unproven -- a SPECIFIC arithmetic relationship, NOT generic
      insufficiency
      -> relationship_unresolved   (llm_semantic_review; hint: llm_or_range_evidence)
  unknown_allocator_contract
      allocator call recognized but its size semantics are unknown
      -> external_contract_unknown (llm_semantic_review; hint: contract_review)
  conflicting_reaching_allocations
      the same destination has multiple incompatible reaching allocation defs
      -> conflicting_definitions   (additional_evidence_required; hint: more_context_or_abstain)
  destination_identity_ambiguous
      cannot establish WHICH memory object the operation writes
      -> identity_ambiguous        (additional_evidence_required; hint: identity_evidence_or_abstain)
  free_may_reach_sink
      lifetime state differs across feasible paths (free reaches the sink on
      some paths but not others)
      -> relationship_unresolved   (llm_semantic_review; hint: focused_path_question)
  free_dominates_sink
      the same allocation is DEFINITELY freed before the operation on every path
      -> NOT a candidate-review bucket: a DETERMINISTIC lifetime finding
         (analysis_status deterministic_finding, route separate_finding)
  required_evidence_absent
      no more specific recoverable property exists
      -> insufficient_evidence     (additional_evidence_required; hint: abstain)

PRECEDENCE for multiple simultaneous reasons: a candidate can trip more than one
prerequisite (e.g. unknown allocator AND ambiguous identity). Producers emit ALL
detected reasons in `all_reason_codes`; the PRIMARY reason (which fixes the
bucket) is the EARLIEST FAILED PREREQUISITE per PRECEDENCE below -- never
whatever dict/iteration order happened to surface first. Ordering rationale: you
cannot ask about capacity if you do not even know which object is written, or
which allocation reaches it, or whether it is still live.
"""

ANALYSIS_STATUSES = ("open_candidate", "abstained", "deterministic_complete",
                     "deterministic_finding")

# bucket -> route (the A/B/C-relevant routing). llm buckets are the routable set.
BUCKET_ROUTE = {
    "relationship_unresolved": "llm_semantic_review",
    "external_contract_unknown": "llm_semantic_review",
    "conflicting_definitions": "additional_evidence_required",
    "identity_ambiguous": "additional_evidence_required",
    "insufficient_evidence": "additional_evidence_required",
}
LLM_ROUTABLE_BUCKETS = frozenset(
    b for b, r in BUCKET_ROUTE.items() if r == "llm_semantic_review")

# Coverage-gap categories (oracle-required; NOT scan-time, NOT A/B/C).
COVERAGE_GAP_CATEGORIES = (
    "operation_not_recognized", "frontend_fact_missing", "unsupported_representation",
    "propagation_not_modeled", "required_fact_not_produced",
)

# reason_code -> definition. `bucket` None means "not a candidate-review bucket"
# (a deterministic finding routed separately).
REASON_DEFINITIONS = {
    "capacity_relation_not_established": {
        "condition": "capacity and width known; width<=capacity unproven",
        "bucket": "relationship_unresolved", "unresolved_property": "write_length_within_capacity",
        "resolution_hint": "llm_semantic_review"},
    "allocation_overflow_relation_unresolved": {
        "condition": "allocation expression known; no-overflow/operand range unproven",
        "bucket": "relationship_unresolved",
        "unresolved_property": "allocation_multiplication_does_not_overflow",
        "resolution_hint": "llm_or_range_evidence"},
    "unknown_allocator_contract": {
        "condition": "allocator recognized but size semantics unknown",
        "bucket": "external_contract_unknown", "unresolved_property": "allocator_size_semantics",
        "resolution_hint": "contract_review"},
    "conflicting_reaching_allocations": {
        "condition": "same destination has multiple incompatible reaching allocations",
        "bucket": "conflicting_definitions", "unresolved_property": "single_reaching_allocation",
        "resolution_hint": "more_context_or_abstain"},
    "destination_identity_ambiguous": {
        "condition": "cannot establish which memory object is written",
        "bucket": "identity_ambiguous", "unresolved_property": "destination_object_identity",
        "resolution_hint": "identity_evidence_or_abstain"},
    "free_may_reach_sink": {
        "condition": "lifetime state differs across feasible paths",
        "bucket": "relationship_unresolved", "unresolved_property": "capacity_valid_along_all_paths",
        "resolution_hint": "focused_path_question"},
    "free_dominates_sink": {
        "condition": "same allocation definitely freed before the operation on every path",
        "bucket": None, "unresolved_property": None, "resolution_hint": "separate_finding",
        "analysis_status": "deterministic_finding", "finding_class": "lifetime_use_after_invalidation",
        "route": "separate_finding"},
    "required_evidence_absent": {
        "condition": "no more specific recoverable property exists",
        "bucket": "insufficient_evidence", "unresolved_property": None,
        "resolution_hint": "abstain"},
}

# Earliest-failed-prerequisite ordering (index 0 = highest precedence).
PRECEDENCE = (
    "destination_identity_ambiguous",
    "conflicting_reaching_allocations",
    "unknown_allocator_contract",
    "free_dominates_sink",
    "free_may_reach_sink",
    "allocation_overflow_relation_unresolved",
    "capacity_relation_not_established",
    "required_evidence_absent",
)
_PREC_INDEX = {r: i for i, r in enumerate(PRECEDENCE)}


def primary_reason(reason_codes):
    """The bucket-fixing reason among several: the earliest failed prerequisite.
    Deterministic -- never dependent on dict/iteration order."""
    rs = [r for r in reason_codes if r in _PREC_INDEX]
    if not rs:
        return None
    return min(rs, key=lambda r: _PREC_INDEX[r])


def bucket_for_reason(reason_code):
    d = REASON_DEFINITIONS.get(reason_code)
    return d["bucket"] if d else None


def route_for_reason(reason_code):
    d = REASON_DEFINITIONS.get(reason_code) or {}
    if d.get("route"):
        return d["route"]                     # explicit (deterministic finding)
    return BUCKET_ROUTE.get(d.get("bucket"))  # via bucket


def property_for_reason(reason_code):
    d = REASON_DEFINITIONS.get(reason_code) or {}
    return d.get("unresolved_property")


def is_llm_routable(reason_code):
    return bucket_for_reason(reason_code) in LLM_ROUTABLE_BUCKETS


def validate_record(rec):
    """Schema/consistency check for one analysis record."""
    st = rec.get("analysis_status")
    assert st in ANALYSIS_STATUSES, f"bad status {st}"
    if st == "deterministic_complete":
        return True
    if st == "deterministic_finding":
        assert rec.get("reason_code") == "free_dominates_sink", rec
        assert rec.get("uncertainty_bucket") is None, rec
        assert rec.get("recommended_route") == "separate_finding", rec
        return True
    primary = rec.get("reason_code")
    assert primary in REASON_DEFINITIONS, f"unknown reason {primary}"
    assert bucket_for_reason(primary) == rec.get("uncertainty_bucket"), rec
    assert route_for_reason(primary) == rec.get("recommended_route"), rec
    # if all_reason_codes present, primary must be the precedence-selected one
    allr = rec.get("all_reason_codes")
    if allr:
        assert primary_reason(allr) == primary, f"primary {primary} != precedence over {allr}"
    return True
