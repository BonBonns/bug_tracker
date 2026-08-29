#!/usr/bin/env python3
"""Analysis-record taxonomy for TChecker's automatic bucket layer -- FROZEN v2.

SCHEMA_VERSION "2" (bumped from "1" to add `delegated_to_stack_capacity_v2` -- a
REROUTED handoff, same shape as the pre-existing `free_dominates_sink`, for a V1
non-heap destination whose CPG-resolved structure is known but whose capacity
adjudication belongs to V2's stack-capacity integration, never to V1 itself; see
`oob_runtime_capacity_verdict.diagnose_nonbare_destination`'s `fixed()`). No
existing reason code's condition, bucket, route, or llm_eligible changed.

SCHEMA_VERSION "1" freezes: the reason codes, their exact conditions, the bucket
mappings, the ROUTES (keyed on reason, not merely bucket), the llm_eligible flag,
and the PRECEDENCE order. This is a cross-producer interface: producers emit v1
reason codes; nothing here changes without a version bump. (Freezing the schema
does NOT freeze the whole scanner -- producers are still being extended to emit
these reasons; the full experimental scanner is frozen only once that is done.)

TWO bucket families, never mixed:
1. CANDIDATE-REVIEW buckets -- TChecker recognized an operation and produced a
   record; scan-time derivable; decide whether/how a case reaches a resolver.
2. COVERAGE-GAP categories -- a KNOWN-POSITIVE produced no candidate; need an
   external oracle; scanner-coverage eval only, never A/B/C (listed, not emitted).

ROUTE BY REASON, NOT ONLY BUCKET. Several reasons share `relationship_unresolved`
but need different focused resolvers, so the route and unresolved_property are
per-reason. The bucket names the broad cause; the reason + property name the task:

  reason_code                              bucket                    route                       llm
  capacity_relation_not_established        relationship_unresolved   semantic_relationship_review  y
  write_count_bound_not_established        relationship_unresolved   semantic_relationship_review  y
  allocation_overflow_relation_unresolved  relationship_unresolved   range_arithmetic_review       y
  free_may_reach_sink                      relationship_unresolved   path_feasibility_review       y
  unknown_allocator_contract               external_contract_unknown semantic_contract_review      y
  conflicting_reaching_allocations         conflicting_definitions   additional_evidence_required  n
  destination_identity_ambiguous           identity_ambiguous        additional_evidence_required  n
  required_evidence_absent                 insufficient_evidence     additional_evidence_required  n
  free_dominates_sink                      (none: rerouted)          lifetime_analysis             n
  delegated_to_stack_capacity_v2           (none: rerouted)          stack_object_capacity_adjudication  n

semantic_contract_review is DISTINCT from a generic LLM review: the task is to
ESTABLISH an allocator/callee contract from implementation, documentation, or
supplied source -- not to guess what a function probably does. If no contract
evidence is available, the correct result degrades to additional_evidence_required
(a producer that can tell the two apart should emit unknown_allocator_contract vs
required_evidence_absent accordingly).

free_dominates_sink is NOT a finished lifetime verdict: the capacity producer must
not decide a different security property. It emits a HANDOFF (analysis_status
"rerouted", candidate_class lifetime_use_after_invalidation, route
lifetime_analysis) with the established facts; a dedicated lifetime producer /
adjudicator confirms identity, no replacement definition, a feasible post-free
path, and an actual dereference. Until that layer exists it is a deterministic
lifetime CANDIDATE, not a finding.

delegated_to_stack_capacity_v2 is the same shape of handoff, for a different
producer boundary: the V1 heap-capacity producer has no capacity SOURCE for a
stack array, struct-member array, or scalar object (only for heap allocations).
When it CPG-resolves a non-heap destination's structure (element type, element
count, offset, the write's raw width expression) it hands those facts off rather
than guessing or finalizing a comparison itself -- V2's stack-capacity
integration is the one arithmetic owner for that adjudication, for both bare and
non-bare destinations alike. It is never emitted as a candidate-review bucket
(bucket=None, llm_eligible=False) because the next step is deterministic
arithmetic, not a semantic judgment call.

PRECEDENCE: producers emit ALL detected reasons in `all_reason_codes`; the PRIMARY
reason (which fixes the bucket) is the EARLIEST FAILED PREREQUISITE below -- never
dict/iteration order.
"""

SCHEMA_VERSION = "2"

ANALYSIS_STATUSES = ("open_candidate", "abstained", "deterministic_complete", "rerouted")

# Coverage-gap categories (oracle-required; NOT scan-time, NOT A/B/C).
COVERAGE_GAP_CATEGORIES = (
    "operation_not_recognized", "frontend_fact_missing", "unsupported_representation",
    "propagation_not_modeled", "required_fact_not_produced",
)

# reason_code -> frozen definition. `bucket` None => not a candidate-review bucket.
REASON_DEFINITIONS = {
    "capacity_relation_not_established": {
        "condition": "capacity and write length known; width<=capacity unproven",
        "bucket": "relationship_unresolved", "unresolved_property": "write_length_within_capacity",
        "route": "semantic_relationship_review", "llm_eligible": True},
    "write_count_bound_not_established": {
        "condition": "capacity known; number of writes not bounded <= capacity",
        "bucket": "relationship_unresolved", "unresolved_property": "write_count_within_capacity",
        "route": "semantic_relationship_review", "llm_eligible": True},
    "allocation_overflow_relation_unresolved": {
        "condition": "allocation expression known; no-overflow/operand range unproven",
        "bucket": "relationship_unresolved",
        "unresolved_property": "allocation_multiplication_does_not_overflow",
        "route": "range_arithmetic_review", "llm_eligible": True},
    "free_may_reach_sink": {
        "condition": "lifetime state differs across feasible paths",
        "bucket": "relationship_unresolved", "unresolved_property": "capacity_valid_along_all_paths",
        "route": "path_feasibility_review", "llm_eligible": True},
    "unknown_allocator_contract": {
        "condition": "allocator/callee recognized but its size semantics are unknown",
        "bucket": "external_contract_unknown", "unresolved_property": "allocator_size_semantics",
        "route": "semantic_contract_review", "llm_eligible": True},
    "conflicting_reaching_allocations": {
        "condition": "same destination has multiple incompatible reaching allocations",
        "bucket": "conflicting_definitions", "unresolved_property": "single_reaching_allocation",
        "route": "additional_evidence_required", "llm_eligible": False},
    "destination_identity_ambiguous": {
        "condition": "cannot establish which memory object is written",
        "bucket": "identity_ambiguous", "unresolved_property": "destination_object_identity",
        "route": "additional_evidence_required", "llm_eligible": False},
    "required_evidence_absent": {
        "condition": "no more specific recoverable property exists",
        "bucket": "insufficient_evidence", "unresolved_property": None,
        "route": "additional_evidence_required", "llm_eligible": False},
    "free_dominates_sink": {
        "condition": "allocation definitely freed before the operation on every path",
        "bucket": None, "unresolved_property": None,
        "route": "lifetime_analysis", "llm_eligible": False,
        "analysis_status": "rerouted", "candidate_class": "lifetime_use_after_invalidation"},
    "write_exceeds_stack_capacity": {
        "condition": "a literal write length/offset provably exceeds a stack/object "
                     "fixed extent -- a distinguished proven-oversized finding, never "
                     "a hard vulnerable verdict (flag, never assume safe)",
        "bucket": "relationship_unresolved", "unresolved_property": "write_length_within_destination_capacity",
        "route": "range_arithmetic_review", "llm_eligible": False},
    "delegated_to_stack_capacity_v2": {
        "condition": "destination resolves (via CPG reference-target) to a fixed "
                     "stack/object extent -- an array or a scalar; V1 has no capacity "
                     "SOURCE for non-heap objects and does not adjudicate",
        "bucket": None, "unresolved_property": None,
        "route": "stack_object_capacity_adjudication", "llm_eligible": False,
        "analysis_status": "rerouted", "candidate_class": "stack_object_capacity_pending"},
}

CANDIDATE_REVIEW_BUCKETS = ("relationship_unresolved", "external_contract_unknown",
                            "conflicting_definitions", "identity_ambiguous", "insufficient_evidence")

# Earliest-failed-prerequisite ordering (index 0 = highest precedence).
PRECEDENCE = (
    "destination_identity_ambiguous",
    "conflicting_reaching_allocations",
    "unknown_allocator_contract",
    "free_dominates_sink",
    "free_may_reach_sink",
    "allocation_overflow_relation_unresolved",
    "capacity_relation_not_established",
    "write_exceeds_stack_capacity",
    "write_count_bound_not_established",
    "required_evidence_absent",
)
_PREC_INDEX = {r: i for i, r in enumerate(PRECEDENCE)}


def primary_reason(reason_codes):
    rs = [r for r in reason_codes if r in _PREC_INDEX]
    return min(rs, key=lambda r: _PREC_INDEX[r]) if rs else None


def bucket_for_reason(rc):
    d = REASON_DEFINITIONS.get(rc)
    return d["bucket"] if d else None


def route_for_reason(rc):
    d = REASON_DEFINITIONS.get(rc)
    return d["route"] if d else None


def property_for_reason(rc):
    d = REASON_DEFINITIONS.get(rc) or {}
    return d.get("unresolved_property")


def llm_eligible_for_reason(rc):
    d = REASON_DEFINITIONS.get(rc) or {}
    return bool(d.get("llm_eligible"))


def validate_record(rec):
    st = rec.get("analysis_status")
    assert st in ANALYSIS_STATUSES, f"bad status {st}"
    if st == "deterministic_complete":
        return True
    if st == "rerouted":
        rc = rec.get("reason_code")
        assert REASON_DEFINITIONS.get(rc, {}).get("analysis_status") == "rerouted", rec
        assert rec.get("uncertainty_bucket") is None, rec
        assert rec.get("recommended_route") == route_for_reason(rc), rec
        assert rec.get("candidate_class") == REASON_DEFINITIONS[rc]["candidate_class"], rec
        assert rec.get("established_facts"), "rerouted handoff must carry established_facts"
        return True
    primary = rec.get("reason_code")
    assert primary in REASON_DEFINITIONS, f"unknown reason {primary}"
    assert bucket_for_reason(primary) == rec.get("uncertainty_bucket"), rec
    assert route_for_reason(primary) == rec.get("recommended_route"), rec
    assert llm_eligible_for_reason(primary) == rec.get("llm_eligible"), rec
    allr = rec.get("all_reason_codes")
    if allr:
        assert primary_reason(allr) == primary, f"primary {primary} != precedence over {allr}"
    return True
