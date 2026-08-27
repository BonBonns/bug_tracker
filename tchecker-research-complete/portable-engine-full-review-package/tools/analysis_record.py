#!/usr/bin/env python3
"""Analysis-record taxonomy for TChecker's automatic bucket layer.

TWO DISTINCT bucket families that must not be mixed:

1. CANDIDATE-REVIEW buckets -- assigned when TChecker RECOGNIZED an operation and
   produced an analysis record (an open candidate, or a recognized-but-abstained
   result). These are derivable during an ordinary scan from the producer's own
   reason code, and they decide whether/how a case reaches an LLM.

2. COVERAGE-GAP categories -- assigned when a KNOWN-POSITIVE evaluation case
   produced no candidate at all. TChecker generally cannot self-assign these
   during a scan (it may not know it missed anything); distinguishing "the fact
   genuinely does not exist" from "the frontend failed to export it" needs an
   external known-positive oracle. These belong to the SCANNER-COVERAGE
   evaluation, never to the LLM A/B/C evaluation.

The router (bucket_router.py) translates an EXPLICIT producer reason_code into a
candidate-review bucket via REASON_TO_BUCKET below. It must NOT infer a bucket
merely from the presence or absence of a candidate -- that only ever yields the
single "open candidate -> relationship_unresolved" label and cannot distinguish
causes.
"""

ANALYSIS_STATUSES = ("open_candidate", "abstained", "deterministic_complete")

# --- Candidate-review buckets (scan-time assignable) -------------------------
CANDIDATE_REVIEW_BUCKETS = {
    "relationship_unresolved": "llm_semantic_review",
    "external_contract_unknown": "llm_semantic_review",
    "identity_ambiguous": "additional_evidence_required",
    "conflicting_definitions": "additional_evidence_required",
    "insufficient_evidence": "additional_evidence_required",
}

# --- Coverage-gap categories (oracle-required; NOT scan-time, NOT A/B/C) ------
COVERAGE_GAP_CATEGORIES = (
    "operation_not_recognized",
    "frontend_fact_missing",
    "unsupported_representation",
    "propagation_not_modeled",
    "required_fact_not_produced",
)

# --- Explicit producer reason codes -> candidate-review bucket ---------------
# The producer emits the reason_code from its own logic; the router only maps.
REASON_TO_BUCKET = {
    # open candidate: capacity/write relationship recognized but not proven
    "capacity_relation_not_established": "relationship_unresolved",
    # recognized write, but the writing/allocating callee has no known contract
    "callee_contract_missing": "external_contract_unknown",
    "unknown_allocator": "external_contract_unknown",
    # recognized write, but the destination pointer's identity is ambiguous
    "pointer_identity_ambiguous": "identity_ambiguous",
    # recognized write, but the destination has two different reaching allocations
    "conflicting_allocations": "conflicting_definitions",
    # recognized write, but capacity cannot be established from the evidence
    "multiplication_overflow_not_ruled_out": "insufficient_evidence",
    "symbolic_size_unresolved": "insufficient_evidence",
    "capacity_invalidated_by_free": "insufficient_evidence",
}


def bucket_for_reason(reason_code):
    return REASON_TO_BUCKET.get(reason_code)


def route_for_bucket(bucket):
    return CANDIDATE_REVIEW_BUCKETS.get(bucket)


def validate_record(rec):
    """Cheap schema/consistency check for one analysis record."""
    assert rec.get("analysis_status") in ANALYSIS_STATUSES, rec
    if rec["analysis_status"] == "deterministic_complete":
        return True
    reason = rec.get("reason_code")
    bucket = rec.get("uncertainty_bucket")
    assert bucket in CANDIDATE_REVIEW_BUCKETS, f"unknown bucket {bucket}"
    assert REASON_TO_BUCKET.get(reason) == bucket, f"reason {reason} != bucket {bucket}"
    assert rec.get("recommended_route") == CANDIDATE_REVIEW_BUCKETS[bucket], rec
    return True
