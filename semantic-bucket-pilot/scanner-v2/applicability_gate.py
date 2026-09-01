#!/usr/bin/env python3
"""APPLICABILITY-GATE-R01: the real, missing affirmative-applicability step task #41's own
docstring disclosed as absent, and task #34's own rejection-funnel analysis (the five real
TIER_TRANSITIVELY_CALLED_FROM_REGISTERED promotions) confirmed as the LAST remaining structural
blocker -- provenance resolves, the candidate shape is real, reachability now clears (task #32
reopened), and reportable STILL stays False solely because nothing ever set
`applicability_status = "APPLICABLE"`. This module is that step, defined separately per
property family, per direct instruction -- never a single blanket rule.

`reportable=True` after this module runs still means ONLY "eligible for manual security
review as a scanner candidate" -- provenance.py's own TERMINOLOGY BOUNDARY, unchanged. This
module does NOT adjudicate, does NOT declare a vulnerability, and does NOT itself decide a
finding is real -- it only determines whether the real, disclosed PRECONDITIONS for eligibility
already hold, using fields other modules already computed. Applied AFTER
`reachability_tier.classify_record_reachability()` (needs `reachability_status`) and BEFORE
`adjudication_registry.apply_known_adjudications()`/`staged_enablement.enforce_staged_enablement()`
(both of which may still veto `reportable` afterward -- this module never has the final word).

=====================================================================================
RESOURCE GUARD (R04/R05/R06) -- retains R06's own real build-configuration and source-boundary
requirements, adds nothing new:
  1. verdict == "VALUE_ACQUISITION_GUARD_MISSING" (the ONLY real candidate verdict --
     scanner_candidate is already this exact check, reused here for clarity, not redefined).
  2. provenance.resolved is True.
  3. `source_boundary_evidence` is PRESENT (not None) -- confirmed directly in
     resource_guard_verdict_r06.py: reaching verdict==GUARD_MISSING at all already REQUIRES
     exc_config == "disabled" (every other value returns CONTRACT_NOT_APPLICABLE/
     BUILD_CONFIGURATION_CONFLICT/BUILD_CONFIGURATION_UNRESOLVED first) -- so condition 1 alone
     already retains the real build-configuration requirement; `source_boundary_evidence`
     being present additionally requires the finding to have gone through R06's OWN real
     source-boundary trace (R04/R05's own legacy findings never carry this key at all -- they
     predate R06's gate, and stay "comparison diagnostic," never applicable, by construction).
  4. `source_boundary_evidence["traced_to_parameter"]` is a REAL, NAMED VALUE parameter -- NOT
     `"this"`. A trace that resolves to `this` (the call's own implicit receiver/self pointer)
     is not the same kind of "a value parameter could plausibly carry JS-supplied data" claim
     R06's own docstring is about (its own real motivating case, node-libcurl's `size_t size`,
     is a genuine value parameter); `this` is determined by which method a JS caller invoked
     through, not by an argument value at all. REAL, DISCLOSED CONSEQUENCE, confirmed directly
     against this replay's own real data, not assumed: node-libcurl's own real finding traces to
     `"size"` (a real value parameter) and clears this condition; all 4 of pqclean@0.8.1's own
     real findings trace to `"this"` and do NOT -- they stay NOT_YET_DETERMINED, exactly as
     R06_GUARD_MISSING_REVIEW.md already recommended (a future INDIVIDUAL review, not an
     automatic rule, is what would move them, the same way node-libcurl's own case was only ever
     resolved by a real, individual, cited manual review).
  R06's own source-boundary check currently NEVER produces a positive ("confirmed attacker-
  controlled") signal at all (its own module docstring: "EVERY reached parameter... is now
  reported as SOURCE_BOUNDARY_UNRESOLVED, attacker_controlled: False" -- a deliberate,
  disclosed, negative-only correction). This module does NOT require attacker_controlled==True
  (structurally impossible to ever satisfy today) -- "eligible for manual review" needs the real
  premises to hold, not proof of exploitability that no part of this pipeline can currently
  produce.

STAGED PROPERTIES -- LOCK_BALANCE / PROTECTED_FIELD / OOB_WRITE / OOB_INDEX_WRITE / OOB_READ:
  Determined (real evidence, not assumed): `provenance.PROPERTY_CANDIDATE_RULES` already
  confirms, per its own comment, that every item these five keys' own findings/candidates lists
  EVER contain IS already a real candidate -- no abstention-shaped entry is ever mixed into the
  list itself (abstentions there only ever increment a separate classification COUNTER).
  lock_balance_verdict.py/protected_field_verdict.py were checked directly before writing this:
  neither has more than the one real `findings.append(...)` site their own real positive
  fixtures already exercise. There is therefore no property-specific shape condition beyond
  what candidate-ness + reachability already establish for these five -- the SAME rule applies
  to all of them:
    1. scanner_candidate is True (PROPERTY_CANDIDATE_RULES' own unconditional True for these
       five keys, reused here for clarity, not redefined).
    2. provenance.resolved is True.
    3. reachability_status is in staged_enablement.py's OWN `_EXTERNALLY_REACHABLE_TIERS`
       allowlist (imported directly, never redefined here -- a second copy of this set would
       be a real drift risk).
    4. the property's own key is in `staged_enablement.ENABLED_PROPERTIES`.
  This makes the record eligible for manual review -- it does NOT declare an OOB/lock/field
  vulnerability, per direct instruction.

OOB_COMPARE: explicitly, deliberately NOT touched by this module at all (task #40's own real
investigation keeps it disabled; `staged_enablement.py`'s own gate already forces it non-
reportable unconditionally regardless of applicability_status -- see this module's own control
proving this module never even sets applicability_status on it).
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import provenance  # noqa: E402
import staged_enablement as se  # noqa: E402

RESOURCE_GUARD_KEYS = ("r04_findings", "r05_findings", "r06_findings")
STAGED_APPLICABILITY_KEYS = ("lock_balance_findings", "protected_field_findings",
                             "oob_write_candidates", "oob_index_write_candidates",
                             "oob_read_candidates")
# Deliberately excludes "oob_compare_candidates" -- task #40 stays disabled; this module never
# even considers it.

_EXCLUDED_TRACE_TARGETS = {"this"}


def _resource_guard_applicable(f):
    if f.get("verdict") != "VALUE_ACQUISITION_GUARD_MISSING":
        return False, None
    prov = f.get("provenance") or {}
    if not prov.get("resolved"):
        return False, None
    sbe = f.get("source_boundary_evidence")
    if not sbe:
        return False, None
    traced = sbe.get("traced_to_parameter")
    if not traced or traced in _EXCLUDED_TRACE_TARGETS:
        return False, traced
    return True, traced


def _staged_applicable(key, f):
    if not f.get("scanner_candidate"):
        return False
    prov = f.get("provenance") or {}
    if not prov.get("resolved"):
        return False
    if f.get("reachability_status") not in se._EXTERNALLY_REACHABLE_TIERS:
        return False
    if key not in se.ENABLED_PROPERTIES:
        return False
    return True


def apply_applicability(record):
    """Sets applicability_status="APPLICABLE" on every real finding/candidate that clears its
    own property family's real preconditions above, then recomputes reportable through
    provenance.finalize_reportability() immediately -- a finding that does NOT clear its own
    preconditions is left exactly as it already was (NOT_YET_DETERMINED, the same real default
    finalize_reportability() itself already assigns -- this module never forces it back down,
    only ever raises it when the real preconditions hold). Returns the count of findings newly
    marked APPLICABLE this call."""
    applied = 0
    for key in RESOURCE_GUARD_KEYS:
        for f in record.get(key) or []:
            ok, _traced = _resource_guard_applicable(f)
            if not ok:
                continue
            if f.get("applicability_status") == "APPLICABLE":
                continue
            f["applicability_status"] = "APPLICABLE"
            provenance.finalize_reportability(f, f.get("scanner_candidate", False))
            applied += 1
    for key in STAGED_APPLICABILITY_KEYS:
        for f in record.get(key) or []:
            if not _staged_applicable(key, f):
                continue
            if f.get("applicability_status") == "APPLICABLE":
                continue
            f["applicability_status"] = "APPLICABLE"
            provenance.finalize_reportability(f, f.get("scanner_candidate", False))
            applied += 1
    return applied
