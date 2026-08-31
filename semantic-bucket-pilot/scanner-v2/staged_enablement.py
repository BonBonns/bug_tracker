#!/usr/bin/env python3
"""STAGED-ENABLE-R01 (tasks #36/#37/#38/#39/#40): per-property staged corpus-run enablement.

WHY THIS EXISTS: `run_diagnostic_100.py`'s own `enforce_diagnostic_only()` is an all-or-nothing
blanket -- every property forced non-reportable, correct for a diagnostic run whose whole point
was that no property had yet been individually validated. This module is what "enabling" one
property in a REAL (non-diagnostic) corpus run actually means, now that some properties' own
precondition tasks are individually complete while others are not. As of this module's own
introduction:
  - LOCK_BALANCE (task #36): ENABLED -- task #32 (reachability) was its only listed
    precondition, and is now complete.
  - PROTECTED_FIELD (task #37): ENABLED -- same, task #32 only.
  - OOB_READ (task #39): ENABLED -- #29/#30/#32/#35/#42/#43 are all complete.
  - OOB_WRITE / OOB_INDEX_WRITE (task #38): ENABLED -- #30/#32/#35/#42/#44 are all complete. #44
    (pointer/length capacity + CFG dominance modeling) reached its own real completion point:
    all 3 real Tremor CVE-2018-5147 sinks are accounted for end to end -- 2 recovered as real
    candidates, the 3rd (a genuinely nested/2D index, `decodevv_add`'s own `a[chptr++][i]`)
    formally, explicitly bounded as a disclosed `ABSTAIN` rather than silently dropped or
    guessed at (`oob_index_write_verdict.py`'s new `emit_abstentions()`). No unbounded gap
    remains in either OOB_WRITE producer. #46 closed the one remaining wiring gap
    (`oob_index_write_candidates` was missing from `provenance.py`'s own enrichment on this
    branch).
  - OOB_COMPARE (task #40): NOT enabled -- task #33 investigated this directly (a real
    positive-control fixture proves the detector itself works; a real 33-package corpus survey
    found zero real positives and root-caused why) and concluded the detector should stay
    gated pending a real corpus positive or a wider run -- a deliberate, evidence-backed "not
    yet," not an open precondition waiting to clear on its own.
`ENABLED_PROPERTIES` is the single, disclosed source of truth for this -- update it (with a
comment citing the task that justifies the change) as more properties clear their own
preconditions, rather than scattering the decision across callers.

Deliberately does NOT touch `r04_findings`/`r05_findings` -- Resource Guard keeps its own
separate lineage/gate (task #41, not yet merged); this module has no opinion on it either way.

TWO REAL GATES, both required for one of the five staged properties' own finding to stay
reportable:
  1. The property itself is in `ENABLED_PROPERTIES`.
  2. The finding's own `reachability_status` (from `reachability_tier.py`, task #32) is present
     and is NOT `REACHABILITY_UNRESOLVED` -- "the property is enabled" does not mean "every
     finding this property ever emits is automatically a demonstrated npm-package
     vulnerability" (task #36's own explicit instruction). A finding whose reachability was
     never established stays non-reportable regardless of which stage its own property has
     reached -- with a DISTINCT diagnostic label (`REACHABILITY_REQUIRED_FOR_REPORTING`) from
     the property-level gate (`STAGE_NOT_ENABLED`), so the two reasons a finding stayed
     non-reportable are never conflated into one.

Never turns a real `False` into `True` -- this module only ever narrows what
`provenance.enrich_record()`'s own formula (task #35) already computed, exactly like
`run_diagnostic_100.py`'s own `enforce_diagnostic_only()` does for the diagnostic run. A finding
that clears both gates here keeps whatever `reportable` value the formula gave it, unchanged.
"""

ENABLED_PROPERTIES = frozenset({
    "lock_balance_findings",         # task #36
    "protected_field_findings",      # task #37
    "oob_write_candidates",          # task #38
    "oob_index_write_candidates",    # task #38
    "oob_read_candidates",           # task #39
})
# NOT enabled: oob_compare_candidates -- task #33's own real investigation found no positive-
# path evidence in the corpus searched and recommended staying gated (task #40), a deliberate
# evidence-backed decision, not an open precondition. #34 (the eventual six-property aggregator)
# must NOT silently flip this on -- OOB_COMPARE stays out of ENABLED_PROPERTIES until a real
# corpus positive is found or a wider run changes this specific conclusion.

_STAGED_KEYS = ("lock_balance_findings", "protected_field_findings", "oob_write_candidates",
                "oob_index_write_candidates", "oob_read_candidates", "oob_compare_candidates")

_UNRESOLVED_REACHABILITY = {None, "REACHABILITY_UNRESOLVED"}


def enforce_staged_enablement(record):
    """Applied AFTER `provenance.enrich_record()` (and, when reachability has been computed,
    `reachability_tier.classify_record_reachability()`) on a REAL, non-diagnostic-only
    corpus-run record. For each of the five staged property keys (never `r04_findings`/
    `r05_findings`):
      - not in `ENABLED_PROPERTIES`: forces `reportable=False`, `stage_status=
        'STAGE_NOT_ENABLED'`.
      - in `ENABLED_PROPERTIES` but `reachability_status` is unresolved/absent: forces
        `reportable=False`, `stage_status='REACHABILITY_REQUIRED_FOR_REPORTING'`.
      - in `ENABLED_PROPERTIES` with a real, resolved reachability tier attached: `reportable`
        is left exactly as `provenance.py`'s own formula computed -- never flipped `False` ->
        `True`; `stage_status='STAGE_ENABLED'`.
    Returns `record` (mutated in place)."""
    for key in _STAGED_KEYS:
        enabled = key in ENABLED_PROPERTIES
        for f in record.get(key) or []:
            if not enabled:
                if f.get("reportable"):
                    f["reportable"] = False
                f["stage_status"] = "STAGE_NOT_ENABLED"
                continue
            if f.get("reachability_status") in _UNRESOLVED_REACHABILITY:
                if f.get("reportable"):
                    f["reportable"] = False
                f["stage_status"] = "REACHABILITY_REQUIRED_FOR_REPORTING"
                continue
            f["stage_status"] = "STAGE_ENABLED"
    return record
