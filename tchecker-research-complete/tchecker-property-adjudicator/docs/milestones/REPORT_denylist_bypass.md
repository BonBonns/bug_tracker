# Denylist-bypass promotion report — fourth independently gated class

## Mechanism (generalized, not hard-coded)
An earlier rejection predicate excludes only a NARROWER representation/set of values
while a later consumer interprets a BROADER equivalent/matching set, letting an
attacker-controlled value pass the check yet acquire the prohibited meaning at the
consumer. This is a **predicate-semantics / domain-coverage** mismatch.

## The conceptual upgrade (the point of this class)
    old detector view:   exact check + regex later          = suspicious
    evidence model:      check rejects set A; consumer prohibits set B; is B ⊆ A ?

The security property is set/domain containment, NOT `matcher_kind(check) != matcher_kind(consumer)`.
Different matcher kinds are only EVIDENCE.
  - containment ESTABLISHED (B ⊆ A)      -> SAFE_DOMAIN_CONTAINED
  - containment DISPROVEN                 -> CANDIDATE_DENYLIST_BYPASS
  - containment cannot be established      -> NEEDS_SEMANTIC_REVIEW (SEMANTICALLY_OPEN)

Matcher taxonomy carried as evidence: EXACT_KEY, REGEX(ANCHORED_FINITE|BROAD|UNKNOWN),
UNKNOWN(external). Semantic equivalence is never inferred from function names alone.

## Twelve required controls — all pass
     #1 exact check + broad regex consumer        DISPROVEN            -> CANDIDATE
     #2 exact check + exact consumer, same set     ESTABLISHED_CONTAINED-> SAFE
     #3 regex check ⊇ regex consumer (finite)      ESTABLISHED_CONTAINED-> SAFE
     #4 normalization BEFORE both, same canonical  ESTABLISHED_CONTAINED-> SAFE
     #5 exact on raw, normalization AFTER check     domain changed       -> OPEN
     #6 check and consumer on different fields      NOT_JOINED           -> NOT_A_FINDING
     #7 unknown external matcher/parser             unresolved domain    -> OPEN
     #8 multi-representation: one blocked/one not   per-alt DISPROVEN    -> CANDIDATE (unblocked alt)
     #9 identical regex at distinct nodes           distinct identities  -> no collision
    #10 prior-line escaped local (known blind spot) escape resolved      -> SAFE
    #11 validation search-loop fixtures             zero denylist candidates (CLEAN)
    #12 representation variant via helper matcher   breadth unresolved   -> OPEN

Critical rule honored: the mechanism is NOT reduced to matcher_kind difference.
Containment is computed as the property; kind/breadth only feed it. Where containment
is provable safe (exact==exact, escaped literal, finite anchored subset, normalize-before)
the class stays SAFE; where disprovable it is CANDIDATE; otherwise SEMANTICALLY_OPEN.

## CanonicalEvidenceSet mapping (interface unchanged — fourth shape, same seam)
STRUCTURAL: check identity; consumer identity; value identity; check-before-consumer;
            intervening transform (normalizer) identities; per-alternative consumer paths.
SEMANTIC:   rejection matcher kind; consumer interpretation kind; rejected set / consumer
            language where established; containment relation B ⊆ A; whether normalization
            changes the comparison domain.
UNCERTAINTY: matcher semantics unknown; regex breadth unresolved; normalization semantics
            unknown; same-value relation unresolved; external parser semantics unresolved.
VALUE-FLOW ORIGIN: NOT_APPLICABLE — a predicate/domain mismatch does not require an
            attacker value path to be characterised; provenance is populated only where
            real provenance establishes attacker influence, else UNKNOWN/NOT_APPLICABLE.

## Report categories
ALREADY_PRODUCED:        matcher kind, escaped flag, filter→consumer flow (prior detector).
NEWLY_PRESERVED:         regex breadth (ANCHORED_FINITE/BROAD/UNKNOWN), same-value vs
                         normalized-value relation, escape-resolution-through-locals,
                         normalization ordering (before/after), containment tri-state,
                         per-alternative consumer verdicts.
MISSING_RELATION:        none on the twelve controls.
SEMANTIC_UNKNOWN:        #5 (normalize-after), #7 (external matcher), #12 (helper matcher)
                         correctly SEMANTICALLY_OPEN rather than guessed.
NOT_APPLICABLE:          value-flow origin (predicate/domain mechanism).
VERDICT_MOVEMENT:        #10 moves prior detector's false-positive → SAFE (escaped local);
                         #1/#8 remain CANDIDATE via disproven containment, not kind-diff.
INCORRECT/FABRICATED:    none — no semantic equivalence inferred from names; no fabricated
                         containment relationships.
OFF_DIAGONAL_CLASSIFICATION: none — 4×4 matrix is strictly diagonal.

## Full validation
4×4 contamination matrix (serialize/guard/validation/denylist): strictly diagonal.
Frozen gates: DENYLIST 6/6, VALIDATION 6/6, GUARD 6/6, SERIALIZE 9/9; provenance R38/R39/R40 PASS.
Promotion requires zero unexplained contamination and zero fabricated semantic relationships: MET.
