# Routing evaluation (PRIMARY empirical result)

Since the confirmatory A/B/C accuracy experiment cannot be powered from real
disclosed CVEs (EXPANSION_RESULTS.md), the routing evaluation — always planned
as a separate experiment over the broader record set — is the primary empirical
characterization of the frozen v1 scanner. It answers: **for the operations the
scanner recognizes but cannot immediately prove, where does it route them?**

Meta-routes (from the frozen taxonomy):
- `DETERMINISTIC_COMPLETE` — proven safe, no review.
- `LLM_SEMANTIC_REVIEW` — semantic relationship / contract / range-arithmetic /
  path-feasibility review (the slice the bucket method targets).
- `ADDITIONAL_EVIDENCE_REQUIRED` — a fact is missing; needs evidence or analyzer
  repair, NOT semantic review.
- `LIFETIME_ANALYSIS` — rerouted to a dedicated lifetime layer.

## Frozen corpus (151 distinct operations)

| meta-route | count | share |
|------------|-------|-------|
| ADDITIONAL_EVIDENCE_REQUIRED | 105 | 69.5% |
| LLM_SEMANTIC_REVIEW | 44 | 29.1% |
| DETERMINISTIC_COMPLETE | 2 | 1.3% |

**~70% of recognized operations route to additional-evidence-required, not to
LLM review.** Only ~29% are LLM-semantic-review candidates, and (per
FEASIBILITY.md) those collapse to ~7 distinct code sites / ~2 genuine vulnerable
functions once de-duplicated and ground-truthed.

## Interpretation

The scanner's uncertainty is dominated by **missing-evidence** conditions
(unresolved destination identity, capacity facts the frontend did not stage,
unproven propagation), which are calls for deterministic analyzer/frontend
repair or for a produced fact — not for an LLM to reason semantically. The
semantic-review slice the bucket method targets is real but a minority of the
scanner's output, and within it the genuinely vulnerable, independently-grounded
instances are scarce (EXPANSION_RESULTS.md: 4/5 fresh disclosed CVE sites are
outright scanner misses).

This is the honest empirical shape of the contribution:

1. The typed-uncertainty bucket + route layer **correctly separates** the ~29%
   LLM-reviewable slice from the ~70% that needs evidence/repair — that
   separation is itself the useful, measurable output, and it is produced
   automatically from explicit producer reason codes (no human hint).
2. The A/B/C harness that would measure whether typed buckets improve LLM review
   **within** that slice is built and validated, but the real-CVE corpus does
   not supply a powered, balanced case set for it.
3. So the routing evaluation — the distribution above, and the demonstration
   that the scanner more often needs evidence/repair than semantic review — is
   the primary result, with the A/B/C harness as validated, ready machinery.

## Broader-sample population

See `routing_evaluation_result.json` for the whole-module expansion population
(coarse, un-deduplicated) — it reinforces the abstention/evidence-dominated
distribution above on a much larger record count.
