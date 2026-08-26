# Gate 36 — Rejected-Idea Anti-Regression Suite

Status: **PASS — 14/14**

This gate converts measured/rejected legacy PHP-engine approaches into permanent portable-core regressions.

Protected invariants:

1. **No naive callee-source attribution.** A parameter/state source merely present in a callee is not attributed to its return unless the returned semantic value depends on it.
2. **No `NO_DEFINING_ASSIGN` crusade.** Direct call results resolve semantically without requiring a local assignment; a truly undefined local remains UNKNOWN.
3. **No competing-definition guessing.** Multiple possible local definitions produce explicit abstention rather than selecting one.
4. **No partial-wrapper promotion.** A transform-on-one-branch/pass-through-on-another wrapper is CONDITIONAL, never GUARANTEED.
5. **No disconnected-fixture fabrication.** An opaque/disconnected value remains UNKNOWN even when a source-looking parameter exists in the same function.
6. **No generic fallback evidence.** Missing/competing facts are exposed through machine-readable ABSTENTION reasons.

The gate intentionally adds no new provenance behavior. It makes previously rejected ideas executable invariants so future language frontends/core refactors cannot silently reintroduce them.

Observed run:

```
GATE36=14/14
ANALYSIS_STATUS=COMPLETE
```
