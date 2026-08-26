# Gate 38 — Deterministic typed-evidence consumer

Status: **PASS (21/21)**

Gate 38 closes the legacy failure where deterministic adjudication could structurally ignore engine provenance. The portable consumer now reads the typed evidence contract directly and keeps provenance, relation certainty/abstention, and context-specific transformation adequacy as independent axes.

Key invariants verified:

- `ESTABLISHED` origin is not enough for an exact hard path.
- `VALUE_SPECIFIC + EXACT + COMPLETE` is required for hard provenance projection.
- `POSSIBLE`, `NOT_ESTABLISHED`, `NONE`, and `PARTIAL` remain distinct.
- truncation is visible and can never become `NO_ORIGIN`.
- possible or abstained path relations block hard projection.
- explicit abstention reasons survive deterministic consumption.
- context-stack effect guarantees require matching, complete context assessments.
- effect adequacy does not change origin status, and origin status does not change effect adequacy.
- the consumer has no vulnerability/security verdict and is language/framework neutral.

Runtime marker:

```
GATE38=21/21
ANALYSIS_STATUS=COMPLETE
```
