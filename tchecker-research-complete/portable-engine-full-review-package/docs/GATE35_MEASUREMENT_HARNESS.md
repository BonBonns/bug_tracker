# Gate 35 — Built-in measurement/runtime contract

Purpose: carry forward the measured PHP-engine lesson that analysis must be falsifiable and machine-diffable.

Adds a portable runtime layer with:

- explicit `COMPLETE | PARTIAL | FAILED` status; completion is never inferred from process exit or partial logs;
- deterministic structured run JSON (`portable-analysis-run/0.1`);
- stable result IDs for set-based A/B comparison;
- structured counters, abstentions, and truncations;
- an explicit feature registry (including env-backed feature declarations); unknown features fail closed;
- first-class A/B diff reporting appeared/disappeared results, uncertainty/status transitions, and counter deltas.

This layer is analysis-domain-neutral: results contain provenance/evidence states, not vulnerability verdicts.

Gate pass criterion: all runtime invariants execute in Java and print `GATE35=.../...` plus `ANALYSIS_STATUS=COMPLETE`.
