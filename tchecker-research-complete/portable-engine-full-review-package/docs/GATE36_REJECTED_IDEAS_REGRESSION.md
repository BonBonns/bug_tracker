# Gate 36 — Rejected Ideas Become Tests

The legacy PHP evaluation measured several plausible changes that either produced wrong provenance or chased buckets that were correct abstentions. Gate 36 makes those negative results part of the portable engine's permanent contract.

## What is protected

- **Return relevance:** `callee contains source` is insufficient. Only semantic dependencies of the returned value propagate.
- **Defining assignments:** direct call values do not need artificial assignments; genuinely missing definitions remain UNKNOWN; competing definitions abstain.
- **Partial transformations:** one transformed branch plus one raw/pass-through branch cannot be globally GUARANTEED.
- **Unresolved attribution:** a disconnected/opaque value stays unresolved; surrounding source-like facts cannot be used as substitutes.
- **Evidence:** abstentions are machine-visible, with no generic/fallback relation kind.

## Why this exists

These are not feature hypotheses. They are anti-regression properties derived from approaches that were measured and rejected in the previous PHP engine. The purpose is to prevent a future frontend, optimizer, or provenance bridge from accidentally reintroducing them.

## Result

`GATE36=14/14`, `ANALYSIS_STATUS=COMPLETE`.
