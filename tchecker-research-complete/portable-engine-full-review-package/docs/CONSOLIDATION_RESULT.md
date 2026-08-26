# Consolidation Result

The portability work has been consolidated into one active package through Gate 23.

## Canonicalized

- One active `PHPCGFactory.java`: Gate-23 cumulative version.
- One active JS/TS CSV adapter: closure-capable adapter carrying the earlier destructuring-era changes.
- Call-resolution, state-summary, uncertainty/evidence, and WordPress instrumentation are separated into named directories.
- Historical gate Java snapshots and duplicate adapter snapshots are not part of the active implementation tree.

## Regression status

`run_all_gates.sh` result:

- Gates 10-23: 14/14 executable preserved regression scripts PASS.
- Gates 2-9: 8/8 historical result artifacts present; no uniform self-contained runner was preserved in those packages, so they are explicitly labeled RECORDED rather than re-executed.
- Executed regressions: 0 failures.

## Canonical engine verification

The bundled detector was rebuilt from source with the canonical Gate-23 factory. The fresh Gate-23 real-engine probe passed and confirmed closure summaries and exact local closure-call edges.

See `CANONICAL_ENGINE_VERIFY.txt` for the build/probe transcript.

## What this does not claim

This is a consolidation, not the final physical Java refactor. WordPress-specific logic still exists inside the legacy factory. The package now gives that refactor a stable canonical branch and regression harness instead of multiple drifting `PHPCGFactory_gate*.java` files.
