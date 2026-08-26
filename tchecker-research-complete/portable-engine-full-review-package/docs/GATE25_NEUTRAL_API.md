# Gate 25 — Neutral ProgramGraph API

## Purpose
Turn the real-frontend work into an actual language-neutral core boundary before any further JS/TS feature gates.

## Added
- `core/program_graph/ProgramGraph` Java interface.
- Immutable language-neutral facts for functions, parameters, type declarations, calls and arguments.
- `Resolution` enum with weakest-edge composition.
- Constructor invariants that reject impossible resolution states (for example EXACT with two targets).
- `portable-program-facts/0.2`, unifying the generic Joern and TypeScript Joern normalizers under one schema.
- Schema validator that fails closed on inconsistent call-resolution facts.
- Gate-25 synthetic conformance test.

## Verification
- `GATE25=6/6`.
- `PROGRAM_FACTS_VALID functions=3 calls=1 types=0`.
- Cumulative executable regression: `15/15`, regressions `0`.
- Gates 24 and 24-TS remain BLOCKED because real `joern`/`jssrc2cpg` binaries are not installed in this runtime.

## Architectural result
Future frontends no longer need to target PHP AST node types as their conceptual contract. The stable target is `ProgramGraph` / `portable-program-facts/0.2`. The legacy PHP-shaped engine remains behind an adapter/bridge until its internals are extracted incrementally.

## Next task
Implement the first consumer adapter from `ProgramGraph` into portable provenance primitives, beginning with only function/parameter/call/return facts. Do not add security profiles or more JS syntax until that core path can execute independently of PHP AST classes.
