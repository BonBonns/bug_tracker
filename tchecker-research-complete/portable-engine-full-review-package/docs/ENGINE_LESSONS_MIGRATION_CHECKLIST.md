# Legacy PHP Engine Lessons → Portable Engine Checklist

This file is the persistent checklist for the empirically derived engine-improvement spec. Do not remove an item merely because a later language gate passes.

## P0

| Legacy lesson | Portable status after Gate 38 | Remaining work |
|---|---|---|
| Adaptive traversal budget; visible truncation | IMPLEMENTED (Gate 27) | Tune budgets on real corpora; measure finding/provenance deltas |
| Class/context-scoped transformation adequacy | CORE SHAPE IMPLEMENTED (Gate 30) | Populate security/profile rules only when security profiles are added |
| Semantic, not syntactic propagation | IMPLEMENTED (Gates 26–27) | Keep AST independence as invariant |
| Structure-aware transformation checks | IMPLEMENTED (Gates 31–32) | Connect to real frontend/sink contexts later |
| Persistence / second-order state | IMPLEMENTED GENERIC CORE (Gate 28) | Add framework/language adapters for concrete storage APIs |

## P1

| Legacy lesson | Portable status after Gate 38 | Remaining work |
|---|---|---|
| Nested parser/output context stack | IMPLEMENTED GENERIC CORE (Gate 32) | Add concrete context stacks in profiles/frontends |
| Full relation/evidence model with abstention | IMPLEMENTED CORE (Gates 29, 33) | Extend taxonomy only with explicit tests; no generic fallback |
| State-channel origins + return relevance | IMPLEMENTED GENERIC CORE (Gates 27, 34) | Add concrete request/session/environment adapters |
| Deterministic downstream consumer uses typed evidence | IMPLEMENTED NEUTRAL CONSUMER (Gate 38) | Add any future security/adjudication policy on top; keep typed axes separate |

## P2

| Legacy lesson | Portable status after Gate 38 | Remaining work |
|---|---|---|
| Performance/correctness hygiene | INITIAL AUDIT + INDEXED VIEW IMPLEMENTED (Gate 37) | Profile real portable workloads before promoting/adding optimizations |
| Built-in measurement harness | IMPLEMENTED INITIAL VERSION (Gate 35) | Add production corpus/repository A/B command, standard shadow metrics, reproducible run config |

## Rejected approaches — permanent regressions

Gate 36 protects these as executable tests:

- no naive `callee contains source => return source` bridge;
- no assumption that `NO_DEFINING_ASSIGN` is inherently a bug;
- no guessing among competing definitions;
- no promotion of partial/pass-through wrappers to guaranteed transformations;
- no fabricated attribution in disconnected/opaque fixtures;
- no generic fallback evidence replacing explicit abstention.

## Process invariants

- Measure before promoting behavior.
- UNKNOWN, PARTIAL/TRUNCATED, and demonstrated NO FLOW are distinct states.
- Every deliberate abstention/truncation is emitted.
- Evidence precision is not a verdict.
- New behavior should be shadow-measured where practical before promotion.
- Keep real-Joern Gates 24/24-TS blocked rather than substituting the prototype adapter.

## Gate 37 update — performance/correctness hygiene

- Repeated linear lookup class: **MEASURED IN PORTABLE CORE; indexed alternative implemented.** `ProgramGraph` default ID/group lookup methods scan lists; `IndexedProgramGraph` is semantics-equivalent and builds immutable hash/group indexes once.
- `LinkedList.contains()` legacy hotspot: **NOT PRESENT** in active neutral Java packages as of Gate 37.
- Boxed `Long` / `Integer` reference equality: **NOT PRESENT** in active neutral Java packages as of Gate 37 source audit.
- Mutable caller-owned list aliasing: **guarded** by defensive `List.copyOf` / `Set.copyOf` in active graph/summary records; Gate 37 adds mutation tests.
- Performance claim status: **NO CORPUS SPEEDUP CLAIM.** Gate 37 proves lookup complexity reduction synthetically; live Joern/corpus profiling remains required before prioritizing further optimization.

## Gate 38 update — deterministic typed-evidence consumer

- Deterministic consumer: **IMPLEMENTED as a language/framework-neutral core consumer.** It consumes identity precision, origin status, resolution, completeness/truncation, typed relation status/kind, explicit abstention, and context-stack effect assessment.
- `ESTABLISHED` origin is **not** automatically an exact hard path. `VALUE_SPECIFIC + EXACT + COMPLETE` is required, and possible/abstained path relations block hard projection.
- `NONE`, `NOT_ESTABLISHED`, and `PARTIAL` remain distinct deterministic outcomes; neither unknown nor truncation can become a demonstrated no-origin result.
- Context-specific transformation adequacy is a separate axis from provenance. A demonstrated effect cannot manufacture an origin, and an unknown origin cannot erase a demonstrated context-specific effect.
- Context stack mismatches/incomplete assessments fail closed to `UNKNOWN_FOR_CONTEXT`.
- The consumer contains no security verdict. A future security/profile adjudicator may consume these typed axes, but must add policy rather than infer it from provenance absence.
