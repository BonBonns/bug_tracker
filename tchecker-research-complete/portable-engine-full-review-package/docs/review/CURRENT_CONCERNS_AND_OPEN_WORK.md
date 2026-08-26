# Current Concerns and Open Work

This file is intentionally conservative. It lists the issues a reviewer should actively try to falsify or confirm rather than assuming the current architecture is correct.

## 1. Real Joern validation — DONE for Gates 24/24-TS, still open more broadly

**Update 2026-08-20:** Gates 24 and 24-TS were run against a real Joern install
(joern-cli, `codepropertygraph-domain-classes 1.7.70`, official `joernio/joern`
GitHub release) and both genuinely pass: `GATE24=10/10`, `GATE24_TS=27/27`. See
`tests/gates/gate24/GATE24_RESULT.md` and `tests/gates/gate24-ts/GATE24_TS_PLAN.md`.

This surfaced one real, fixed bug: `export_ts_facts.sc` referenced
`ClosureBinding.closureOriginalName`, which no longer exists on this Joern
version's `ClosureBinding` node. Fixed by dropping the field (verified unused
downstream in `capture_facts.py`) rather than by adjusting expectations.

What this does **not** yet answer — the remaining review questions below still
apply, because Gate 24/24-TS only exercise a small set of hand-written fixtures,
not a real-world corpus:

Review questions:
- Does the real `jssrc2cpg` CPG provide every fact assumed by `portable-program-facts/0.2` on a broader, real-world corpus, not just the gate fixtures?
- Which call/type facts are exact, heuristic, ambiguous, or unresolved in actual Joern output across a wider range of code patterns? (Gate 24-TS's `run/result.txt` has concrete observed values for union/interface/generic/inheritance/any dispatch on its 8 fixtures — a good starting reference, but not exhaustive.)
- Do typed receivers, unions, properties, return types, interfaces, inheritance, generics, closures, and dynamic calls map as assumed outside the fixture set?
- Are any current neutral facts artifacts of the prototype adapter rather than real Joern concepts? (Gates 3–23 still need this check — see concern 3 below; they were not part of this validation pass.)
- Was the one schema-drift bug found (`closureOriginalName`) the only place `export_neutral.sc` / `export_ts_facts.sc` assume a CPG schema shape that has since changed? Only the fields these two gates exercise were checked; other exported fields (e.g. `evaluationStrategy`, other node types) were not individually audited against this Joern version.

## 2. The production path is still split

The package contains both the portable neutral core and the legacy `PHPCGFactory` / `StaticAnalysis` implementation. The neutral core is not yet the sole production analysis path.

Review questions:
- Which behaviors still exist only in the legacy path?
- Which Gates 3–23 capabilities still depend on sidecars/bridges instead of neutral ProgramGraph facts?
- What is the smallest staged migration that avoids a flag day rewrite?
- Where can duplicate implementations drift semantically?

## 3. Early JS/TS gates need real-frontend revalidation

Gates 3–23 demonstrated function calls, TypeScript narrowing, property flow, state/aliasing, MAY/UNKNOWN propagation, indexed state, destructuring, spread/copy, closures, and related behavior. Some of those tests used prototype adapters/sidecars.

Do not assume those results automatically hold for the real Joern frontend. Treat them as a conformance specification to replay.

## 4. PHP-derived invariants must not be lost

The original measured PHP-engine spec is in `docs/source-observations/PHP_ENGINE_IMPROVEMENT_SPEC.md`.
The most important invariants are:

- no silent hard recursion cutoff; resource exhaustion must be visible as PARTIAL/TRUNCATED;
- propagation follows semantic abstract value state, never AST subtree membership;
- return provenance requires return relevance, not merely a source anywhere in a callee;
- persistence and state channels are explicit modeling problems;
- transformation adequacy is class/context-specific and structure-aware;
- nested parser/use contexts are ordered and cannot reuse one transformation across layers;
- identity precision, origin status, path resolution, and completeness are separate axes;
- abstention is explicit and machine-readable;
- NOT_ESTABLISHED, PARTIAL, and demonstrated NO ORIGIN are different states;
- heuristic/ambiguous paths must never be silently hardened;
- measure behavior changes before promotion.

## 5. Measurement is implemented but not yet productionized

Gate 35 introduced completion states, stable IDs, feature registry, counters, and A/B diffing. Remaining concerns:

- production CLI integration;
- reproducible run configuration capture;
- standard shadow-counter API tied to feature flags;
- verification that every feature flag is actually read on the production path;
- real repository/corpus A/B runs.

## 6. Performance work needs real profiling

Gate 37 found repeated list scans and introduced `IndexedProgramGraph`. It did not claim corpus speedup.

Review questions:
- Is IndexedProgramGraph the right default once real workloads are measured?
- Are there hidden O(n²) walks in provenance/state/evidence construction?
- Are memoization/cache keys semantically safe under ambiguity and state changes?
- Are mutable aliases or boxed-reference comparisons present outside the audited neutral packages?

## 7. Concrete adapters are intentionally incomplete

Generic models exist for persistence, request/session/environment/process state, transformations, and context stacks. Actual API mappings are not complete.

Do not add broad framework guesses. Add adapters only from demonstrated API semantics and keep API/profile logic outside the language-neutral core.

## 8. Security policy should remain downstream

The portable core should answer program-analysis questions: provenance, state, resolution, transformations, contexts, completeness. It should not hard-code vulnerability verdicts.

Any future security profile/adjudicator must consume typed evidence and must not use shortcuts such as:
- NOT_ESTABLISHED => false positive;
- privileged/admin-controlled => safe;
- VALUE_SPECIFIC => attacker-controlled;
- one partial sanitizer branch => guaranteed sanitizer.

## 9. Rejected approaches are permanent regressions

Gate 36 exists specifically to keep previously measured bad ideas from returning. Review any change that weakens those tests with extra suspicion.

## 10. Trust measurements over architectural confidence

The PHP project repeatedly found that plausible reasoning was wrong until empirically checked. Every proposed behavioral change should name:
- expected observable difference;
- shadow metric or fixture/corpus test;
- preservation gate;
- kill criterion if benefit does not materialize.
