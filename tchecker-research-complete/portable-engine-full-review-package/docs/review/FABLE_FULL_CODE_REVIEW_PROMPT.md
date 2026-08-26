# Prompt for Fable — Full Portable Engine Code Review

You are reviewing a complete static program-analysis engine migration project. Treat the repository I give you as authoritative. Do not redesign it from memory or from generic architecture preferences before inspecting the actual code, tests, and notes.

## Goal

Review the entire codebase for correctness, architectural drift, missing integrations, regressions, and unfinished migration work. The project started as a PHP/WordPress analysis engine and is being rebuilt into a language-neutral provenance engine with a real Joern JavaScript/TypeScript frontend planned as the first new frontend.

This first review is **program-analysis focused, not vulnerability hunting**. Do not spend the review inventing security sinks/sources. Security/profile policy is downstream of the neutral core.

## Read in this order

1. `START_HERE.md`
2. `docs/ENGINE_LESSONS_POST_GATE38_AUDIT.md`
3. `docs/ENGINE_LESSONS_MIGRATION_CHECKLIST.md`
4. `docs/source-observations/PHP_ENGINE_IMPROVEMENT_SPEC.md`
5. `docs/review/CURRENT_CONCERNS_AND_OPEN_WORK.md`
6. root `README.md`
7. `core/program_graph/`
8. `core/provenance-neutral/`
9. `core/evidence/`
10. `core/effects/`
11. `core/runtime/`
12. `frontends/javascript-typescript/joern/` and `joern-ts/`
13. `frontends/javascript-typescript/ts2legacycsv.js` only as the prototype/regression oracle
14. `engine/legacy-detector/`
15. `tests/gates/`, especially Gates 24–38 and the earlier JS/TS conformance gates 3–23

## Non-negotiable historical invariants

These came from measured failures in the PHP engine. Treat them as constraints unless the code/tests demonstrate a better replacement:

- Resource limits must never silently mean NO FLOW. Emit PARTIAL/TRUNCATED.
- Provenance must be semantic abstract-value propagation, not source-language AST subtree membership.
- A source inside a callee is not a return origin unless it is return-relevant.
- Persistence and request/session/environment/process state are explicit channels, not reasons to guess deeper lineage.
- EXACT / HEURISTIC / AMBIGUOUS / UNRESOLVED must remain distinguishable.
- PROVEN / MAY / UNKNOWN and COMPLETE / PARTIAL must remain distinguishable.
- Identity precision, origin status, path resolution, and completeness are independent axes.
- Transformation/sanitization-like effects are class/context specific, structure aware, and all-path sensitive.
- Nested parser/use contexts are ordered; a transformation for one layer cannot automatically satisfy another.
- Multiple plausible definitions/targets require explicit abstention or ambiguity, never arbitrary selection.
- Evidence strength is not a verdict.
- No generic fallback may hide an unsupported relation branch.
- Every behavioral change should be measured before promotion.

Also read Gate 36 before proposing any origin bridge or partial-wrapper shortcut; several plausible ideas were already measured and rejected.

## Important architectural question

The intended long-term path is:

```text
PHP frontend / Joern frontend ---------\
JS/TS real Joern jssrc2cpg ------------> ProgramGraph / neutral facts
future language frontends -------------/              |
                                                       v
                                            portable provenance core
                                                       |
                                            typed evidence/effects
                                                       |
                                             optional profiles/policy
```

The temporary JS/TS→legacy-PHP-shaped CSV adapter is **not** intended to be the production JS/TS frontend. It is a regression/conformance oracle.

## Review tasks

### A. Verify the current architecture from code

Map the actual runtime/dataflow path. Identify:
- which classes/files are genuinely active;
- which are historical/test-only;
- which pieces still depend on `PHPCGFactory` or PHP AST conventions;
- which Gates 3–23 capabilities have actually migrated to the neutral core versus still living in adapters, sidecars, or bridges.

Do not infer this from directory names. Trace code and test invocation.

### B. Audit `ProgramGraph`

Determine whether the neutral fact model is sufficient for the semantics already proven in Gates 3–23:
- ordinary calls;
- arguments/parameters/returns;
- TypeScript receiver narrowing;
- properties and indexed accesses;
- classes/methods/inheritance/interfaces;
- local aliases;
- heap/object state and strong/weak updates;
- may-alias control flow;
- closures and lexical capture;
- destructuring;
- spread/copy;
- persistence/state channels;
- ambiguous/unresolved call targets.

For each missing primitive, name the minimum new neutral fact needed. Do not add PHP or JS syntax concepts to the core when a semantic fact will do.

### C. Audit real-Joern readiness

Inspect Gate 24 and Gate 24-TS. They are BLOCKED/NOT RUN unless real `joern` / `jssrc2cpg` results are present.

Check:
- whether exporter queries use valid current Joern CPG concepts;
- whether normalization loses call/type/receiver information;
- whether the `portable-program-facts/0.2` schema can represent real Joern ambiguity;
- whether any expected behavior is based only on the prototype adapter.

Do not claim Gate 24/24-TS passes without executing real Joern.

If Joern is available in your environment, run the gates and report observed facts. If it is not available, leave them BLOCKED and give the exact command/input needed to run them.

### D. Audit the portable provenance engine

Look specifically for recreations of the PHP bugs:
- fixed depth cutoffs or silent early returns;
- syntax/subtree-based provenance tests;
- callee-contains-source attribution;
- ambiguity flattened into exact facts;
- UNKNOWN or PARTIAL collapsed to no-flow;
- competing definitions resolved arbitrarily;
- state identity based only on property/key name;
- strong updates used where aliasing is uncertain;
- uncertainty being upgraded through wrappers;
- path resolution strength being lost during composition.

For each issue, provide file/method and a minimal reproducer.

### E. Audit evidence/effect/context contracts

Verify that downstream consumers cannot confuse:
- VALUE_SPECIFIC with ESTABLISHED origin;
- ESTABLISHED origin with EXACT path;
- NOT_ESTABLISHED with NONE;
- PARTIAL with COMPLETE;
- MAY with PROVEN;
- one adequate transformation branch with all-path adequacy;
- one parser-layer transformation with another layer.

Check that abstention reasons are explicit and that unsupported relation types cannot silently become generic fallback evidence.

### F. Audit measurement and flags

Verify that:
- `ANALYSIS_STATUS=COMPLETE` or its structured equivalent is explicit;
- partial/failed runs cannot masquerade as success;
- result IDs are stable enough for A/B;
- duplicate IDs fail loudly;
- feature flags are registered and actually read on production paths;
- shadow metrics can measure divergence without altering behavior;
- A/B reports appeared/disappeared results and semantic-state transitions.

### G. Audit performance without guessing

Find obvious asymptotic hazards, but distinguish:
- demonstrated correctness bug;
- demonstrated complexity problem;
- merely suspicious code.

Do not claim runtime wins without measurements. Pay particular attention to repeated scans, graph walks inside graph walks, cache invalidation, allocation churn, and mutable-key hazards.

### H. Run tests

Run every executable gate you can. Clearly distinguish:
- executed PASS;
- historical recorded result;
- BLOCKED;
- failed.

Do not convert historical output files into fresh test passes.

If the full suite times out, run relevant gates independently and report exactly what was and was not executed.

## Required output

Produce these sections:

### 1. EXECUTIVE VERDICT
Give a concise assessment of whether the codebase is a sound basis for the multilingual engine and name the three biggest risks.

### 2. ACTUAL ARCHITECTURE MAP
Trace the real code path, with files/classes and where the legacy and neutral engines split.

### 3. CONFIRMED BUGS
Only issues demonstrated from code/tests. For each:
- severity to analysis correctness;
- file/method;
- exact mechanism;
- minimal reproducer/test;
- whether it can change detection/provenance or is latent.

### 4. HIGH-CONFIDENCE ARCHITECTURAL DEBT
Things that are not necessarily current bugs but will block the real Joern/multilanguage migration.

### 5. PROGRAMGRAPH GAP MATRIX
A table:

```text
Capability | Prototype gate | Neutral fact support | Real Joern validation | Gap / next action
```

Cover Gates 3–23 semantics.

### 6. PHP LESSONS COMPLIANCE TABLE
For every item in `PHP_ENGINE_IMPROVEMENT_SPEC.md`, classify:

```text
IMPLEMENTED
PARTIAL
NOT IMPLEMENTED
NOT APPLICABLE
BLOCKED ON REAL DATA
```

Cite the code/test that supports the classification. Do not rely only on the existing checklist; independently verify it.

### 7. TEST EXECUTION LEDGER
Exact commands and results. Separate fresh runs from recorded artifacts.

### 8. PRIORITIZED NEXT WORK
Give no more than 8 items, ordered by expected correctness/portability value. Each item must state:
- why now;
- smallest implementation;
- verification gate;
- preservation/regression gate;
- kill criterion.

### 9. DO NOT DO
List proposed changes that would violate measured lessons or prematurely couple the neutral core to one language/framework.

## Review discipline

- Inspect before modifying.
- Measure before promoting.
- Prefer explicit UNKNOWN/AMBIGUOUS/ABSTAINED over fabricated certainty.
- Do not call a finding or architecture improvement successful merely because it compiles.
- Do not silently redesign files just because names are PHP-specific; first determine whether the behavior is actually language-specific.
- If you modify code, keep every behavior change gated until the appropriate tests/measurements demonstrate value.
- Preserve the existing regression suite while fixing packaging/test-runner defects.

At the end, tell me exactly what you would do **first**, but do not begin a broad refactor until the review report is complete.
