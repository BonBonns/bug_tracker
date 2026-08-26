# Portable Engine — through Gate 29

This package consolidates the JS/TS portability prototype into one active code layout.
Historical gate artifacts are retained only under `tests/gates/`; old `PHPCGFactory_gate*.java`
and duplicate frontend adapter snapshots are intentionally removed from the active tree.

## Canonical active implementation

- `core/provenance/PHPCGFactory.java` — canonical Gate-23 factory. This is also installed into the self-contained legacy detector source tree.
- `frontends/javascript-typescript/ts2legacycsv.js` — canonical JS/TS→legacy CSV adapter. It includes the destructuring-era adapter changes plus closure emission.
- `bridges/call_resolution/` — explicit frontend call-resolution facts.
- `bridges/state_summary/` — receiver/property state, alias, indexed state, destructuring and spread/copy models/bridge generators.
- `core/uncertainty/` — MAY/UNKNOWN evidence and path reporting.
- `profiles/wordpress/` — WordPress-specific instrumentation that is not yet extracted from the legacy factory.

## Regression command

```bash
./run_all_gates.sh
```

This executes every preserved gate test that has a runnable regression script (Gates 10–23) and separately verifies that result artifacts exist for Gates 2–9. It does **not** falsely label the latter as re-executed tests.

## Canonical Java compile + real Gate-23 probe

```bash
./verify_canonical_engine.sh
```

This rebuilds the bundled detector source with the canonical factory and runs a fresh Gate-23 closure probe against it.

## Important remaining architectural debt

The directory organization is now clean, but the Java implementation is not yet physically split into separate Java core/profile classes. WordPress-specific passes still live in `PHPCGFactory.java`. This consolidation makes one canonical branch and one regression entry point first; extracting those passes is the next refactor, not something this package pretends has already happened.

## Gate 24: real Joern frontend

The intended JS/TS first layer is now `frontends/javascript-typescript/joern/`.
`ts2legacycsv.js` remains a prototype/regression oracle only. Gate 24 invokes the real
Joern `jssrc2cpg` frontend and normalizes its CPG into `portable-program-facts/0.1`.

**Verified 2026-08-20: `GATE24=10/10` PASS**, run against a real Joern install
(joern-cli, `codepropertygraph-domain-classes 1.7.70`, from the official
`joernio/joern` GitHub release). See `tests/gates/gate24/GATE24_RESULT.md` for the
full record, including a note on a previously-shipped, contradictory-looking
artifact that this run superseded.

## Gate 24-TS: TypeScript conformance on real Joern

`tests/gates/gate24-ts/` contains eight TypeScript fixtures covering directly typed receivers, unions, typed properties, typed returns, interfaces, inheritance, bounded generics, and `any`.

`frontends/javascript-typescript/joern-ts/` exports standard CPG type/call facts from the real `jssrc2cpg` graph. The gate deliberately **characterizes** Joern's callee precision for union/interface/generic cases instead of baking in guessed expectations. It requires the basic TypeScript type facts (typed parameters, members, inheritance, calls) and writes `gate24_ts_observations.json` for the dispatch comparison.

**Verified 2026-08-20: `GATE24_TS=27/27` PASS**, run against the same real Joern
install. The first real attempt surfaced a genuine CPG-schema drift bug
(`ClosureBinding.closureOriginalName` no longer exists on this Joern version) in
`export_ts_facts.sc`; fixed with no change to downstream capture semantics. See
`tests/gates/gate24-ts/GATE24_TS_PLAN.md` for the fix and full dispatch
observations (union/interface/generic resolution classes, etc.).

To re-run either gate:

```bash
JSSRC2CPG=/path/to/jssrc2cpg.sh JOERN=/path/to/joern \
  tests/gates/gate24/run_gate24.sh
JSSRC2CPG=/path/to/jssrc2cpg.sh JOERN=/path/to/joern \
  tests/gates/gate24-ts/run_gate24_ts.sh
```

## Gate 25: neutral ProgramGraph boundary

`core/program_graph/` is now the canonical language-neutral frontend contract. Both real-Joern normalizers target `portable-program-facts/0.2`, and the Java API enforces resolution invariants (`EXACT`, `HEURISTIC`, `AMBIGUOUS`, `UNRESOLVED`) without PHP AST or WordPress concepts.

Gate 25 is locally executed: `GATE25=6/6`. Cumulative runnable regressions are `15/15` with zero regressions. Gates 24/24-TS remain blocked only on the missing real Joern binaries.

## Gate 26: first extracted neutral provenance engine

`core/provenance-neutral/` is the first executable analysis logic that consumes the
`ProgramGraph` interface directly. It implements function/argument/parameter/return
provenance and preserves EXACT/HEURISTIC/AMBIGUOUS/UNRESOLVED semantics without using
PHP AST classes or WordPress rules.

Verification:

```text
GATE26=10/10
EXECUTED 16/16
REGRESSIONS 0
CANONICAL_ENGINE_GATE23=PASS
```

This is intentionally a narrow extraction. Heap/state, closures, framework callbacks,
and security semantics have not yet been moved into the neutral Java core.

## Gate 27 — portable correctness contract

The neutral provenance core now supports semantic local assignment/alias flow and explicit `COMPLETE | UNKNOWN | PARTIAL` analysis status. Resource limits emit structured truncation events rather than silently behaving as no-flow. A 21-function chain is verified under the default budget, so the legacy PHP engine's hard depth-9 cutoff is not inherited.

Run:

```bash
tests/gates/gate27/run_gate27.sh
```

## Gate 28 — portable persistence/state channels

The neutral graph/core now models durable or out-of-band state explicitly using `PersistenceLocation`, write/read facts, and out-of-band `OriginRef`s. This supports write -> later read provenance across function/request boundaries without teaching the core WordPress, browser-storage, or database API names.

The read/write correspondence is supplied by a frontend/profile state model with `EXACT | HEURISTIC | AMBIGUOUS | UNRESOLVED` resolution. The provenance core never guesses by key name; mismatched locations abstain, ambiguous/heuristic reads stay MAY, and unresolved reads stay UNKNOWN.

Run:

```bash
tests/gates/gate28/run_gate28.sh
```

## Gate 29 — typed evidence / abstention contract

`core/evidence/` is now the typed boundary between neutral provenance and downstream consumers. It keeps **identity precision**, **origin status**, **resolution**, and **analysis completeness** separate so an identified value cannot be mistaken for an established origin, and a proven common dependency over an ambiguous path cannot be mistaken for an exact hard path.

The machine contract is `portable-evidence/0.1`. It has no vulnerability verdict field. `OriginStatus.NONE`, `NOT_ESTABLISHED`, and `PARTIAL` are distinct outcomes.

Verification:

```text
GATE29=15/15
EXECUTED 19/19
REGRESSIONS 0
CANONICAL_ENGINE_GATE23=PASS
```

## Gate 30 — class/context-aware transformation effects

`core/effects/` introduces a language-neutral transformation relation:

```text
operation × effect_class × use_context -> adequacy
```

There is deliberately no flat global sanitizer/transformer membership bit. A transformation can be guaranteed in one semantic context, inadequate in another, and unknown where no exact rule exists. Conditional wrappers remain conditional, and a wrapper is guaranteed only when every alternative branch is guaranteed for the same effect/context.

The core stays non-security-specific: it contains generic transformation classes and contexts, not WordPress escapers or vulnerability verdicts. Security/framework profiles may register policy later without changing provenance.

## Gate 31

The portable effect layer now supports structure-aware transformation chains and ordered nested context boundaries.
See `docs/GATE31_STRUCTURE_AWARE_EFFECTS.md` and `tests/gates/gate31/`.

## Gate 32 — explicit nested context stack

Adds a first-class ordered `ContextStack` and fail-closed evaluator for values crossing multiple parser/use boundaries. Transformations are assessed per structural segment and cannot be reused across later layers by flattened membership. See `tests/gates/gate32/GATE32_RESULT.md`.

## Gate 33 — relation evidence and mandatory abstention

The neutral evidence layer now has a semantic relation taxonomy and explicit machine-readable abstention. Missing/ambiguous relation cases cannot silently degrade to a generic fallback. See `docs/GATE33_RELATION_EVIDENCE.md`.

## Gate 34 — state channels

The neutral provenance core now distinguishes request/session/environment/process state from durable persistence. State-channel reads explicitly declare whether they are external origins, write-linked, or unmodeled; unmodeled channels remain UNKNOWN. See `docs/GATE34_STATE_CHANNELS.md`.

## Gate 35 — measurement/runtime contract

`core/runtime` provides explicit completion state, structured run records, a feature registry, structured counters/truncations/abstentions, and first-class A/B diffing over stable analysis result IDs. See `docs/GATE35_MEASUREMENT_HARNESS.md`.

## Gate 37 — performance/correctness hygiene

Gate 37 audits the active neutral Java packages for legacy performance/correctness bug classes and adds an optional immutable `IndexedProgramGraph` view. It is behavior-preserving by construction and regression-tested against the unindexed `ProgramGraph` semantics. The synthetic complexity test records 2,000,000 backing-list reads for 100 tail lookups in a 20,000-function default graph, versus 20,000 reads to build the index once and 0 backing-list reads for the same 100 indexed lookups. This is not presented as a corpus runtime claim.

## Post-Gate-38 engine-lessons audit

`docs/ENGINE_LESSONS_POST_GATE38_AUDIT.md` is the current item-by-item audit against the empirically derived PHP-engine improvement spec. It separates implemented portable-core invariants from work still requiring real Joern, concrete adapters, production-path migration, corpus A/B, or live profiling.
