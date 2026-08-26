# Engine Lessons Audit after Gate 38

This audit compares the measured PHP-engine improvement spec against the portable engine state after Gate 38. It is a status review, not a new semantic gate.

## Executive result

The portable core now encodes nearly all of the *architectural correctness invariants* learned from the PHP engine. The remaining work is concentrated in four areas:

1. **Real frontend validation** — Gates 24 / 24-TS are still blocked until real Joern `jssrc2cpg` is available.
2. **Concrete adapters/profiles** — generic persistence, state-channel, context, and transformation models exist, but framework/language APIs still need adapters.
3. **Production migration** — the neutral core exists, but the legacy PHP factory is still a parallel implementation and many earlier JS/TS semantics remain prototype-side rather than native neutral-core facts.
4. **Corpus-scale measurement** — budgets, indexing, feature flags, and A/B machinery exist, but real repository/corpus tuning and live profiling remain unverified.

## Item-by-item status

### P0.1 Adaptive traversal budget
**Status: IMPLEMENTED IN CORE; REAL-CORPUS TUNING PENDING.**

Gate 27 replaces silent fixed-depth behavior with a global work budget, high emergency depth limit, structured truncation events, and distinct COMPLETE / UNKNOWN / PARTIAL outcomes. A >9-hop chain is covered by regression tests.

Remaining:
- run real repositories/corpora and tune default work/depth budgets;
- compare result/provenance sets at different budgets;
- ensure truncation counters are surfaced by the production CLI.

### P0.2 Class/context-scoped transformation adequacy
**Status: CORE MODEL IMPLEMENTED; CONCRETE SECURITY/PROFILE RULES DEFERRED.**

Gates 30-32 implement operation × effect class × use context adequacy and nested context stacks. There is no flat sanitizer set in the neutral core.

Remaining:
- concrete profile rule registries (WordPress, browser/JS, DB, shell, etc.) only when security profiles are intentionally added;
- frontend/profile mapping from real calls to transformation operations.

### P0.3 Semantic, not syntactic, propagation
**Status: IMPLEMENTED AS CORE INVARIANT.**

Gates 26-27 propagate `ValueRef` / summaries rather than searching language AST subtrees. Gate 27 asserts the neutral provenance engine has no language AST dependency.

Remaining:
- validate the same invariant with real Joern facts once Gates 24/24-TS run;
- prevent future frontend-specific shortcuts from bypassing `ValueState`/summary semantics.

### P0.4 Structure-aware transformations
**Status: IMPLEMENTED IN GENERIC CORE.**

Gates 31-32 evaluate transformation structure and parser/context boundaries in order; flattened membership cannot satisfy later context layers.

Remaining:
- real sink/context construction from production frontends/profiles.

### P0.5 Persistence / second-order state
**Status: GENERIC CORE IMPLEMENTED; CONCRETE STORAGE ADAPTERS PENDING.**

Gate 28 models persistent locations, writes, reads, resolution, and persisted origins.

Remaining:
- PHP/WordPress mappings such as post meta/options/user meta/transients;
- JS/TS mappings such as storage/database APIs as appropriate;
- corpus validation that write/read identity is neither over- nor under-merged.

### P1.6 Nested parser/output contexts
**Status: GENERIC CORE IMPLEMENTED.**

Gate 32 provides first-class ordered context stacks and fail-closed incomplete/mismatched context handling.

Remaining:
- concrete context-stack construction from real framework/sink behavior.

### P1.7 Full relation/evidence model + abstention
**Status: CORE IMPLEMENTED.**

Gates 29 and 33 provide typed evidence, semantic relation kinds, explicit abstention reasons, and no generic fallback relation.

Remaining:
- validate relation coverage against real Joern/frontend facts;
- add new relation kinds only with explicit tests and abstention behavior.

### P1.8 State-channel origins + return relevance
**Status: GENERIC CORE IMPLEMENTED; CONCRETE CHANNEL ADAPTERS PENDING.**

Gate 27 enforces return relevance. Gate 34 separates REQUEST / SESSION / ENVIRONMENT / PROCESS state and distinguishes EXTERNAL_SOURCE / WRITE_LINKED / UNMODELED.

Remaining:
- framework/language adapters for actual session/request/environment APIs;
- real-repository validation of channel identity and write linking.

### P1.9 Deterministic consumer uses typed evidence
**Status: NEUTRAL DETERMINISTIC CONSUMER IMPLEMENTED.**

Gate 38 consumes identity precision, origin status, resolution, completeness/truncation, relation status, abstention, and context effects. It keeps provenance and transformation adequacy separate.

Remaining:
- migrate or build any eventual security/adjudication policy on top of this consumer;
- do not reintroduce policy shortcuts such as NOT_ESTABLISHED => false positive.

### P2.10 Performance/correctness hygiene
**Status: INITIAL AUDIT + INDEXED VIEW IMPLEMENTED; LIVE PROFILING PENDING.**

Gate 37 found repeated linear lookup in default `ProgramGraph` accessors and added semantics-equivalent immutable `IndexedProgramGraph`. It also audits for the legacy LinkedList and boxed-reference-equality bug classes and tests defensive copies.

Remaining:
- profile real Joern/repository workloads;
- promote indexed access on measured benefit rather than synthetic complexity alone;
- continue live sampling for new hotspots.

### P2.11 Measurement harness
**Status: INITIAL ENGINE-RUNTIME CONTRACT IMPLEMENTED; PRODUCTION CLI/CORPUS WORK PENDING.**

Gate 35 provides COMPLETE / PARTIAL / FAILED run state, stable result IDs, structured counters, feature registry, truncations/abstentions, and A/B diffing.

Remaining:
- production CLI command for corpus/repository A/B;
- standard shadow-counter API tied to feature registry;
- run artifact persistence and reproducible configuration capture;
- verify every experimental feature is read on the actual production path.

## Rejected approaches

**Status: ENCODED AS PERMANENT REGRESSIONS (Gate 36).**

Protected:
- no callee-contains-source => return-source bridge;
- no treating missing defining assignment as inherently erroneous;
- no guessing among competing definitions;
- no promotion of partial/pass-through transformations;
- no fabricated origins in opaque/disconnected cases;
- no generic fallback replacing explicit abstention.

## Important work not fully represented by the legacy checklist

### A. Real Joern frontend is still a critical blocker
Gates 24 and 24-TS remain BLOCKED because real `joern` / `jssrc2cpg` is unavailable in this runtime. The temporary JS/TS adapter is a regression oracle, not the intended production frontend.

This is the highest-priority external validation task because it determines whether the neutral `ProgramGraph` mapping matches actual Joern JS/TS facts.

### B. Production path is still split
The package contains a neutral portable provenance core **and** the legacy `PHPCGFactory`/`StaticAnalysis` implementation. The neutral implementation is not yet the sole production analysis path.

Remaining extraction/migration work includes:
- route real frontend facts directly into `ProgramGraph`;
- migrate production provenance/state/evidence consumers to the neutral core;
- progressively retire PHP-AST-specific core behavior instead of maintaining two engines indefinitely.

### C. Earlier JS/TS semantic gates are not all native neutral-core capabilities yet
Gates 3-23 demonstrated classes, type narrowing, state/aliasing, MAY provenance, arrays/indexing, destructuring, spread, closures, etc. Some of those were implemented in prototype adapters/sidecars/bridges. They still need to be revalidated and, where necessary, represented as neutral `ProgramGraph` facts or portable-core abstractions after real Joern integration.

### D. Corpus validation remains essential
The new core has strong fixture coverage, but several PHP lessons were learned only because corpus measurement contradicted plausible reasoning. Real-repository evaluation must remain a promotion gate.

## Priority order from here

1. **Run Gates 24 and 24-TS with real Joern.** Fix the neutral mapping based on observed CPG facts, not assumptions.
2. **Re-run semantic conformance through the real frontend** (calls, TS narrowing, properties/returns, closures, state/indexing/destructuring/spread) and identify which facts belong in `ProgramGraph`.
3. **Make the neutral core the production path** for ordinary provenance before adding new language-specific semantics.
4. **Add concrete state/persistence/context adapters** only as needed by real repositories.
5. **Wire Gate-35 runtime/A-B machinery into the production CLI**, then use it for corpus promotion decisions.
6. **Profile real workloads** before further performance work.

## Current verification snapshot

The post-Gate-38 audit reran the directly relevant gates successfully:

- Gate 27: 12/12 PASS
- Gate 29: 15/15 PASS
- Gate 30: 13/13 PASS
- Gate 31: 15/15 PASS
- Gate 32: 13/13 PASS
- Gate 33: 18/18 PASS
- Gate 34: 15/15 PASS
- Gate 35: 17/17 PASS
- Gate 36: 14/14 PASS
- Gate 37: PASS (source/complexity audit)
- Gate 38: 21/21 PASS

This audit makes **no claim** that Gates 24/24-TS passed or that corpus-scale behavior has been validated.
