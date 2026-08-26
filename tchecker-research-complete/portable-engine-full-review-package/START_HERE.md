# Portable Engine — Full Review Package

This is the current consolidated codebase through the post-Gate-38 engine-lessons audit.
It is intended to be the canonical package for code review and continuation work.

## Read these first

1. `docs/ENGINE_LESSONS_POST_GATE38_AUDIT.md` — current status and unfinished work.
2. `docs/ENGINE_LESSONS_MIGRATION_CHECKLIST.md` — persistent PHP→portable-engine lessons checklist.
3. `docs/source-observations/PHP_ENGINE_IMPROVEMENT_SPEC.md` — original measured observations from the PHP engine.
4. `docs/review/CURRENT_CONCERNS_AND_OPEN_WORK.md` — concise list of concerns that should drive review.
5. `docs/review/FABLE_FULL_CODE_REVIEW_PROMPT.md` — ready-to-paste review prompt.
6. `README.md` — architecture/history and gate summary.

## What is canonical

- `core/program_graph/` — language-neutral frontend contract.
- `core/provenance-neutral/` — extracted portable provenance engine.
- `core/evidence/`, `core/effects/`, `core/runtime/` — typed evidence, transformation/context effects, and measurement/runtime contracts.
- `frontends/javascript-typescript/joern/` and `frontends/javascript-typescript/joern-ts/` — intended real Joern JS/TS frontend path.
- `frontends/javascript-typescript/ts2legacycsv.js` — prototype/regression oracle, not the intended production frontend.
- `engine/legacy-detector/` — bundled legacy PHP detector retained for regression and staged migration.
- `tests/gates/` — historical and current conformance/regression gates through Gate 38.

## Current high-priority unfinished work

1. ~~Run real Joern Gate 24 / Gate 24-TS~~ — **DONE 2026-08-20.** Both gates now
   genuinely PASS against a real Joern install (`GATE24=10/10`,
   `GATE24_TS=27/27`); see `tests/gates/gate24/GATE24_RESULT.md` and
   `tests/gates/gate24-ts/GATE24_TS_PLAN.md`. One real CPG-schema drift bug
   (`ClosureBinding.closureOriginalName`) was found and fixed in
   `export_ts_facts.sc` along the way. The ProgramGraph mapping was not found to
   need correction against the observed real-CPG facts, but this has only been
   checked against the Gate 24 / 24-TS fixtures, not a broader corpus — treat the
   mapping as spot-checked, not exhaustively validated.
2. Revalidate Gates 3–23 semantic capabilities through the real Joern frontend.
   (JSTS-R05, the fresh capability-proof track, now also passes against the real
   frontend — see `tests/gates/jsts-r05/` — but Gates 3–23 themselves still
   grade stored prototype outputs per `tests/run_all.py`.)
3. Migrate the actual production analysis path to ProgramGraph + neutral core; avoid maintaining two permanent engines.
4. Add concrete state/persistence/context adapters only when justified by real repositories.
5. Wire the Gate-35 runtime/A-B machinery into the production CLI and run corpus/repository comparisons.
6. Profile real workloads before making further performance claims or optimizations.
7. JS-STATE-R06 (proposed, not started): return-contract-establishment
   characterization for the failure-state-erasure fact family, nominated by
   real-corpus evidence in `docs/corpus-scans/js-real-r01/`. Do not jump
   straight to CFG/reaching-definitions unification for that fact family
   without re-checking against a second real corpus first — the evidence to
   date does not support it as the dominant blocker.

Do not report blocked gates as PASS and do not silently replace real Joern with the prototype adapter.

## Note on this environment's Joern install

A real Joern CLI is installed in this session's sandbox at
`/home/claude/joern-install/joern-cli` (downloaded from the official
`joernio/joern` GitHub release, `codepropertygraph-domain-classes 1.7.70`). It is
**not part of this package/zip** — it lives outside `portable-engine-full-review-package/`
in the sandbox filesystem and will not persist or travel with the package. To
reproduce Gate 24 / 24-TS elsewhere, install Joern separately (see
`frontends/javascript-typescript/joern/README.md`) and point `JSSRC2CPG`/`JOERN`
at it.
