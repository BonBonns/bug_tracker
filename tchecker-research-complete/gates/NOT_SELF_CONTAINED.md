# gate_r39.py, gate_r40.py — RESOLVED, no longer NOT_SELF_CONTAINED

**Previously marked NOT REPRODUCIBLE. That is now fixed and verified, not assumed.**

## What was missing and what fixed it

1. The Java core (`PortableProvenanceEngine`, `ProgramGraphLoader`, `core/`) was absent from
   earlier snapshots. Found in a user-uploaded archive at `/mnt/user-data/uploads/` that had not
   been checked. Compiled with `javac` (required installing the JDK via `apt-get
   install openjdk-21-jdk-headless` -- only the JRE was present before) and verified by actually
   running 5 of its Java gate tests directly: `Gate25ProgramGraphTest` (6/6), `Gate26PortableProvenanceTest`
   (10/10), `Gate27CorrectnessContractTest` (12/12), `Gate30TransformationEffectsTest` (13/13),
   `Gate38DeterministicConsumerTest` (21/21) -- all PASS.
2. The `char/` -> `raw/` `typedecls.tsv` bridge (previously searched for exhaustively across 78
   output archives and not found) turned out to live inside a per-milestone gate exporter,
   `tests/gates/js-prov-r08/export_callsites.sc`, which writes `typedecls.tsv` as a side effect
   of its main job. Exact 4-column match: `(td.id, td.name, td.fullName, td.isExternal)`.
3. The real external corpus (`github.com/gothinkster/koa-knex-realworld-example`) was cloned
   fresh, a real CPG built with `jssrc2cpg.sh`, and the full producer chain run against it.

## Result

- `gate_r39.py`: **JS_PROV_R39=7/7, PROMOTION_GATE=PASS** -- reproduced from scratch.
- `gate_r40.py`: **JS_PROV_R40=9/9, PROMOTION_GATE=PASS** -- reproduced from scratch, using the
  R40-specific superset of the producer script (adds `nested_member_exports.tsv`; the plain R38/R39
  version doesn't have this table -- see `gates/recovered_from_prior_outputs/export_r38_facts_R40_VERSION.sc`).

Both fixtures are now bundled at `gates/fixtures/r39-out/raw/` and `gates/fixtures/r40-out/raw/`,
generated from the real corpus now also bundled at `gates/fixtures/corpus_d_src/` for full
from-scratch reproducibility (not just pre-computed facts).

Note: running `gate_r38.py` against this SAME real-corpus data (rather than its own small
synthetic `r38-fixture/`) legitimately fails several of its specific teeth (T4, T5, T8, T9, T7) --
those assertions are written against R38's own handcrafted fixture's exact structure (a specific
"late middleware," a specific "two routers in one file" case) which the real corpus doesn't
happen to contain. That is expected and correct, not a regression: R38 continues to pass 10/10
against its own bundled fixture.
