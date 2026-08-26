# RUNBOOK — portable provenance engine (multilingual, real-Joern)

## What this is
A language-neutral data-provenance engine. Language frontends (real Joern
jssrc2cpg for JS/TS, c2cpg for C/C++) are reduced to versioned neutral fact
documents; a strict, inference-free Java loader builds a ProgramGraph; the
PortableProvenanceEngine computes provenance with explicit abstention.
Scoreboard: tests/gates/jsts-r06 (23 PASS / 16 deliberately-unsupported / 0 gaps).

## Prerequisites
- JDK 21 (javac/java on PATH)
- Python 3.10+
- Joern CLI 4.0.400 (for frontend-dependent gates):
  https://github.com/joernio/joern/releases/download/v4.0.400/joern-cli.zip
- Node 18+ with the TypeScript compiler library (for the union sidecar):
  npm i typescript  — then set the require() path in
  frontends/javascript-typescript/tsc-sidecar/tsc_union_types.js if it differs
  from /home/claude/js-frontend/node_modules/typescript/lib/typescript.js

## Environment
export JOERN_HOME=/path/to/joern-cli
export JOERN=$JOERN_HOME/joern
export JSSRC2CPG=$JOERN_HOME/jssrc2cpg.sh
export REPLAY_DIR=$PWD/tests/replay-corpus     # shipped snapshot; or rebuild (below)

## Run everything (canonical suite)
python3 tests/run_all.py
Expected: EXECUTED 20/20, HISTORICAL_RECORDED 8/8, REGRESSIONS 0,
REAL_FRONTEND_24 PASS, REAL_FRONTEND_24-TS PASS.
Labels are honest: 'regrade' rows validate STORED prototype outputs (gates 10-23);
fresh capability proofs are the JSTS-R track. Frontend gates report BLOCKED
(not FAIL) when JOERN/JSSRC2CPG are absent.

## Individual tracks (tests/gates/TRACKS.md is the map)
JSTS-R05  end-to-end TS -> jssrc2cpg -> neutral facts -> loader -> engine -> evidence
          (cd tests/gates/jsts-r05 && bash run.sh)
JSTS-R06  conformance ledger over the replay corpus
          (cd tests/gates/jsts-r06 && bash run.sh)     # needs jsts-r05 build + REPLAY_DIR
CPP-R06   real C AND C++ through the SAME loader/engine
          (cd tests/gates/cpp-r06 && bash run.sh)      # needs JOERN_HOME with c2cpg.sh
CORE-S01..S03  state / identity / capture semantics at the Java API level
          (cd tests/gates/core-s0N && bash run.sh)     # no frontend needed
JSTS-R02..R04  frontend fact derivations vs prototype ground truths
          (bash tests/gates/jsts-r0N/run.sh $REPLAY_DIR/gXX/raw [program_facts.json])
          R02: g20   R03: g13 (+program_facts.json)   R04: g23
JS-SOURCE-R02  external WebExtension runtime-message payloads (MAY)
          (cd tests/gates/js-source-r02 && bash run.sh)
JS-SOURCE-R03  use-scoped WebExtension tab URL metadata (MAY)
          (cd tests/gates/js-source-r03 && bash run.sh)
CORE-S05..S06  corresponding neutral source-origin semantics
          (cd tests/gates/core-s0N && bash run.sh)

## Rebuilding the replay corpus from sources (optional; ~15 min)
bash tests/rebuild_replays.sh          # honors REPLAY_DIR

## Key directories
core/program_graph        neutral facts + strict ProgramGraphLoader (zero deps)
core/provenance-neutral   PortableProvenanceEngine
core/evidence             typed evidence model
frontends/javascript-typescript/joern-ts   exporter (.sc), normalizer, fact derivers,
                                           dispatch classifier (promoted corrections)
frontends/javascript-typescript/tsc-sidecar  union recovery via the TS checker
tests/gates/cpp-r06/frontend               C/C++ exporter + normalizer (same contract)
tests/replay-corpus                        shipped fixture corpus (raw + fact docs)

## Fact document chain (what the loader consumes)
portable-program-facts/0.3  + portable-state-facts/0.4
+ portable-identity-facts/0.2 + portable-capture-facts/0.2
Loader is validation+deserialization ONLY; unknown schemas and known-but-
unconsumed families fail loudly (UNSUPPORTED_FACT_FAMILY). Every derived fact
carries FactDerivation {origin, rule, source_node_ids}.

State facts 0.4 add a mandatory canonical `receiver_location` (root binding plus
ordered property path). The loader retains explicit 0.3 compatibility with the
historical direct-receiver interpretation; it does not infer missing paths.

Source facts remain `portable-source-facts/0.1`. `target_kind=STATE_READ` uses
the historical `target_local_id` field as the concrete state-read fact ID; this
is explicit deserialization, not a loader inference. See
`docs/JS_SOURCE_R03_WEBEXT_TAB_URLS.md` for its contamination ceilings.
