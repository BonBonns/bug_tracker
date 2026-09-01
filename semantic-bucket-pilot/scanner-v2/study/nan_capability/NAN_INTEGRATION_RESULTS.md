# Nan Resource Guard integration (task #34 roadmap, step 1) -- results

Per direct instruction: integrate the frozen, standalone `resource_guard_verdict_nan.py`
(30/30 of its own unit controls, `NAN_CAPABILITY_FREEZE.md`) into the live pipeline, provenance,
applicability, adjudication, and aggregate output, then validate node-snap7's 3 real candidates
and the 6 real negative-control packages. Wiring covered in the prior commit
(`provenance.py`, `applicability_gate.py`, `adjudication_registry.py`,
`six_property_aggregator.py`, `run_pipeline_one.py`/`run_pipeline_one_r06.py`); this document
covers the real, live validation run.

## Synthetic controls: 23/23 (`check_nan_integration.py`)

`PROPERTY_CANDIDATE_RULES["nan_findings"]` exact-match on the two real contract_id verdicts
(never a same-prefixed abstention); `enrich_record()` provenance resolution; applicability
(positive, the weaker `exported_registration` tier accepted, an unrecognized future tier value
rejected, a non-candidate abstention rejected); `adjudication_registry.py` reaching
`nan_findings` through the shared R04/R05/R06 loop; `six_property_aggregator.py` treating it as
always-enabled and summing its raw/reportable counts correctly.

## Real, live validation: 47/48

Run against the SAME 8 real packages the capability's own freeze rests on, through the
now-fully-integrated live pipeline (`run_pipeline_one.py`'s real `run_one()` -- real
c2cpg+jssrc2cpg, real `provenance.enrich_record()`, real
`adjudication_registry.apply_known_adjudications()`, all wired in), with
`applicability_gate.apply_applicability()` and `six_property_aggregator.aggregate_record()`
applied on top, the same post-processing stage every other property goes through.

**node-snap7@1.0.9 (positive)** -- all checks pass. The real live run reproduces exactly the 3
frozen real candidates (`ReadArea`, `Upload`, `FullUpload`), each with `provenance.resolved=True`
and `scanner_candidate=True`; `applicability_gate.apply_applicability()` grants `APPLICABLE` to
all 3; each is `reportable=True` end to end, with no adjudication vetoing it -- **the first real,
non-synthetic `reportable=True` findings this integration has produced.** They are NOT yet
manually adjudicated true/false positive -- that review is explicitly out of this step's own
scope (task #34 roadmap step 2 covers manual review of known structural false-positive
patterns for LOCK_BALANCE/OOB, not Nan; no claim is made here about node-snap7's own real-world
exploitability).

**5 of 6 negative controls confirmed, 0 false positives**: `murmurhash-native`, `msgpack`,
`scrypt`, `libpq`, `phplike` -- each real live run reaches `ANALYZED` and produces zero real Nan
candidates, matching `NAN_CAPABILITY_FREEZE.md`'s own real result, now reconfirmed through the
fully-integrated live pipeline rather than the capability's own standalone dev/test harness.

## Update: kafka-javascript's own real, live run now CONFIRMED (Task 1 of 5, Nan-integration finalization)

The original round above left `@confluentinc/kafka-javascript@1.10.0` as a real, disclosed gap
(`RESOURCE_LIMIT` at 259.2s under the default `NPM_CORPUS_TIMEOUT_MULTIPLIER=1`). Per direct
instruction ("complete or formally resource-limit the kafka-javascript negative control"), this
was root-caused and RESOLVED, not merely re-disclosed:

**Root cause, confirmed directly via per-stage timing, not guessed:** a real live rerun with
`NPM_CORPUS_TIMEOUT_MULTIPLIER=6` (raising `SCAN_TIMEOUT` to 540s and `NORMALIZE_TIMEOUT` to
1080s) reached `ANALYZED` in 498.8s total wall time. Per-stage breakdown: `c2cpg` 23.0s,
`jssrc2cpg` 6.4s, `cpp_export` 36.2s, `js_export` 11.1s, **`cpp_normalize` 330.1s** (the real
bottleneck -- exceeds the DEFAULT `NORMALIZE_TIMEOUT` of 180s by itself), `js_normalize` 3.6s,
`polyglot_link` 48.5s, `r04_scan` 7.9s, `r05_scan` 11.2s, `r06_scan` 9.2s, **`nan_scan` 9.7s**.

The real, disclosed finding: `nan_scan` itself is fast (9.7s, unremarkable at this codebase
size) -- the ORIGINAL `RESOURCE_LIMIT` was never actually about `resource_guard_verdict_nan.py`'s
own per-call backward-trace loop being slow at scale (the concern the first round's own
disclosure speculated). It was `cpp_normalize` (`normalize_c_cpp_facts_v03.py`, a stage that
existed and ran for every OTHER property long before Nan was integrated) exceeding its own
DEFAULT 180s budget on this exceptionally large real codebase (301 C++ files, the full bundled
`deps/librdkafka` C library) -- the exact same class of issue `run_pipeline_one.py`'s own
`NORMALIZE_TIMEOUT` comment already documents for `re2` (127.6s real, hence the existing 180s
default margin) -- kafka-javascript simply sits further along that same real spectrum (330.1s),
past that margin. Not a Nan-specific defect; a pipeline-wide normalize-stage capacity question
that happens to have blocked Nan's own negative-control confirmation as a side effect.

**Real result: `nan_scan` produces 2 raw findings, ZERO reportable candidates.** Both raw
findings are real `NAN_NEWBUFFER_UNBOUNDED_ALLOCATION_SOURCE_BOUNDARY_UNRESOLVED` abstentions
(the traced size argument's own `info[N]` origin could not be structurally resolved -- a real,
disclosed abstention, never silently promoted). **This matches, byte-for-byte in verdict shape,
kafka-javascript's own independent result from task 4's 97-package bundle replay**
(`NAN_REPLAY_TASK4_RESULTS.md`: 2 raw findings, 0 reportable, same verdict) -- two independently-
computed real results (a fresh live c2cpg/jssrc2cpg run here, vs. a bundle replay over
previously-preserved facts there) agreeing exactly is real corroborating evidence for both.

**Negative control status: 6/6 confirmed, 0 false positives.** No fix to
`resource_guard_verdict_nan.py` itself was needed or made -- the capability's own logic was
never the bottleneck.

## What this establishes

- The wiring is real and correct: provenance, applicability, adjudication, and aggregation all
  correctly process `nan_findings`, proven against real corpus data, not just synthetic fixtures.
- Node-snap7's 3 real candidates now flow end to end to `reportable=True` -- since manually
  adjudicated true positives, not merely eligible for review (`NODE_SNAP7_NAN_MANUAL_REVIEW.md`).
- **All 6/6 negative controls are now confirmed clean** under the fully-integrated live
  pipeline, including kafka-javascript -- the one remaining real gap from the original
  integration round is closed.

---
*Live validation here; the preserved 97-package sample's own Nan replay (no Joern rebuild) is
covered separately in `study/task34_replay/NAN_REPLAY_TASK4_RESULTS.md`.*
