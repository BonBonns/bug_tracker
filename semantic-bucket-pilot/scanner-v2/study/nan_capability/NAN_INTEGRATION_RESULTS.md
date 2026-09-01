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

**1 of 6 negative controls -- real, disclosed gap, not a correctness defect**:
`@confluentinc/kafka-javascript@1.10.0`'s real live run hit `RESOURCE_LIMIT` at 259.2s wall
time -- the `nan_scan` stage exceeded the pipeline's own `SCAN_TIMEOUT` (90s at the default
`NPM_CORPUS_TIMEOUT_MULTIPLIER=1`) on this exceptionally large real codebase (301 C++ files,
including the full bundled `deps/librdkafka` C library) -- a real performance characteristic of
`resource_guard_verdict_nan.py`'s own per-call, per-contract backward-trace loop at this scale,
never stress-tested at this size during the capability's original 8-package development. The
"zero false positives" conclusion for this SPECIFIC record still trivially holds (no
`nan_findings` key exists on a `RESOURCE_LIMIT` record, so zero candidates were ever asserted
either way) -- but the real, positive claim "kafka-javascript was fully scanned and confirmed
negative under the now-integrated pipeline" is **NOT confirmed** by this run; only the original
capability's own standalone-harness validation (`NAN_CAPABILITY_FREEZE.md`) reached that
conclusion for this package. Not fixed in this round -- a performance tuning question
(raising `SCAN_TIMEOUT` or `NPM_CORPUS_TIMEOUT_MULTIPLIER` for a future rerun of this one
package specifically), explicitly out of scope for this integration step, disclosed rather than
silently left ambiguous.

## What this establishes

- The wiring is real and correct: provenance, applicability, adjudication, and aggregation all
  correctly process `nan_findings`, proven against real corpus data, not just synthetic fixtures.
- Node-snap7's 3 real candidates now flow end to end to `reportable=True` -- a real, novel
  finding population this pipeline has never produced before, requiring the SAME rigor of manual
  review the 5 staged transitive promotions already received (task #34's own
  `TRANSITIVE_PROMOTIONS_MANUAL_REVIEW.md` precedent) before any claim beyond "eligible for
  manual review" is made about them.
- 5/6 negative controls reconfirmed clean; the 6th (`kafka-javascript`) remains unconfirmed under
  the integrated pipeline due to a real, disclosed timeout, not a correctness gap.

---
*Live validation only -- no Joern rebuild of the 100-package bundle sample (js_raw was never
preserved in those bundles; a future replay of the 100-package sample under Nan, per roadmap
step 5, will require either preserving js_raw in newly-generated bundles or a fresh live run).*
