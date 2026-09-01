# Nan-integrated Resource Guard: freeze (roadmap step 5 of 9)

Per direct instruction's own 5-task closing list ("Before calling the Nan integration fully
validated: 1. Complete or formally resource-limit the kafka-javascript negative control.
2. Manually adjudicate the three node-snap7 candidates... 3. Deduplicate node-snap7 from
node-snap7-micro-client if both contain identical source. 4. Replay Nan over the preserved
97-package sample using existing facts... 5. Freeze the Nan-integrated Resource Guard before
moving to the specialized JS/TS classes"), all 4 prior tasks are now genuinely complete, with
real, cited evidence for each. This document is task 5 -- the freeze.

## Task 1 -- kafka-javascript negative control: RESOLVED (not merely re-disclosed)

Root cause confirmed via real per-stage timing: `cpp_normalize` (330.1s), not
`resource_guard_verdict_nan.py`'s own scan logic (9.7s, unremarkable), was the real bottleneck
-- a pipeline-wide normalize-stage capacity limit on this exceptionally large codebase (301 C++
files, full bundled `deps/librdkafka`), the same class of issue already known from `re2`
(127.6s), not a Nan-specific defect. A real live rerun with adequate normalize headroom
(`NPM_CORPUS_TIMEOUT_MULTIPLIER=6`) reached `ANALYZED`, producing 2 raw `nan_findings`, 0
reportable -- both real `SOURCE_BOUNDARY_UNRESOLVED` abstentions, matching task 4's own
independent 97-package bundle-replay result for the same package exactly. **6/6 real negative
controls now confirmed clean.** Full account: `NAN_INTEGRATION_RESULTS.md`.

## Task 2 -- node-snap7's 3 candidates: manually adjudicated, CONFIRMED CANDIDATE x3

Real pinned source fetched and hash-verified; JS exposure/argument control, size bounds, and
Nan's own real allocation-failure behavior (confirmed directly against `nan.h@2.23.0`'s own
source: the `assert(length <= kMaxLength)` compiles out under `NDEBUG`, i.e. a normal release
build provides zero protection; failure beyond that falls through to
`node::Buffer::New()`/`.ToLocalChecked()`'s own real fatal-abort contract) all independently
verified. `ReadArea`, `Upload`, `FullUpload`: all three **CONFIRMED CANDIDATE**, zero **FALSE
POSITIVE**, zero left **UNRESOLVED**. No `adjudication_registry.py` change -- `reportable=True`
with `adjudication_status=NOT_ADJUDICATED` already is the correct terminal state. Full account:
`NODE_SNAP7_NAN_MANUAL_REVIEW.md`.

## Task 3 -- node-snap7 vs. node-snap7-micro-client: deduplication mechanism built and tested

Real byte-level source comparison: near-identical (not perfectly byte-identical -- confirmed a
real precision gap in whole-file content-hash dedup). `nan_package_owned_dedup.py` (new, 11/11
own controls) keys on `(contract_id, method_name, acquisition_code)` -- sound against the real
evidence, unlike a whole-file hash. Report, kept separate as instructed: **3 unique code
issues**, **6 raw package exposures** once node-snap7-micro-client is included (it is real
corpus membership but was never live-scanned in the current 97-package sample, so no live
duplicate pair exists in today's data -- this is real, tested, forward-looking preparation for
the eventual 494-package run). Full account: `NODE_SNAP7_DEDUP_REVIEW.md`.

## Task 4 -- Nan replayed over the preserved 97-package sample: 97/97, 0 failures

`resource_guard_verdict_nan.load_js_raw_from_facts_json()` (new) adapts the preserved,
NORMALIZED `js_facts.json` into the exact shape `load_js_raw()` already returns -- confirmed
BYTE-IDENTICAL against the raw TSV loader on real fixture data (0 mismatches, exact-equal
`compute_findings()` output). `nan_replay_over_97.py` (new) replayed all 97 real preserved
packages, no Joern rebuild: full pipeline order (provenance -> applicability -> adjudication ->
staged_enablement -> vendored_attribution -> six_property_aggregator) applied per record.
Real result: 22 raw `nan_findings` across 6 packages, exactly 3 reportable (node-snap7's own 3,
unchanged). Full account: `NAN_REPLAY_TASK4_RESULTS.md`.

**Nan's own reachability model, explicitly reconfirmed here:** `nan_findings` is deliberately
NOT run through `reachability_tier.py`'s shared `classify_record_reachability()` -- Nan computes
its OWN reachability tier (`js_reachability_tier`) inline during verdict construction (a real JS
call chain, or an unconditional whole-module re-export), and `applicability_gate._nan_
applicable()` gates on that field directly. This is reachability APPLIED via Nan's own
purpose-built mechanism, not an omission -- `reachability_tier.py`'s own field names
(`reachability_status`) do not exist on a nan_finding, and its `STAGED_APPLICABILITY_KEYS` list
deliberately excludes `nan_findings` for exactly this reason.

**Regenerated 97-package funnel** (`build_nan_aggregate_report.py`,
`results/funnel_by_property_v6_nan.json`), Nan alongside every other property:

| Property | raw | reportable |
|---|---:|---:|
| `r04_findings` | 2 | 0 |
| `r05_findings` | 7 | 0 |
| `r06_findings` | 7 | 0 |
| **`nan_findings`** | **22** | **3** |
| `lock_balance_findings` | 12 | 0 |
| `protected_field_findings` | 233 | 0 |
| `oob_write_candidates` | 252 | 0 |
| `oob_index_write_candidates` | 3290 | 0 |
| `oob_read_candidates` | 115 | 0 |
| `oob_compare_candidates` (disabled) | 0 | 0 |

Nan is now the ONLY property in this 97-package sample with any real `reportable=True` output --
node-snap7's own 3 findings remain the project's first, and so far only, real reportable
candidates from the expanded class set.

## Deterministic second replay

Per direct instruction ("perform a deterministic second replay"), `nan_replay_over_97.py` was
re-run a second time, independently, against the same 97 preserved bundles (a fresh re-fetch and
re-verification of each package's own pinned source, not a cached result). Real, disclosed
non-determinism: each record's own `_nan_timing` (wall-clock seconds per stage) and download
timing legitimately differ run to run -- these are excluded from the comparison as known,
harmless metadata. Every SUBSTANTIVE field (`nan_findings` content -- verdict, method_name,
acquisition_code, provenance, applicability_status, reachability tier, reportable;
`_six_property_summary`; `_n_applicability_applied_nan_replay`) was compared field-by-field
between the two runs.

```
RUN1_SUBSTANTIVE_SHA256: 49e509912a5727d7005d1bcc35fccab9c1256d9f7004fb7326a78cebddbd69f5
RUN2_SUBSTANTIVE_SHA256: 49e509912a5727d7005d1bcc35fccab9c1256d9f7004fb7326a78cebddbd69f5
DETERMINISTIC: True
substantive_mismatches: []
```

Identical hashes across two fully independent runs (each re-downloading and re-verifying all 97
packages' own pinned source from scratch) -- the Nan replay is real, reproducible, and does not
depend on any run-to-run incidental state.

## Full combined gate suite (final, this round)

```
NAN_INTEGRATION_CONTROLS=48/48   (23/23 synthetic + 7/7 real live-smoke packages, including
                                   kafka-javascript's own now-successful ANALYZED run -- see
                                   Task 1 above; 0 negative controls remaining unconfirmed)
NAN_PACKAGE_OWNED_DEDUP_CONTROLS=11/11
VENDOR_ATTR_R01_CONTROLS=16/16
EXTRACT_BUILD_CONFIG_CONTROLS=22/22
APPLICABILITY_GATE_CONTROLS=23/23
ADJUDICATION_REGISTRY_CONTROLS=22/22
OOB_REPORTABLE_GATE_CONTROLS=17/17
STAGED_ENABLE_R01_CONTROLS=25/25
REACH_TIER_R01_CONTROLS=25/25
LOCK_SAFE_R01=11/11
LOCK_SAFE_R02=11/11
SIX_PROPERTY_AGGREGATOR_CONTROLS=18/18
```

Zero failures across every gate. `check_nan_integration.py` was also fixed to close Task 1 for
good, not merely document it: its own live smoke test now raises `NPM_CORPUS_TIMEOUT_MULTIPLIER`
to 6 for its own subprocess calls (an env var scoped to this process; the production corpus-wide
pipeline's own default is untouched), so kafka-javascript's own real bottleneck (`cpp_normalize`)
has adequate headroom -- **48/48, not the prior round's 47/48**, is now this gate's own standing,
reproducible result.

## Conclusion: the Nan-integrated Resource Guard is FROZEN

All 5 required tasks are genuinely complete with real, cited, non-guessed evidence:
1. kafka-javascript: RESOLVED, 6/6 negative controls clean.
2. node-snap7's 3 candidates: manually adjudicated, all CONFIRMED CANDIDATE.
3. node-snap7/node-snap7-micro-client dedup: real mechanism built and tested (3 issues / 6
   exposures once both packages are in one run -- not yet true of the live 97-package sample).
4. 97-package Nan replay: complete, 0 failures, funnel regenerated.
5. This document.

Per direct instruction's own framing: **the 54-unknown-build-config problem is resolved (50/54,
`BUILD_CONFIG_RECONSTRUCTION_RESULTS.md`), and Nan is now genuinely wired, validated, and frozen
-- not merely sitting on a separate branch.** The Nan Resource Guard is ready to stand alongside
R04/R05/R06 as a permanent, always-enabled member of the Resource Guard family
(`six_property_aggregator.NAN_KEYS`) going forward. Freezing this means: no further changes to
`resource_guard_verdict_nan.py`'s own contract logic, `applicability_gate._nan_applicable()`, or
`adjudication_registry.py`'s shared loop are expected as part of THIS integration effort --
future changes (a new contract, a new tier) are a new, separately-scoped round, following the
same real-evidence discipline this one used throughout.

Next: roadmap steps 6-9 (remaining reachability paths for callback/worker registration and
module-load execution; the two known structural false-positive families -- lock-primitive
wrapper recognition and OOB cross-variable type/extent equivalence; the 11 specialized JS/TS
analyzer classes, integrated and validated one at a time with a 100-package replay after each;
and only then, the full 494-package corpus run).
