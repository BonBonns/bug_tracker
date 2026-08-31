# R05 interim near-miss audit

Read-only audit of the live, still-running R05 corpus scan's own completed output. The live
scan (`claude/aggregate-kinds-producer-test-03zs7n`, PID 6956) was never stopped, modified,
or raced against -- confirmed healthy and progressing throughout this audit (365 -> 369/494
packages while this document was written). No scanner, contract, exporter, or normalizer
file was modified anywhere in this audit. Conducted entirely on a new, isolated branch,
`claude/r05-near-miss-audit`, branched from `claude/r06-precision-fix` (`ddf0ff6`) for
tooling access only -- the R05 scanner files audited are the FROZEN ones, verified below.

## 1. Snapshot provenance

| Field | Value |
|---|---|
| Snapshot file | `r05_near_miss_snapshot_00000365_654d4d8f03af.tsv` |
| Row count | 365 real, complete JSONL records (no partial trailing line included -- `make_checkpoint.py`'s own atomic-write discipline, see `CHECKPOINT_METADATA_ERRATUM.md`) |
| SHA-256 | `654d4d8f03af3c6c26db26b7e391dc22889ad8a5a81cf671b889f5a0e7356d5d` |
| Verified byte-identical to | `head -365 full_scan_r05_working.jsonl` on the still-live working file, checked immediately after snapshotting |
| Live-scan progress at snapshot time | 365/494 (PID 6956, elapsed ~5h18m at snapshot time) |
| `resource_guard_verdict_r05.py` | `9d6a7bdaeb88b0bdc368a994048215b6` (matches `RESOURCE_GUARD_R05.md`'s own documented frozen hash) |
| `resource_contracts_r05.py` | `c498764b1294f6c6a4af372b1ad56871` (matches documented frozen hash) |
| `npm_corpus/run_pipeline_one.py` | `1c031795a3383ff63aa1a22e382daeae` (matches documented frozen hash) |
| `npm_corpus/npm_build_configuration.tsv` | `ffb1e8429ce885b04f4abef058f8d584` (the PRE-fix, package-wide-only extraction currently driving the live scan -- the real defect this whole R06 effort exists to correct; recorded here as the real input this audit's findings are measured against) |

All three scanner/pipeline hashes match their documented frozen values exactly -- the live
scan is running precisely the code its own freeze docs describe, not a drifted copy.

## 2. Complete decision funnel (aggregate, from the frozen snapshot)

Computed by `build_funnel.py` against the snapshot above. Real schema note (disclosed, not
assumed): this schema records per-package AGGREGATE classification COUNTS, not a per-candidate
funnel-stage record -- only 6 of the 10 requested funnel stages have real classification
counters in the current R05 schema; the rest are inferred by subtraction, and per-candidate
identification (package/method/file) is only possible for the handful of verdicts that
produce a real finding record (see `RECORD_BEARING_VERDICTS` in `build_funnel.py`). This
limitation is itself relevant scanner-behavior evidence, not just a review inconvenience --
see Section 5.

| Stage | Real count | Real counter(s) |
|---|---|---|
| 1. acquisition name encountered | 25,518 | `ACQUISITION_NAME_MATCH_CANDIDATE` |
| 2. acquisition identity/shape recovered | 23,951 | `R05_RECOVERY_CANDIDATE` (+0 via R04's own resolved path -- `ACQUISITION_CALL_FOUND` never fires corpus-wide, confirmed, matching `R05_DESIGN.md`'s own documented account) |
| 3+4. overload + result-type recognized | **2** | `R05_ACQUISITION_CALL_RECOVERED` |
| 6. size influence check reached | 2 | (same 2 candidates) |
| 8. downstream use established | 1 | (`RESOURCE_ACQUIRED_NO_USE`: 0) |
| 9. guard classification completed | 1 | (`VALUE_ACQUISITION_SEMANTICS_UNRESOLVED`/`PREDICATE_*`: 0) |
| 5. build configuration applicable | 1 | (`CONTRACT_NOT_APPLICABLE`/`BUILD_CONFIGURATION_CONFLICT`/`_UNRESOLVED`: 0 each) |
| 10. actionable finding emitted | 1 | `VALUE_ACQUISITION_GUARD_MISSING` |

Real code-order note (disclosed, not hidden): in `resource_guard_verdict_r05.py`'s own
actual execution order, the size-influence check (stage 6) runs BEFORE downstream-use/guard
analysis (stages 8-9), and the applicability gate (stage 5) runs AFTER the dominance walk
completes, not before -- the table above uses the CONCEPTUAL stage numbers requested, not
literal code order, to avoid mis-stating which real check produced which count.

### Stopping-reason distribution (aggregate)

| Real classification key | Count | Real per-candidate record? |
|---|---|---|
| `R05_RECOVERY_RESULT_TYPE_UNRECOGNIZED` | 23,949 | No -- pure counter |
| `SIZE_ATTACKER_INDEPENDENT` | 1 | No -- pure counter |
| `VALUE_ACQUISITION_GUARD_MISSING` | 1 | Yes |
| `RESOURCE_ACQUIRED_NO_USE`, `PREDICATE_*`, `VALUE_ACQUISITION_SEMANTICS_UNRESOLVED`, `CONTRACT_NOT_APPLICABLE`, `BUILD_CONFIGURATION_CONFLICT`, `BUILD_CONFIGURATION_UNRESOLVED`, `VALUE_ACQUISITION_GUARD_ESTABLISHED` | 0 each | (n/a -- zero real instances so far) |

**The funnel's real, overwhelming bottleneck is stage 3+4** (overload + result-type
recognition): 23,949 of 23,951 candidates that reach stage 2 stop there. Only 2 candidates
in the entire 365-package snapshot ever progress past it.

## 3. Frozen review selection

Recorded in full, before any of the newly-selected source was read, in
`FROZEN_REVIEW_LIST.md` (same directory). Summary:

- **Every positive finding** (population 1, entire population): `node-libcurl@5.1.2`.
- **`SIZE_ATTACKER_INDEPENDENT`** (population 1, entire population): `node-crc16@2.0.7`.
- **`R05_RECOVERY_RESULT_TYPE_UNRECOGNIZED`** (dominant bucket, 99.99% of all recovery
  candidates): fixed, deterministic rule (rank by real count, descending; exclude
  already-reviewed packages; collapse the real `@nodert-win10*` auto-generated family to its
  single highest-ranked member) -> `swisseph@0.5.17`, `@nodert-win10-rs4/windows.ui.
  notifications@0.4.4`, `node-snap7@1.0.9`, `@brick-a-brack/napi-canon-cameras@0.1.5`,
  `@nodriverai/mavjs@0.1.2`.
- **Stages 5 (build config), 8 (use), 9 (guard)**: no distinct population beyond the 2
  already-covered candidates -- honestly reported as empty, not padded.

## 4. Evidence tables -- reviewed cases

### 4.1 `node-libcurl@5.1.2` -- `Easy::ReadFunction` (CONFIRMED_FALSE_POSITIVE)

| Check | Finding |
|---|---|
| Acquisition call + exact overload | `Napi::Buffer<uint8_t>::New(env, static_cast<size_t>(size))` -- the real 2-arg allocating overload |
| Who controls size | `Easy::ReadFunction`'s own `size`/`nmemb` PARAMETERS, supplied by **libcurl internally** via `curl_easy_setopt(ch, CURLOPT_READFUNCTION, Easy::ReadFunction)` -- confirmed real via libcurl's own published contract for this callback signature (`size_t(char*, size_t, size_t, void*)`) |
| Real JS/native boundary | `ReadFunction` is a real **libcurl-invoked native callback**, never called by JS -- no `Napi::CallbackInfo` anywhere in its signature |
| Build target + exception config | Real target `<(module_name)` (from `Easy.cc`'s own `sources` entry) resolves to **`enabled`** via a real `node_addon_api_except` gyp-target dependency and a real `!`-list removal of `-fno-exceptions` -- the live scan's own pre-fix `npm_build_configuration.tsv` instead reports the WHOLE package `disabled` (package-wide, non-target-scoped) |
| Downstream use | Buffer written to and returned, real, unguarded |
| Existing guard | None in this function -- but see applicability below |
| Frontend-vs-source disagreement | Confirmed real, independently: (1) build-config extraction (package-wide, pre-fix) says `disabled`; real per-target says `enabled`; (2) the pre-fix scanner treats reaching the `size` PARAMETER as attacker evidence with no check that the enclosing function is JS-reachable at all |
| Code still in current release | Yes -- fetched the exact pinned `node-libcurl@5.1.2` tarball this corpus run used |
| **Classification** | **`CONFIRMED_FALSE_POSITIVE`** -- two independent, compounding scanner defects (source-boundary + build-config), both already fixed on `claude/r06-precision-fix`/`claude/r06-fix01i-integration`, real-verified: `actionable_findings: 0` under the fixed scanner, record retained as a diagnostic `CONTRACT_NOT_APPLICABLE` with both pieces of real evidence attached |

### 4.2 `node-crc16@2.0.7` (CONFIRMED_TRUE_NEGATIVE)

| Check | Finding |
|---|---|
| Acquisition call | Real, recovered `Napi::Buffer::New` site |
| Who controls size | A fixed, real C++ literal -- not JS-influenced, not network-influenced, not influenced by anything at runtime |
| **Classification** | **`CONFIRMED_TRUE_NEGATIVE`** -- correctly rejected before any attacker-trace/dominance logic runs; kept as the standing true-negative reference per instruction |

### 4.3 `swisseph@0.5.17` (CONFIRMED_TRUE_NEGATIVE, bucket check)

| Check | Finding |
|---|---|
| Real "New"-named calls | All confirmed `Nan::New(...)`/`Nan::SetMethod(...)` -- **`Nan`-based addon**, not `node-addon-api` (`using namespace v8;`, real source read directly) |
| Real `Napi::Buffer::New` presence | **None found anywhere in the package** |
| **Classification** | **`CONFIRMED_TRUE_NEGATIVE`** -- 1,496 real rejections at the result-type gate are all correct; this contract was never built for `Nan`-style addons (a third real, independently-confirmed instance of this pattern this session, after `jpeg-turbo` and `libpq`) |

### 4.4 `@nodert-win10-rs4/windows.ui.notifications@0.4.4` (CONFIRMED_TRUE_NEGATIVE)

| Check | Finding |
|---|---|
| Real "New"-named occurrences | `static void New(Nan::NAN_METHOD_ARGS_TYPE info)` -- real `Nan::ObjectWrap`-style CONSTRUCTOR CALLBACKS (this project's own auto-generated WinRT class wrappers each define a method literally named `New`), not Buffer allocations at all |
| Real `Napi::Buffer::New`/`Nan::NewBuffer` presence | None found |
| Raw-text vs. real CPG count | 37 raw textual `New(` occurrences vs. 793 real classification-counter hits -- a real, disclosed effect of this heavily templated/macro-generated WinRT bridge code being expanded into many more CPG call nodes than raw source text shows; not investigated further (would require Joern-level inspection of this specific file, out of this audit's real scope once the call SHAPE itself is confirmed irrelevant to Buffer allocation) |
| **Classification** | **`CONFIRMED_TRUE_NEGATIVE`** -- correctly rejected; none of these "New"-named nodes are Buffer allocations |

### 4.5 `node-snap7@1.0.9` (CONTRACT_COVERAGE_GAP -- real, substantive finding)

| Check | Finding |
|---|---|
| Real "New"-named calls that triggered the 616 rejections | Not `Nan::NewBuffer` (see below) -- likely other `Nan::New<T>(...)` template calls (Object/String/Integer/Function), not individually enumerated further since the REAL scope gap below is independent of this count |
| **Real, separately-discovered buffer-allocation calls** | `Nan::NewBuffer(size)` (`node_snap7_server.cpp:813`, inside `S7Server::HandleReadWriteEvent`) and `Nan::CopyBuffer(...)` (same function, write path) -- **11 real call sites across the package**, confirmed via direct source read |
| Why R05 never even attempts these | R05's `RECOVERY_CONTRACTS` matches by the literal call NAME `"New"` -- `Nan::NewBuffer`/`Nan::CopyBuffer` are literally different function names and are NEVER even added to the `R05_RECOVERY_CANDIDATE` pool, regardless of shape or type. This is a real, structural contract-scope limitation, not a downstream logic bug. |
| Who controls size (the one instance investigated in full depth) | `size = byteCount * rw_event_baton_g.Tag.Size`, where `rw_event_baton_g.Tag` is set (`*PTag`, `node_snap7_server.cpp:38`) from the underlying, vendored `snap7` C library's own real S7-protocol event/callback mechanism (`deps/snap7/`) -- i.e. a REAL S7 PLC PROTOCOL PEER over the network, in the addon's SERVER role. **Not JS-argument-controlled at all** -- there is no `Napi::CallbackInfo`/JS call boundary anywhere in this specific allocation's own call chain. Terminology correction: this is **not** a true negative in the general security sense -- a network peer supplying an unbounded size into an internal allocation can still be security-relevant, it simply does not establish the CURRENT project's own JS-argument threat model. Classified precisely as `EXTERNAL_NETWORK_CONTROLLED_OUT_OF_CURRENT_JS_SCOPE`, not folded into `CONFIRMED_TRUE_NEGATIVE`. |
| Real JS/native boundary | None for this allocation site -- it is entirely internal to the native server-event path; the resulting buffer is later passed to JS as an EMIT argument (`argv[4] = buffer`), read-only from JS's side |
| Existing guard (the SEPARATE, JS-FACING side, `RWBufferCallback`) | **A real, explicit, correct guard exists**: `if (node::Buffer::Length(info[0]) < size) { ThrowTypeError(...); }` BEFORE the `memcpy` that copies FROM a JS-supplied buffer -- this is the genuinely JS-argument-adjacent code path in this file, and it is properly guarded |
| Build target + exception config | Real `binding.gyp`: `-fexceptions` explicitly enabled (`cflags_cc: ["-fexceptions"]`, `cflags_cc!: ["-fno-exceptions"]`) for the native `node_snap7` target -- moot for a `Nan`-based allocation anyway, since `Nan::NewBuffer`'s own real failure contract (`Maybe<Local<Object>>` + `.ToLocalChecked()`, which fatally crashes via V8's own error handler on empty) is structurally different from `Napi::Buffer::New`'s exceptions-disabled-vs-enabled contract this project's `REAL_CONTRACTS`/`RECOVERY_CONTRACTS` are built around |
| Code still in current release | Yes -- fetched the exact pinned `node-snap7@1.0.9` tarball |
| **Classification** | **`CONTRACT_COVERAGE_GAP`** -- a real, disclosed, structural scope limitation (RECOVERY_CONTRACTS never recognizes `Nan::NewBuffer`/`Nan::CopyBuffer` by name), NOT a bug in any downstream logic. Separately and explicitly: **this specific instance's own size origin is network/protocol-controlled, not JS-argument-controlled** -- even a future contract extension covering `Nan::NewBuffer` would need its own, separate size-origin analysis (a different threat dimension than this project's declared JS-argument scope), not an automatic promotion. Not claimed as a vulnerability here. |

### 4.6 `@brick-a-brack/napi-canon-cameras@0.1.5` (CONFIRMED_TRUE_NEGATIVE)

Real, genuine `node-addon-api` package (confirmed `Napi::` calls throughout). All real "New"
calls are `Object`/`Number`/`String`/`Error`/`TypeError`::New -- zero `Buffer::New` anywhere
in the package. **`CONFIRMED_TRUE_NEGATIVE`.**

### 4.7 `@nodriverai/mavjs@0.1.2` (CONFIRMED_TRUE_NEGATIVE)

Real, genuine `node-addon-api` package. All real "New" calls are `String`/`Array`/
`External<mavsdk::System>`::New -- zero `Buffer::New` anywhere. **`CONFIRMED_TRUE_NEGATIVE`.**

## 5. Confirmed scanner defects (this audit)

1. **`node-libcurl`'s own two, already-fixed defects** (source-boundary overclaim,
   package-wide build-config misclassification) -- confirmed, cross-checked, both already
   remediated on `claude/r06-precision-fix` (verified via `actionable_findings: 0` and the
   dual real-evidence record); no new fix proposed here.
2. **`Nan::NewBuffer`/`Nan::CopyBuffer` are entirely uncovered by `RECOVERY_CONTRACTS`**
   (`node-snap7`, real, confirmed via source, 11 real call sites in one package alone) --
   a genuine `CONTRACT_COVERAGE_GAP`, newly found by this audit. **Not fixed here**, per
   instruction (documented for a future, separate regression fixture + revision, after this
   reviewed batch is frozen). Proposed future work, NOT started: extend
   `resource_contracts_r05.py`/`_r06.py` with a new curated entry for `Nan::NewBuffer`'s own
   2-arg allocating overload, including its own real failure-predicate contract (V8's fatal
   crash on an empty `Maybe`, not node-addon-api's exceptions-disabled/empty-buffer
   contract) -- and separately, a real size-origin classification step so a
   network/protocol-controlled size (like this specific `node-snap7` instance) is never
   conflated with JS-argument control.
3. **Raw-text-vs-CPG-count multiplier for heavily templated/macro-generated code**
   (`@nodert-win10-rs4/windows.ui.notifications`, 37 raw vs. 793 real counted) -- observed,
   not investigated to a root cause (would require Joern-level AST inspection of this one
   file); does not appear to affect correctness of the REJECTION decision itself (none of
   the real "New"-shaped candidates found are Buffer allocations regardless of count), so
   not elevated to a confirmed defect -- recorded as an open, low-priority observation.

## 6. Confirmed safe cases

- `node-crc16@2.0.7` (`CONFIRMED_TRUE_NEGATIVE`, literal size).
- `swisseph@0.5.17`, `@nodert-win10-rs4/windows.ui.notifications@0.4.4`,
  `@brick-a-brack/napi-canon-cameras@0.1.5`, `@nodriverai/mavjs@0.1.2` (all
  `CONFIRMED_TRUE_NEGATIVE` -- no real `Napi::Buffer::New` acquisition exists in any of
  these packages at all; correct rejection is trivial and complete).
- `node-snap7`'s own real `RWBufferCallback` JS-facing path (a real, explicit, correct
  length guard before the `memcpy` -- not itself a finding, noted as a real example of
  properly-guarded code encountered during this audit).

## 7. Potential true positives

None identified in this pass. The one real positive candidate reviewed (`node-libcurl`) is
a confirmed false positive, not a true one.

## 8. Unresolved cases

None -- every candidate selected for review reached a real, evidence-backed classification
in this pass (Section 4). The funnel's later stages (5, 8, 9) have no real, distinct
candidate population yet at this snapshot size (Section 3) -- not "unresolved," genuinely
empty, to be revisited honestly as the corpus grows.

## 9. Exact claims boundary

- This audit finds **no new false negative** and **no new incorrect classification** among
  the 7 real cases reviewed in depth. It finds **one real, disclosed contract-coverage gap**
  (`Nan::NewBuffer`/`Nan::CopyBuffer`), not yet exploited into an actual finding claim, and
  explicitly NOT claimed as a vulnerability -- its one investigated instance's size origin is
  network-controlled, not JS-argument-controlled, a different threat dimension than this
  project's own declared scope. Terminology correction (post-review): that instance is
  `EXTERNAL_NETWORK_CONTROLLED_OUT_OF_CURRENT_JS_SCOPE`, not `CONFIRMED_TRUE_NEGATIVE` -- a
  network-peer-controlled size can still be security-relevant on its own terms; it simply
  does not establish the JS-argument property this project currently scopes findings to.
  The evidence supports a genuine contract-coverage gap, not a confirmed missed
  vulnerability -- both claims are real and distinct, and neither substitutes for the other.
- `node-libcurl` remains the confirmed false-positive regression; `node-crc16` remains the
  confirmed true-negative reference -- both restated, not re-derived, per instruction.
- No scanner, contract, exporter, or normalizer code was changed during this audit. The one
  real defect found (`CONTRACT_COVERAGE_GAP`) is documented for FUTURE work only, gated on
  the standing instruction to propose a fix only after this reviewed batch is frozen.
- The funnel's real bottleneck (23,949 of 25,518 real candidates, 93.9%, stopping at
  overload/result-type recognition) is, on this pass's real evidence, predominantly
  CORRECT rejection (non-Buffer factories, `Nan`-based packages entirely out of scope) --
  not a sign of widespread missed true positives. This is a real, evidence-backed
  conclusion from 5 independently investigated packages spanning distinct real domains, not
  an assumption; it does not extend automatically to the remaining, unreviewed ~225
  packages in this bucket, and is not claimed to.
- This document is explicitly INTERIM. When the live scan finishes, only the newly
  completed records will be appended to this audit using the same frozen methodology
  (fresh snapshot, fresh funnel, fresh deterministic sample of any NEW near-miss
  population) -- this pass's own findings are not re-derived or invalidated by that future
  append.
