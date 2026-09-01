# TASK #34 rejection funnel + OOB_INDEX_WRITE stratified audit

Re-analysis of task #34's own real replay output (`results/replay_records.jsonl`, 97 packages, `develop @ fdb22fa5af01cbaab9577d85906f0a33515f0e62`). No new scan, no new download, no recomputation of `reportable` -- every bucket below is read directly from fields the real pipeline already set.

## Cross-language linker: already current, not stale (answering directly)

Task #34's replay never reused any bundle's own captured `cross_language_bindings.json` (that file was written at overnight-run capture time, by an earlier revision of the linker, and predates task #46/#47). `replay_100_bundles.py` does not load that file into a record at all -- `reachability_tier.classify_record_reachability(record, js, cpp)` computes registration and linkage FRESH, every single time, straight from each package's own preserved `js_facts.json`/`cpp_facts.json`, via `reachability_tier.py`'s own live `import link_napi_facts` -- the SAME current, `develop`-checked-out FIX01I linker this analysis's own deep-dive below reuses. There was no stale link output to recompute away from; this was already true for the original replay.

## Headline correction

3,918 raw scanner records is not 3,918 vulnerabilities. Zero reportable records does not mean 97 packages are safe. Every raw record failed at least one required evidence gate -- this section shows exactly which one, per property, so precision work can target the actual bottleneck rather than guess at it.

## Per-property rejection funnel

| Property | Raw | NOT_A_CANDIDATE | PROVENANCE_UNRESOLVED | STAGE_NOT_ENABLED | INSUFFICIENT_REACHABILITY | APPLICABILITY_NOT_DETERMINED | CONFIRMED_FALSE_POSITIVE | REPORTABLE |
|---|---|---|---|---|---|---|---|---|
| R04 (comparison diagnostic) | 2 | 2 | 0 | 0 | 0 | 0 | 0 | 0 |
| R05 (comparison diagnostic) | 7 | 2 | 0 | 0 | 0 | 5 | 0 | 0 |
| FALLIBLE_BOUNDED_RESOURCE (R06/FIX01I, driven) | 7 | 2 | 0 | 0 | 0 | 5 | 0 | 0 |
| LOCK_BALANCE | 12 | 0 | 0 | 0 | 12 | 0 | 0 | 0 |
| PROTECTED_FIELD | 233 | 0 | 0 | 0 | 233 | 0 | 0 | 0 |
| OOB_WRITE | 252 | 0 | 0 | 0 | 252 | 0 | 0 | 0 |
| OOB_INDEX_WRITE | 3290 | 0 | 0 | 0 | 3290 | 0 | 0 | 0 |
| OOB_READ | 115 | 0 | 0 | 0 | 115 | 0 | 0 | 0 |
| OOB_COMPARE | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

**Reading this table:** `PROVENANCE_UNRESOLVED` is 0 everywhere -- task #34's own refetch-and-verify closed that bottleneck completely (confirmed already in TASK34_RESULTS.md: 3,918/3,918 resolved). The real bottleneck for the five staged properties is overwhelmingly `INSUFFICIENT_REACHABILITY` (no established JS-reachability evidence -- `TIER_INTERNAL_UNREGISTERED` or `REACHABILITY_UNRESOLVED`); for R04/R05/R06 it is `NOT_A_CANDIDATE` (the scanner's own verdict logic never classified most of that small raw count as a real candidate to begin with -- abstentions and confirmed-safe matches, not gated-out positives).

### Sub-reason detail (what's actually inside each bucket)

**R04 (comparison diagnostic)**
- NOT_A_CANDIDATE: VALUE_ACQUISITION_SEMANTICS_UNRESOLVED=2

**R05 (comparison diagnostic)**
- NOT_A_CANDIDATE: VALUE_ACQUISITION_SEMANTICS_UNRESOLVED=2
- APPLICABILITY_NOT_DETERMINED: NOT_YET_DETERMINED=5

**FALLIBLE_BOUNDED_RESOURCE (R06/FIX01I, driven)**
- NOT_A_CANDIDATE: VALUE_ACQUISITION_SEMANTICS_UNRESOLVED=2
- APPLICABILITY_NOT_DETERMINED: NOT_YET_DETERMINED=5

**LOCK_BALANCE**
- INSUFFICIENT_REACHABILITY: TIER_INTERNAL_UNREGISTERED=11, REACHABILITY_UNRESOLVED=1

**PROTECTED_FIELD**
- INSUFFICIENT_REACHABILITY: TIER_INTERNAL_UNREGISTERED=233

**OOB_WRITE**
- INSUFFICIENT_REACHABILITY: TIER_INTERNAL_UNREGISTERED=244, REACHABILITY_UNRESOLVED=8

**OOB_INDEX_WRITE**
- INSUFFICIENT_REACHABILITY: TIER_INTERNAL_UNREGISTERED=3165, REACHABILITY_UNRESOLVED=125

**OOB_READ**
- INSUFFICIENT_REACHABILITY: TIER_INTERNAL_UNREGISTERED=113, REACHABILITY_UNRESOLVED=2

## R06 (FALLIBLE_BOUNDED_RESOURCE) rejection breakdown, explicit

R06's 7 raw records are outside `reachability_tier.py` entirely (its own module docstring: it deliberately never touches `r04_findings`/`r05_findings`/`r06_findings` -- Resource Guard's reachability question, when it has one, is a separate, narrower question `promote_via_js_linkage.py` answers, not this pipeline's `stage_status`/reachability gate). R06's own 7 records split exactly in two:
- **NOT_A_CANDIDATE: 2** -- verdict breakdown: VALUE_ACQUISITION_SEMANTICS_UNRESOLVED=2. These never entered the candidate pool at all -- `VALUE_ACQUISITION_GUARD_MISSING` is the only verdict `PROPERTY_CANDIDATE_RULES` treats as a candidate; the rest (here, real abstentions/confirmed-safe matches from `resource_guard_verdict_r06.py`'s own contract logic) are correctly excluded before `scanner_candidate` is even considered.
- **APPLICABILITY_NOT_DETERMINED: 5** -- applicability_status breakdown: NOT_YET_DETERMINED=5. These ARE real `VALUE_ACQUISITION_GUARD_MISSING` candidates (`scanner_candidate=True`) with resolved provenance -- the SAME 5 real candidates R05 also produces (R06 shares R05's verdict-construction logic byte-for-byte). They stay non-reportable purely because `applicability_status` defaults to `NOT_YET_DETERMINED` and nothing in this pipeline ever affirmatively sets it to `APPLICABLE` for a real corpus finding -- a real, disclosed gap (task #41's own docstring: no separate, affirmative applicability step exists yet), not a reachability question at all. This is the SAME structural gap the node-libcurl regression in `check_provenance.py` exercises on a single real finding -- here it is confirmed across all 5 of this replay's own real R06 candidates, not just one.

## OOB_INDEX_WRITE stratified audit (3,290/3,918 raw records -- 84% of everything this replay produced)

- Raw records: **3290** across **34** packages, **1254** distinct (package, function) sites, **518** distinct files.
- Mean raw findings per function site: **2.62** -- the volume is NOT one-finding-per-distinct-bug-location; it concentrates in functions that produce many findings each (see top sites below).
- Reachability distribution (real, from `reachability_tier.py`): REACHABILITY_UNRESOLVED=125, TIER_INTERNAL_UNREGISTERED=3165 -- **0 of 3290 have ANY established JS-reachability evidence.** Every single OOB_INDEX_WRITE candidate in this 97-package sample is either `TIER_INTERNAL_UNREGISTERED` (the function exists but is never registered/callable from JS under any idiom this pipeline recognizes) or `REACHABILITY_UNRESOLVED`.
- Provenance hint: PACKAGE_OWNED=1160, VENDORED=2130.
- Vendored-code deduplication for this property specifically: **2130 raw vendored exposures -> 2036 deduplicated real code sites** (not the whole-replay aggregate -- this property's own real number). Vendored dedup collapses only a modest fraction here (~4%) -- most of the volume is NOT the same vendored file repeated across packages, it is many DISTINCT sites, largely within a small number of vendored libraries (see below).
- Derivation rule: CPP_FIXED_ARRAY_INDEX_UNBOUNDED=1980, CPP_PARAM_LENGTH_PAIR_INDEX_UNBOUNDED=1310
- Capacity source: SYNTACTIC_ELEM_COUNT=1980, PARAM_LENGTH_PAIR=1310

### Top vendored libraries this volume comes from

- opus: 795
- sqlite-amalgamation-3530400: 456
- PQClean: 441
- lodepng.cc: 151
- abseil-cpp: 76
- librdkafka: 61
- cld: 58
- winpty: 50
- re2: 21
- snap7: 7
- libffi: 6
- rtaudio: 5
- core: 3

### Top 15 (package, function) sites by raw finding count -- where the volume actually concentrates

| Package | Function | File | Raw findings | Distinct array names indexed |
|---|---|---|---|---|
| @appthreat/sqlite3 | SHA1Transform | deps/sqlite-amalgamation-3530400/shell.c | 256 | block |
| @huxinhai/mmkv | openssl.AES_encrypt:void(uint8_t*,uint8_t*,openssl.AES_KEY*) | MMKV/Core/aes/openssl/openssl_aes_core.cpp | 48 | Te0, Te1, Te2, Te3 |
| @huxinhai/mmkv | openssl.AES_decrypt:void(uint8_t*,uint8_t*,openssl.AES_KEY*) | MMKV/Core/aes/openssl/openssl_aes_core.cpp | 48 | Td0, Td1, Td2, Td3, Td4 |
| @flyskywhy/react-native-gcanvas | rgba8ToPixel | core/android/png/thirdparty/lodepng.c | 24 | out |
| @flyskywhy/react-native-gcanvas | rgba8ToPixel:unsigned int(unsigned char*,size_t,LodePNGColorMode*,ColorTree*,unsigned char,unsigned char,unsigned char,unsigned char) | node/third_party/lodepng.cc | 24 | out |
| @flyskywhy/react-native-gcanvas | rgba16ToPixel | core/android/png/thirdparty/lodepng.c | 20 | out |
| @flyskywhy/react-native-gcanvas | getPixelColorRGBA8 | core/android/png/thirdparty/lodepng.c | 20 | in |
| @flyskywhy/react-native-gcanvas | getPixelColorsRGBA8 | core/android/png/thirdparty/lodepng.c | 20 | in |
| @flyskywhy/react-native-gcanvas | getPixelColorRGBA16 | core/android/png/thirdparty/lodepng.c | 20 | in |
| @flyskywhy/react-native-gcanvas | rgba16ToPixel:void(unsigned char*,size_t,LodePNGColorMode*,shortunsigned,shortunsigned,shortunsigned,shortunsigned) | node/third_party/lodepng.cc | 20 | out |
| @flyskywhy/react-native-gcanvas | getPixelColorRGBA8:void(unsigned char*,unsigned char*,unsigned char*,unsigned char*,unsigned char*,size_t,LodePNGColorMode*) | node/third_party/lodepng.cc | 20 | in |
| @flyskywhy/react-native-gcanvas | getPixelColorRGBA16:void(shortunsigned*,shortunsigned*,shortunsigned*,shortunsigned*,unsigned char*,size_t,LodePNGColorMode*) | node/third_party/lodepng.cc | 20 | in |
| @huxinhai/mmkv | openssl.AES_set_decrypt_key:int(uint8_t*,int,openssl.AES_KEY*) | MMKV/Core/aes/openssl/openssl_aes_core.cpp | 20 | Td0, Td1, Td2, Td3, Te1 |
| re2 | AesRound:Vector128(Vector128&,Vector128&) | vendor/abseil-cpp/absl/random/internal/randen_slow.cc | 16 | te0, te1, te2, te3 |
| @appthreat/sqlite3 | jsonTranslateTextToBlob | deps/sqlite-amalgamation-3530400/sqlite3.c | 14 | jsonIsOk, sqlite3CtypeMap |

### Interpretation

The single top function site alone accounts for 256 of 3290 raw records (7.8%), and the top 15 sites account for 590 (17.9%). Combined with 0% established reachability across the entire property, this is real evidence pointing toward a BROAD MATCHING PATTERN rather than a set of independently interesting candidates: `CPP_FIXED_ARRAY_INDEX_UNBOUNDED` fires on every syntactically-unbounded fixed-array index it can see structurally, which concentrated, dispatch-table-shaped C code (the classic vendored-library idiom: a fixed-size lookup/register array indexed many times across one function, e.g. an ABI-dispatch or opcode table) will produce in bulk regardless of whether any individual index is ever attacker-influenced. This is NOT evidence the detector is wrong (its own controls, oob_write_controls.py/oob_read_controls.py-style positive/negative fixtures, are unaffected by this finding) -- it is evidence that, at 97-package scale, this property's REAL precision bottleneck is reachability concentration in a small number of vendored dispatch-table functions, not a provenance or scanner-candidate problem. A precision pass before the remaining 394 packages should prioritize: (1) manual review of the top concentrated sites above to confirm they are genuinely non-JS-reachable internal dispatch tables (not a reachability-classifier gap); (2) whether a per-function or per-array-name volume cap / dedup-by-(function, rule) key would materially change the corpus-wide picture without discarding real distinct sites; (3) whether the 3-4 top vendored libraries above are worth a targeted reachability re-check before any wider run.

## Reachability deep-dive: beyond registration + direct call

`reachability_tier.py`'s own 4-tier classification is explicitly scoped (its own module docstring) to registration + a real, direct JS call -- "this module does not attempt a transitive native call-graph walk." This section closes that gap for all 3,902 staged rejects, using ONLY preserved bundle evidence (`cpp_facts.json`'s own already-resolved `candidate_target_ids` call edges + `arguments[].kind == METHOD_REF` function-reference arguments) -- no new Joern run, no source re-download.

- **97** packages replayed; **22** have at least one confirmed native registration (exports.Set / InstanceMethod / Nan::SetPrototypeMethod-Export), **75** have zero registered exports at all under any idiom this pipeline recognizes.

| Deep-dive bucket | Count | % of 3,902 |
|---|---|---|
| GENUINELY_INTERNAL | 3766 | 96.5% |
| CALLBACK_OR_WORKER_HEURISTIC | 124 | 3.2% |
| MODULE_LOAD_EXECUTION_HEURISTIC | 7 | 0.2% |
| TRANSITIVELY_CALLED_FROM_REGISTERED | 5 | 0.1% |

| Property | CALLBACK_OR_WORKER_HEURISTIC | GENUINELY_INTERNAL | MODULE_LOAD_EXECUTION_HEURISTIC | TRANSITIVELY_CALLED_FROM_REGISTERED |
|---|---|---|---|---|
| LOCK_BALANCE | 3 | 6 | 0 | 3 |
| OOB_INDEX_WRITE | 104 | 3183 | 3 | 0 |
| OOB_READ | 0 | 115 | 0 | 0 |
| OOB_WRITE | 11 | 235 | 4 | 2 |
| PROTECTED_FIELD | 6 | 227 | 0 | 0 |

**Reading this:** `DIRECTLY_REGISTERED` does not appear -- correctly 0, since these are exactly the candidates that already failed direct registration in the original tier. `TRANSITIVELY_CALLED_FROM_REGISTERED` (a real, resolved call-graph path from SOME registered export reaches this candidate, even if not directly) is vanishingly small (5/3,902). `CALLBACK_OR_WORKER_HEURISTIC` (124) is a real, disclosed heuristic (a best-effort name+scope match, same discipline as the existing InstanceMethod matcher, never a certainty) -- worth targeted manual review, not proof of reachability. Even after this deeper analysis, **3766/3,902 (96.5%) show no real, resolved path from any registered export, transitive caller, callback reference, or the addon's own Init entry point.** This substantially strengthens, rather than weakens, the reachability-driven interpretation: it is not a shallow artifact of `reachability_tier.py`'s own narrower scope -- a real call-graph walk confirms the same picture at corpus scale.

## Root cause of the 136 REACHABILITY_UNRESOLVED cases (stratified, not sampled thin)

By property: OOB_INDEX_WRITE=125, OOB_WRITE=8, OOB_READ=2, LOCK_BALANCE=1
By package: @huxinhai/mmkv=135, uiohook-napi=1

**135/136 (99.3%) of all REACHABILITY_UNRESOLVED cases trace to a SINGLE package: `@huxinhai/mmkv`.** This is not a diffuse, systemic classifier gap across many packages -- it concentrates almost entirely in one. Root cause, confirmed directly against this package's own preserved `js_facts.json` (not assumed):

| Package | Unresolved count | js calls | cpp functions | facts_available |
|---|---|---|---|---|
| @huxinhai/mmkv@0.1.7 | 135 | 0 | 1325 | False |
| uiohook-napi@1.5.5 | 1 | 0 | 459 | False |

`@huxinhai/mmkv`'s own bundled `js_facts.json` records **zero JS calls at all** -- `reachability_tier.classify_function_reachability()`'s own `facts_available` guard (`bool(js['calls']) and bool(cpp['functions'])`) correctly, fails-closed, marks every single one of this package's own real C++ candidates REACHABILITY_UNRESOLVED, regardless of how many real candidates the C++ side alone produced -- not a guess, a real disclosed data gap on this one package's own JS facts extraction (its own top-level JS entry point may genuinely make no native-binding calls directly, or the JS facts extraction for this specific package came back thin -- worth a targeted, single-package re-check, not a corpus-wide reachability_tier.py fix).

## Determinism verification (actual second run, not asserted from design)

*Not yet run for this build -- see `verify_determinism.py`.*

---
*This analysis adds no new scanning and changes no gate. `develop` remains unmodified in behavior; this is read-only reporting over task #34's own already-committed output.*