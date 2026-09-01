# TASK #34 rejection funnel + OOB_INDEX_WRITE stratified audit

Re-analysis of task #34's own real replay output (`results/replay_records.jsonl`, 97 packages, `develop @ fdb22fa5af01cbaab9577d85906f0a33515f0e62`). No new scan, no new download, no recomputation of `reportable` -- every bucket below is read directly from fields the real pipeline already set.

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

---
*This analysis adds no new scanning and changes no gate. `develop` remains unmodified in behavior; this is read-only reporting over task #34's own already-committed output.*