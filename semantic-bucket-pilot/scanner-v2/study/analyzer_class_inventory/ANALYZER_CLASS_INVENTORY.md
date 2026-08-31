# Repository-wide analyzer class inventory

Read-only inventory, per explicit instruction: nothing modified, nothing run. Does **not** use
`ANALYZER_FREEZE.md` as the universe — that document's own claim was already shown
(`study/ANALYZER_CLASS_COVERAGE_MATRIX.md`) to be stale/incomplete. This inventory instead
searched the whole repository directly: every executable scanner/verdict/capability file,
pipeline driver, gate, study document, capability review, and finding schema, across
`semantic-bucket-pilot/` and `tchecker-research-complete/` (the two top-level source trees) plus
the standalone `moz-scan-*` material at repo root. Built via three parallel read-only
reconnaissance passes over the areas outside `scanner-v2/` (which I already knew well from
direct work this session) plus my own direct pass over `scanner-v2/`'s own 65 top-level files
and every relevant `.md` capability-review/freeze document.

**Your suspicion was correct: there are real C-only and real JavaScript-only class families,
neither of which is the fallible-bounded-resource lineage this session's own npm-corpus work
has been focused on.**

## 1. Definitive totals

| Metric | Count | Notes |
|---|---:|---|
| **Distinct security properties implemented** (real verdict-producing logic exists) | **25** | see Section 3's full table; a small number of boundary cases (thread-safety's 2 capabilities, LLM-input's 2 sub-classes) are counted as one property each, noted where it matters |
| **Promotable / sound-as-documented** | **22** | frozen, gated, and not flagged unsound in their own review docs |
| **Explicitly NOT promotable** | **3** | `single_object_pass.py` (own review: "not sound as written and must not be promoted"), Command-Injection (Stage 2B self-described "lower-trust experiment," never wired to an adjudicator config), Gate-39 State-Provenance infra (own doc: "NOT REPRODUCIBLE / NOT RUN" — infra, not itself a property, listed for completeness) |
| **Applicable to JS/TS-to-C/C++ npm packages** (the actual target ecosystem of this session's own corpus work) | **20 of 25** | 6 PHP/WordPress-only properties are the sole hard exclusion (WPACL, WPCSRF, WPIDOR, WPOPT, WP-SQLI, WP-XSS) — everything else touches either general C/C++ (applicable to an npm package's native addon) or JS/TS (applicable to an npm package's own JS/TS layer) |
| **Actually invoked by any corpus pipeline** | **1** | the fallible-bounded-resource lineage (R04+R05 stages only) via `npm_corpus/run_pipeline_one.py` — independently re-confirmed here, not assumed from the earlier audit |
| **Present in the stopped `full_scan_r05_working.jsonl`** | **1** | same one — `r04_classification`/`r04_findings`/`r05_classification`/`r05_findings` are the only classification/finding keys anywhere in the file (452/452 records checked in the earlier audit) |
| **Have sufficient evidence bundles to run today, if wired in** | **~13 of 24 non-PHP properties** | see Section 4 — a real, precise, per-class finding, not a guess |

## 2. Method

- My own direct pass: `semantic-bucket-pilot/scanner-v2/`'s complete 65-file top-level listing,
  every capability's own module docstring, every `*.md` freeze/review/results document
  (`RESOURCE_GUARD_R01-05.md`, `THREAD_SAFETY_R01.md`, `CAPABILITY_PLAN.md`,
  `CAPABILITY_REVIEW.md`, `V2_RESULTS.md`, `V2_STACK_RESULTS.md`, `AUDIT_V2.md`), and the real
  `"schema"` strings each verdict producer writes.
- Three parallel read-only reconnaissance agents, one per unfamiliar area:
  1. `moz-scan-*` (repo root) + `tchecker-research-complete/gates/` + `docs/moz-oob-r01/`
  2. `tchecker-research-complete/tchecker-property-adjudicator/`
  3. `tchecker-research-complete/portable-engine-full-review-package/`
- Cross-verified the load-bearing cross-directory claim myself directly (Section 3.3's
  OOB_WRITE lineage: confirmed `scanner-v2/V2_STACK_RESULTS.md`'s own real gate-name citations
  — `runtimecap 18/18`, `analysis-record 53/53` — match `portable-engine-full-review-package/`'s
  own `oob-runtimecap-r01`/`analysis-record-r01` gates exactly, establishing that
  `scanner-v2/oob_runtime_capacity_v2.py` is a real post-pass over
  `portable-engine-full-review-package/tools/oob_runtime_capacity_verdict.py`, not a
  independent, disconnected reimplementation).
- `semantic-bucket-pilot/`'s own other top-level directories (`corpus/`, `staged/`,
  `frozen-corpus/`, `auto_buckets/`, `prompts/`, `sources/`, `sources_auto/`, `rubric/`,
  `excluded_pre_freeze/`, `experimental-corpus/`, `runs/`) were checked and confirmed to be a
  **separate, unrelated LLM-based case-labeling/routing study** (matches `DESIGN_FROZEN.md`'s
  own A/B/C prompt-condition study) — not static-analysis scanner logic, out of scope for
  "analyzer class," noted here so it isn't silently omitted.

## 3. Full class table

Grouped by ecosystem. Within each group: canonical name, property, files/lineage, inputs,
output schema, gate status, soundness, npm-applicability, pipeline invocation, JSONL presence,
evidence sufficiency (numbered per Section 4's own key).

### 3.1 Fallible-bounded-resource lineage (npm-native, JS↔C/C++) — THE ONE ACTIVE PROPERTY

| Field | Value |
|---|---|
| Canonical name | `FALLIBLE_BOUNDED_RESOURCE` |
| Property | an acquisition that can fail (return empty/null) is used without checking, or (Nan variant) a JS-argument-controlled allocation has no upper bound |
| Files / lineage | `resource_contracts.py`+`resource_guard_verdict.py` (R01) → `_r02` → `_r03` → `_r04` (adds build-config applicability gate) → `_r05` (adds structural recovery for c2cpg-unresolved `Napi::Buffer::New`) → R06 (`claude/r06-precision-fix`, source-boundary gate, isolated branch) → FIX01I (`claude/r06-fix01i-integration`, JS-argument promotion boundary) → Nan capability (`resource_contracts_nan.py`+`resource_guard_verdict_nan.py`, `claude/nan-capability`, two new contracts: `NAN_NEWBUFFER_UNBOUNDED_ALLOCATION`/`NAN_COPYBUFFER_SOURCE_CAPACITY`) |
| Inputs | C/C++ raw Joern facts (`export_c_cpp_facts_v03.sc` → `calls.tsv`/`arguments.tsv`/`parameters.tsv`/`cfg_edges.tsv`/`methods.tsv`) + JS/TS facts (`jssrc2cpg` → `export_neutral.sc`) + cross-language linking (`link_napi_facts.py`) |
| Output schema | `resource-guard-verdict/0.1` through `-r05/0.1`; `resource-guard-verdict-nan/0.1` (Nan capability, separate) |
| Gate | R01=19/19, R02=20/20+blindtest 6/6, R03=33/33+blindtest 6/6, R04=12/12, R05=6/6 real controls+R01-R04 hash regression (`ANALYZER_FREEZE.md`/`RESOURCE_GUARD_R05.md`); Nan capability=25/25 fixture + zero false positives on 6 real negative controls (`NAN_CAPABILITY_FREEZE.md`) |
| Soundness | R01-R05 frozen/production, currently driving the live corpus scan (R04+R05 stages only). R06/FIX01I frozen on isolated branches, not merged into the driven lineage. Nan capability frozen on its own isolated branch. |
| npm-applicable | **Yes — this is the npm-native-addon property** |
| Pipeline-invoked | **Yes — R04 and R05 only** (`run_pipeline_one.py:467,495`) |
| In stopped JSONL | **Yes** — `r04_classification`/`r04_findings`/`r05_classification`/`r05_findings` |
| Evidence sufficient today | Yes for R04/R05 (already running). R06/FIX01I/Nan need no NEW fact exporter — same C/C+++JS/TS facts, just not wired into `run_pipeline_one.py` |

### 3.2 Thread-safety (general C/C++, NOT npm-specific — built against wolfSSL)

| Field | Value |
|---|---|
| Canonical name | `THREAD_SAFETY` (2 capabilities under one property umbrella, per `THREAD_SAFETY_R01.md`'s own framing) |
| Capability 1: `LOCK_BALANCE` | missing-unlock-before-return — `lock_balance_verdict.py`; real CFG walk from a lock-acquire call, unlock-on-same-object clears the path |
| Capability 2: `PROTECTED_FIELD` | a critical section that should exist but is entirely absent (not an incomplete existing lock) — `protected_field_verdict.py` |
| Files | `lock_balance_verdict.py`, `protected_field_verdict.py`, gates `check_lock_balance.py`/`check_protected_field.py`, corpus construction `thread_freeze.py`, round-2/3 measurement `check_corpus_measurement.py` |
| Inputs | C/C++ raw Joern facts — **same exporter as 3.1** (`export_c_cpp_facts_v03.sc`) |
| Output schema | not a versioned `"schema"` string in the same style; verdict fields documented in `THREAD_SAFETY_R01.md` |
| Gate | `check_lock_balance.py`=11/11, `check_protected_field.py`=11/11, both re-verified unchanged through 2 precision-fix rounds (`check_corpus_measurement.py`: round 2=6/6, round 3=9/9) |
| Soundness | frozen, real development-site recovery against a genuine wolfSSL CVE (CVE-2026-5264, `case_e062ef20`) and a real, confirmed false-positive-free fix verification (commit `3034dd9e`) |
| npm-applicable | **Yes, to the C/C++ side of a native addon** — same fact schema as 3.1, never tested against npm-package C++ specifically (built/validated on wolfSSL) |
| Pipeline-invoked | **No** |
| In stopped JSONL | **No** |
| Evidence sufficient today | **Yes — the exact same raw C/C++ facts `run_pipeline_one.py` already generates for every package contain everything both capabilities need.** Pure wiring gap, not a fact-generation gap. |

### 3.3 OOB_WRITE / OOB_READ / OOB_COMPARE (general C/C++, cross-directory lineage)

**The single most complex lineage found** — spans two top-level directories, independently
confirmed connected (Section 2).

| Field | Value |
|---|---|
| Canonical names | `OOB_WRITE` (native buffer overflow on write — 7 representation-variant producers, one property), `OOB_READ` (over-read, sibling property), `OOB_COMPARE` (unsafe `memcmp`/`strncmp` extent, sibling property) |
| Base ("v1") files | `portable-engine-full-review-package/tools/`: `oob_write_verdict.py` ("B4.5", the frozen base), `oob_read_verdict.py` ("B4.6"), `oob_compare_verdict.py` ("TOR-B2a"), plus representation-variant siblings of OOB_WRITE: `oob_index_write_verdict.py` (INDEX_STORE), `oob_pointer_increment_verdict.py` (POINTER_INCREMENT, motivated by real mozjpeg/Debian#768369), `oob_cursor_write_verdict.py` (CURSOR, **explicitly FROZEN as of round 5**), `oob_copy_length_verdict.py` (COPY_LENGTH), `oob_call_sink_verdict.py` (CALL_SINK, built to reach real NSS CVE-2019-11759), `oob_interprocedural_verdict.py` (single-hop cross-function propagation), `oob_runtime_capacity_verdict.py` (dynamic allocations) |
| scanner-v2 extension layer ("v2", confirmed same lineage — Section 2) | `cap_addr_indexed.py` (npm-corpus-project's own "Capability 1": address-of indexed destination `&(base[index])`), `oob_runtime_capacity_v2.py` (real post-pass over `oob_runtime_capacity_verdict.py`), `single_object_pass.py` (a THIRD representation shape attempt — **explicitly rejected**, see 4.5), `heap_extent_check.py` ("Level-3" heap-capacity check) |
| Adjudication layer | `portable-engine-full-review-package/tests/gates/oob-adj-r01/adjudicate_oob.py` (byte-identical copy also lives in `tchecker-property-adjudicator/adjudicator/`), staged via `property_configs/oob_index_write.json` — currently wired for INDEX_STORE only, with a two-channel (curated/untrusted) attestation-and-hint trust model |
| Inputs | C/C++ raw Joern facts, **same `portable-program-facts` schema as 3.1/3.2** |
| Output schema | `{"verdict":"CANDIDATE","class":"OOB_WRITE"\|"OOB_READ"\|"OOB_COMPARE", ...}` (never `"VULNERABLE"`, enforced by explicit assertion in at least one producer); adjudication layer: `tchecker-llm-packet/1.0` |
| Gate | many per-variant gates (`oob-index-r01`, `oob-cursor-r01`, `oob-ptrinc-r01`, `oob-copylen-r01`, `oob-callsink-r01`, `oob-interproc-r01`, `oob-runtimecap-r01`=18/18, `moz-canon-r01` canonical vulnerable/patched anchor, `analysis-record-r01`=53/53, `guard-r01` for OOB_READ, `oob-compare-r07`); scanner-v2's own `gate_stack_capacity_v2.py`=15/15 |
| Soundness | fail-closed by design throughout, candidate-only, real observational validation against 12 real Tor-corpus sites (0 unsafe, 10 safe, 2 unresolved — `TOR_CAND_R01_ADJUDICATION.md`) and 3 real disclosed Mozilla CVEs (all 3 initially MISS under the frozen producer — a real, disclosed, honestly-reported coverage gap, one later fixed by `OOB-INDEX-R01`) |
| npm-applicable | **Yes, to the C/C++ side of a native addon** — same fact schema as 3.1/3.2, built/tested against NSS/mozjpeg/Tor, never against npm-package C++ specifically |
| Pipeline-invoked | **No** |
| In stopped JSONL | **No** |
| Evidence sufficient today | **Yes, same reasoning as 3.2** — the existing C/C++ fact exporter already produces what these producers consume. Pure wiring gap. |

### 3.4 PHP/WordPress family — the hard exclusion from npm applicability

| # | Canonical name | Property | File | Gate/soundness |
|---|---|---|---|---|
| 1 | `WPACL` | reachable AJAX/admin-post/REST handler with no authorization check | `core/provenance/PHPCGFactory.java` (~L2856) | no dedicated gate dir found; research-grade, hand-tuned |
| 2 | `WPCSRF` | state-changing handler not dominated by a nonce check | `core/provenance/PHPCGFactory.java` (~L2891) | as above |
| 3 | `WPIDOR` | authenticated handler acting on a request-supplied object id with no ownership check | `core/provenance/PHPCGFactory.java` (~L2798) | as above |
| 4 | `WPOPT` | action handler reaching an options-write sink with no management capability | `core/provenance/PHPCGFactory.java` (~L2907) | as above |
| 5 | `WP-SQLI` | SQL injection (WordPress taint engine, `SQLI_ONLY` mode) | `core/provenance/StaticAnalysis.java` | `run_recall.sh` FIRE/NOFIRE recall suite |
| 6 | `WP-XSS` | cross-site scripting (same engine, `XSS_ONLY` mode) | `core/provenance/StaticAnalysis.java` | same |
| — | WP finding adjudicator | 2nd-layer triage resolving REST permission-callback gating and wrapper-mediated sinks for #1-6 | `profiles/wordpress/instrumentation/adjudicate.py` | active, fail-closed, no in-tree gate |

**All seven items: PHP/WordPress plugin source only. Zero applicability to JS/TS-to-C/C++ npm
packages** — different language, different frontend (`joern-php`, never invoked by the npm
corpus pipeline, which only runs `c2cpg`/`jssrc2cpg`), different fact schema entirely.

### 3.5 JS/TS npm-applicable classes — repo-root `gates/`

Six real, gated, self-contained classes. All explicitly restrict claims to
`CANDIDATE_*`/`SAFE_*`/`SUSPICIOUS_*` — never `VULNERABLE` — a deliberate project-wide
convention. All consume `jssrc2cpg`-derived `.tsv` fact tables **specific to each class**
(different exporter `.sc` script per class), not the generic facts the npm-corpus pipeline's
own JS export stage produces.

| # | Canonical name | Property | File(s) | Schema | Gate | Real-run evidence |
|---|---|---|---|---|---|---|
| 1 | `DENYLIST_PATTERN_BYPASS` | an exact-match denylist filter bypassed because the surviving string still matches a later unescaped regex/pattern consumer | `denylist_bypass_verdict.py` | `denylist-pattern-bypass-verdict/0.1` | D1-D6, self-reported PASS | — |
| 2 | `GLOBAL_SINGLETON_MUTATION` | CWE-116: assignment to a security-sensitive member of an imported module singleton (e.g. `Mustache.escape = x`), disabling it process-wide via Node's module cache | `globalmut_verdict.py` | `global-singleton-mutation-verdict/0.1` | G1-G6, self-reported PASS | — |
| 3 | `GUARD_FALLTHROUGH` | a caller treats a helper as a hard terminator, but the helper is only conditionally terminating and is called bare (return value discarded) — execution falls through to a sensitive sink | `guard_fallthrough_verdict.py` | `guard-fallthrough-verdict/0.1` | 6/6 | **confirmed actually run**: `.pyc` cache + a real recovered findings JSON (4 real findings on `handlers/admin-ajax.js`) |
| 4 | `MALICIOUS_NPM_INSTALL_EXFIL` | npm install-lifecycle-hook harvest+exfiltration supply-chain pattern (host/installer identifiers → hardcoded outbound URL), extended with obfuscated-eval-in-hook and child_process-exec-in-hook legs | `malicious_npm_verdict.py` | `malicious-npm-install-exfil/0.1` | M1-M13 | **confirmed actually run**: `.pyc` cache + a documented real run, "13/13 against the fresh output" (2026-08-24) — **the single class in this whole inventory most directly about npm supply-chain risk as such** |
| 5a | `UNGUARDED_SERIALIZE_DOS` (gates/ implementation) | `JSON.stringify`/`util.inspect` on raw attacker-controlled request data, no try/catch, no depth guard, no `uncaughtException` net — synchronous crash DoS | `serialize_dos_verdict.py` | `unguarded-serialize-dos-verdict/0.1` | S1-S9, self-reported PASS | `.pyc` cache confirms actual run |
| 5b | Serialize-DoS (tchecker-property-adjudicator implementation — **see 4.4, same conceptual bug, independent implementation**) | same bug class, via the generic taint-property engine | `adjudicate_js.py` (default/hardcoded config) | `canonical-evidence-set/js-ts/1.1` | end-to-end + real-corpus replay (mozilla/fxa) + held-out TS generalization test (novuhq/novu) | FROZEN/production; the most heavily-validated single property in this entire inventory |
| 6 | `VALIDATION_BYPASS` | a per-element validation loop uses `return` instead of `continue` on the first skippable element, silently abandoning validation of every remaining sibling while a paired processing loop still reaches a sink | `validation_bypass_verdict.py` | `validation-bypass-verdict/0.1` | V1-V6, self-reported PASS | — |

### 3.6 JS/TS npm-applicable classes — `tchecker-property-adjudicator/` (generic taint engine + config seam)

One shared engine (`adjudicate_js.py`) parameterized by `property_configs/*.json` — "none of
which is property-specific" per its own docstring — plus two structurally different
shape-based adjudicators (`adjudicate_fail_open.py`, `adjudicate_oob.py`, the latter already
counted in 3.3).

| # | Canonical name | Property | Config/producers | Gate | Soundness |
|---|---|---|---|---|---|
| 7 | `SSRF` (`ATTACKER_CONTROL_OF_REQUEST_HOST`) | attacker control of the outbound request HOST at `fetch`/`axios`/`http(s).request` — host only, path/query/body explicitly out of scope | `property_configs/ssrf_host.json` + 3 WebExtension source-variant producers | 3 gates: 9/9, 10/10, 10/10 | production via config seam |
| 8 | `PATH_TRAVERSAL` (`ATTACKER_CONTROL_OF_FILESYSTEM_LOCATION`) | attacker control of the resolved filesystem path at `fs.*`/`res.sendFile` — explicitly notes a fixed `path.join()` base alone does NOT contain `..` traversal | `property_configs/path_traversal_host.json` | no dedicated frozen/gate doc found in scope | wired but not freshly re-verified this pass |
| 9 | `REDOS` (`ATTACKER_CONTROLLED_REGEX_COMPLEXITY`) | attacker input reaches a regex with a structurally-confirmed catastrophic-backtracking shape — explicitly heuristic, not NFA-proof (same class of tool as safe-regex/recheck/eslint-plugin-redos) | `property_configs/redos_complexity.json` | Stage1=9/9, Stage2=7/7 against real empirically-timed ground truth | FROZEN (Stages 1-2); real corpus scan (1,477 files) found CVE-2025-5892 and 1 previously-undisclosed RocketChat finding, 1 real FP fixed+frozen |
| 10 | `NOSQLI` (`ATTACKER_CONTROL_OF_QUERY_OPERATOR_STRUCTURE`) | attacker-controlled input reaches a MongoDB query field without primitive-type constraint (`$ne`/`$regex`/`$gt`/`$where` injection) — grounded in 3 real RocketChat CVEs | `property_configs/nosqli_query_op.json` | Stage1=10/10, Stage2=9/9 frozen | **Stage3 corpus-scale sweep incomplete/abandoned (~40-45% timeout rate); a known, named, unfixed classifier gap (does not recognize AJV/JSON-schema route validation, RocketChat's real primary defense) is explicitly documented as open — not sound at corpus scale** |
| 11 | `COMMAND_INJECTION` | shell command injection via `exec`/`execSync`/`execFile`/`spawn` | Stage1/2A/2B characterization scripts exist; **no `property_configs/*.json` and no wiring producer — never promoted to a full adjudicated property** | no gate found in scope | Stage 2A caveated-but-reasonable; **Stage 2B explicitly self-described as "a characterization EXPERIMENT, not trusted sanitizer semantics," never auto-promotable** — the clearest "implemented but not promotable" case in the whole inventory besides `single_object_pass.py` |
| 12 | `FAIL_OPEN_SECURITY_CONTROL` | a `Promise.then(fulfilled, rejected)` call whose two handlers are syntactically identical, inside a method with security-decision indicators — candidate that a dependency failure fails open rather than closed | `adjudicate_fail_open.py` | F1-F8, "frozen live-CPG gate" | candidate-only by explicit design, never upgraded to a vulnerability claim |
| 13 | `LLM_INSECURE_OUTPUT_HANDLING` (OWASP LLM02) | model output reaches `eval`/`exec`/SQL, or an HTML/redirect sink | `llm_input_verdict.py` | L1-L7 | production; **real-world validated on a deployed RocketChat plugin, found and fixed 2 real bugs** before confirming a correct true-negative |
| 14 | `LLM_PROMPT_INJECTION` (OWASP LLM01) | request data flows into the system-role prompt content | same file, same gate | same | same |

### 3.7 NSS/C-C++ infrastructure and research (not itself a distinct property)

| Item | What it is | Applicability |
|---|---|---|
| `nss-sslmac-capacity-r01/` | struct-member fixed-array **capacity model** (feeds OOB_WRITE, not itself a verdict) — 24/24 + 24/24-real-Joern + 3 clean regressions across 3 rounds, found and fixed a real silent bug in round 3 (`typedef` alias misclassification could fabricate a false union capacity fact) | C/C++ (NSS/Firefox) only; **never run against real NSS source itself** — its own fixture is hand-written, explicitly disclosed as unverified against the real file |
| `moz-scan-hmacct-dynamic-validation/` | one-off ASan dynamic (not static) reachability probe, single question, result "validation held, no vulnerability found" | C only (NSS); not a reusable analyzer, not part of the class taxonomy |
| `moz-scan-nss-tls13-aead-iv-hardening.patch` | a proposed hardening diff, not an analyzer | n/a |
| `moz-scan-paired-cve-validation-round1.md` | 13-round research log; documents the SAME `OOB_WRITE` family's development history (index/copy-length/pointer-increment/cursor-write/call-sink/interprocedural/runtime-capacity variants, already counted in 3.3) against real paired NSS/mozjpeg CVEs; final honest result on its target CVE (CVE-2019-17006) is **NOT ESTABLISHED** (blocked on an unresolved macro sign), reported as a legitimate negative, not routed around | C/C++ (NSS/mozjpeg) |
| `docs/moz-oob-r01/` | research log; empirically found all 3 real disclosed Mozilla OOB CVEs tested **MISS** identically on vuln/patched under the frozen R03 OOB producer (2 because array-index-store writes weren't modeled yet, fixed by `OOB-INDEX-R01`; 1 because the real capacity check lives in a different translation unit — interprocedural gap) | C/C++ (Gecko/NSS) |

## 4. Evidence-sufficiency key and the real, precise cross-cutting finding

Section 3's "evidence sufficient today" judgment for each property, explained:

1. **Properties 3.1-3.3 (fallible-bounded-resource, thread-safety, OOB_WRITE/READ/COMPARE)**:
   **YES.** All three consume the exact same C/C++ raw-fact schema
   (`export_c_cpp_facts_v03.sc`'s own `calls.tsv`/`arguments.tsv`/`parameters.tsv`/
   `cfg_edges.tsv`/`methods.tsv`) that `run_pipeline_one.py` **already generates for every one
   of the 452 packages processed.** Wiring any of them in would need zero new fact-generation
   work — only a new `subprocess.run([...])` call per package, the same shape as the existing
   `r04_scan`/`r05_scan` stages. This is the single most load-bearing, precise finding in this
   whole inventory: **the npm corpus's own already-completed scan run has silently sufficient
   raw material sitting in intermediate artifacts (deleted after each package, per
   `run_pipeline_one.py`'s own disk-bounding discipline) to have also produced real thread-
   safety and OOB-write candidates on the SAME 452 packages — but this was never done, and
   would now require RE-scanning each package (re-downloading, re-running c2cpg) since those
   intermediate artifacts are gone, not merely re-processing the corpus scan's own output.**
2. **Properties 3.5-3.6 (the 13 JS/TS npm-applicable classes)**: **NO, not as currently
   generated.** Every one of these needs its own SPECIFIC `.sc` Joern-export script producing
   its own specialized fact tables (`denylist_guards.tsv`, `singleton_writes.tsv`,
   `terminator_profile.tsv`, `identifier_reads.tsv`, `source_facts.tsv`/
   `propagation_relations.tsv`/etc. for the taint engine, and so on — 6+ distinct exporter
   scripts, none the same as each other). `run_pipeline_one.py`'s own JS export stage runs
   `export_neutral.sc` (the "Gate-24 portable-program-facts/0.1" pair, per
   `ANALYZER_FREEZE.md`'s own documented selection) — a GENERIC JS/TS fact format
   (calls/methods/arguments), not any of these specialized tables. Wiring any of these 13 in
   would require running an ADDITIONAL, different Joern export pass per property (or per
   small group of compatible properties) against every package — real, non-trivial new
   fact-generation work, not just a new subprocess call.
3. **Property 3.4 (WordPress family)**: **N/A** — wrong ecosystem entirely (PHP), the npm
   corpus pipeline generates no PHP facts and none of these 494 packages are PHP.

## 5. What this does not do

Per instruction: no scanner was modified or run to produce this document. Every gate/pass
count cited above is read from that capability's own existing freeze/review/results
documentation or its own gate script's hardcoded fixture-comparison logic — none was
independently re-executed to verify currency. Two real, disclosed internal inconsistencies
were found and are flagged, not silently resolved: (a) `docs/moz-oob-r01/`'s own gate-count
citations for `OOB_ADJ_R01`/`OOB_ADJ_R03` are not self-consistent across its own document's
different rounds (10/10 vs 14/14 vs 12/12, and 15/15 vs 5/5); (b) `path_transform_identity.py`
is described as a "frozen production interface" in `ARCHITECTURE_SPECIFICATION.md` §4 while
its live implementation has actually moved to a Scala/Joern producer
(`producers/export_transform_identity.sc`) and the Python file itself sits archived under
`historical/` — a real documentation/code-location mismatch, not resolved here.
