# Analyzer class coverage matrix — what the 494-package pipeline actually runs

Read-only audit, per explicit instruction: nothing modified, nothing rerun, the live scan
(PID 6956, `claude/aggregate-kinds-producer-test-03zs7n`) untouched. Built from three sources
only, cross-checked against each other, not assumed from any one alone:

1. `npm_corpus/ANALYZER_FREEZE.md` — the project's own capability-freeze record (item 1).
2. `npm_corpus/PIPELINE_FREEZE.md` + `npm_corpus/run_pipeline_one.py`'s own real source (item
   3/6) — what the corpus driver actually invokes, verified by reading the file, not by
   trusting its own docstring summary.
3. The real, currently-accumulating `full_scan_r05_working.jsonl` (439 records as of this
   audit) — its own real per-record JSON keys, enumerated programmatically across every
   record, not sampled from one.

**Correction to this session's own prior framing, stated up front:** `R05_INTERIM_NEAR_MISS_AUDIT.md`'s
`25,518 → 2 → 1` funnel describes the R05 fallible-bounded-resource class only. Presenting it
as "the scanner" or "the corpus result" without that qualifier was a real overgeneralization
of a single class's audit into a claim about the whole analyzer — corrected here, not repeated
below.

## 1. The matrix

| Class | Frozen capability file(s) | `ANALYZER_FREEZE.md` claims "actually invoked"? | Verified actually invoked by `run_pipeline_one.py`? | Real JSONL keys present (439 records)? | Persisted? |
|---|---|---|---|---|---|
| Fallible bounded resource (R01) | `resource_guard_verdict.py` | Yes | **No** — no call anywhere in `run_pipeline_one.py` | none | No |
| Fallible bounded resource (R02) | `resource_guard_verdict_r02.py` | Yes | **No** | none | No |
| Fallible bounded resource (R03) | `resource_guard_verdict_r03.py` | Yes | **No** | none | No |
| Fallible bounded resource (R04) | `resource_guard_verdict_r04.py` | Yes | **Yes** — `run_pipeline_one.py:467` | `r04_classification`, `r04_findings` (411/439) | Yes |
| Fallible bounded resource (R05) | `resource_guard_verdict_r05.py` | **Not listed at all** (predates R05 — see Section 3) | **Yes** — `run_pipeline_one.py:495` | `r05_classification`, `r05_findings` (411/439) | Yes |
| Lock-balance (missing-unlock-before-return) | `lock_balance_verdict.py` | Yes | **No** — zero references in `run_pipeline_one.py` | none | No |
| Protected-field / global-state (absent critical section) | `protected_field_verdict.py` | Yes | **No** | none | No |
| OOB/runtime-capacity write — address-of indexed dest. | `cap_addr_indexed.py` | Yes | **No** | none | No |
| OOB/runtime-capacity write — stack-array capacity (v2) | `oob_runtime_capacity_v2.py` | Yes | **No** | none | No |
| OOB/runtime-capacity write — single-object `sizeof` bounding | `single_object_pass.py` | Yes | **No** — and see Section 4: this capability's own review found it unsound | none | No |
| OOB/runtime-capacity write — heap-capacity check | `heap_extent_check.py` | Not listed in `ANALYZER_FREEZE.md` at all | **No** | none | No |
| JS↔C++ cross-language linker (shared evidence infra, not a vulnerability class itself) | `link_napi_facts.py` | Yes (listed separately, correctly not called a "capability") | **Yes** — `run_pipeline_one.py:436` (`POLYGLOT`) | `cross_language_bindings` (411/439) | Yes, but **not consumed** by R04/R05's own verdict logic (both files' own docstrings state they "operate on C++-only facts and have no JS facts loaded at all") |

439 real records enumerated for the JSONL-key check (every key across every record, not a
sample): `package_name`, `version`, `status`, `detail`, `stages`, `total_seconds`,
`header_staging` present in all 439; `r04_classification`/`r04_findings`/
`r05_classification`/`r05_findings`/`cross_language_bindings` present in 411/439 (the
remainder are non-`ANALYZED` packages — `RESOURCE_LIMIT`/`CPP_CPG_FAILED` — which correctly
never reach the scan stages at all). No other classification/finding key of any name appears
anywhere in the file.

## 2. What this means, plainly

**Only ONE vulnerability class — fallible bounded resource, the R04→R05 lineage — is
actually invoked by the 494-package pipeline.** Lock-balance, protected-field/global-state,
and all three real OOB/runtime-capacity write capability files are frozen, gated, and
present in the repository, but **none of them is called anywhere in `run_pipeline_one.py`**,
and correspondingly **none of their output exists anywhere in the accumulated corpus JSONL**.
This is not an inference from absence — it is confirmed positively three ways: (a) `grep` for
every one of their filenames in `run_pipeline_one.py`'s own source returns zero call sites;
(b) `PIPELINE_FREEZE.md`, the pipeline's own freeze record, documents its stage list
explicitly and only ever names `r04_scan` (and, in its own later "R05 addendum" section,
`r05_scan`) — never any of the other five; (c) the real JSONL's own per-record keys,
enumerated across all 439 current records, contain no trace of them.

**R01–R03 not running separately is expected, not a gap of the same kind.** This project's
own established convention (stated in R02/R03/R04/R05's own module docstrings) is that each
revision in a single lineage copies its predecessor's logic forward byte-for-byte and only
the TERMINAL revision is the one actually run — R04 already IS what R01-R03 evolved into, and
R05 supersedes R04 the same way (R04's own findings are a strict subset of R05's, confirmed
by R05's own docstring: "R05's own already-resolved-call path is byte-for-byte R04's"). R04
and R05 both being invoked (R05 alongside, not instead of, R04 — see `PIPELINE_FREEZE.md`'s
own R05 addendum) is the correct, intentional shape of ONE class's lineage, not five extra
classes.

**Lock-balance, protected-field, and the three OOB/runtime-capacity capabilities are a
genuinely different situation: five SEPARATE, independently-frozen classes, each addressing a
representation shape none of the others cover, and none of them has ever run against this
corpus at all.** Whatever their own individual gate status was at development time (per
`ANALYZER_FREEZE.md`: "other capabilities' pre-existing gates unchanged, not re-verified
here"), zero evidence exists in this corpus run about how any of them would perform on these
494 real packages.

## 3. The documentation discrepancy itself

`ANALYZER_FREEZE.md` (item 1, "recorded before any corpus construction or scanning begins")
explicitly labels all nine files above (R01-R04 + the five separate classes) as "Load-bearing
entries for the npm corpus run (the scanning capabilities actually invoked)". `PIPELINE_FREEZE.md`
(item 3/6, "frozen after the 50-package pilot completed") is the pipeline construction's own
freeze record, and its own explicit stage list narrows this to `r04_scan` only, with R05 added
later in its own dedicated addendum section. **Neither document states that this narrowing
happened, or reconciles the two claims.** `ANALYZER_FREEZE.md` was never updated to reflect
that five of its nine "actually invoked" capabilities, in fact, are not — nor does R05's own
absence from `ANALYZER_FREEZE.md` (it postdates that freeze) get an addendum comparable to
`PIPELINE_FREEZE.md`'s own "R05 addendum" section. This is a real, findable gap between two of
the project's own freeze records, not a matter of interpretation — confirmed by direct source
and data inspection (Section 1), not by trusting either document's own summary of itself.

## 4. One additional, separate finding: `single_object_pass.py`'s own status

Beyond simply being unwired, `single_object_pass.py` has its own dedicated review document
(`CAPABILITY_REVIEW.md`) whose own opening line states: "the provisional single-object
implementation is **not sound as written and must not be promoted**." Several of its own
listed promotions are called out by name as unsound (`DestroyCertificate:cert`,
`nsslowcert_DestroyTrust:trust`, `sftk_InitGeneric:keyTypePtr`, `NSC_GetMechanismInfo:pInfo`)
because they assume a caller-supplied pointer parameter is fully backed without independent
evidence. This means `single_object_pass.py`'s omission from the corpus pipeline is doubly
correct on the record as it stands: it is both unwired AND, by its own project's own review,
not yet validated as sound — the omission should not be read as "an oversight that should be
corrected by wiring it in," at least not without first addressing that review's own findings.
No equivalent negative self-review was found for `lock_balance_verdict.py`,
`protected_field_verdict.py`, `cap_addr_indexed.py`, `oob_runtime_capacity_v2.py`, or
`heap_extent_check.py` in this pass — their omission is a pure coverage gap, not a
soundness concern found in their own documentation.

## 5. What this means for the Nan capability work in progress

The Nan capability (`NAN_NEWBUFFER_UNBOUNDED_ALLOCATION` / `NAN_COPYBUFFER_SOURCE_CAPACITY`,
`claude/nan-capability`) is real, user-authorized, additive work on the ONE class that IS
actually invoked (the fallible-bounded-resource lineage) — it extends R05's own coverage to a
second, larger contract family within that same class, exactly as the user's own framing
states. It does not touch, replace, or redefine lock-balance, protected-field, or any of the
OOB/runtime-capacity write capabilities, and nothing in this audit changes that work's own
validity. What this audit does establish is that a claim like "the corpus scan covers N
vulnerability classes" would be false as of this run — it covers exactly one, and any future
report on the 494-package corpus should say so explicitly rather than let the R04/R05 funnel
stand in for "the analyzer" the way this session's own prior message did.

## 6. Explicitly not done in this pass

Per instruction: nothing modified, nothing rerun. This audit does not attempt to explain WHY
the pipeline was narrowed to R04/R05 only (no commit message, freeze doc, or other artifact
found in this pass records that decision — Section 3), does not propose wiring any of the five
omitted classes into the pipeline, and does not evaluate what their real candidate/finding
counts WOULD be if they were run — that would require actually invoking them, which is exactly
what "do not modify or rerun anything yet" rules out here.
