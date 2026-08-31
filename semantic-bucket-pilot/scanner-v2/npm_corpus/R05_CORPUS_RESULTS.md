# R05 full-corpus scan: final results

The frozen R04→R05 fallible-bounded-resource pipeline (see `PIPELINE_FREEZE.md`'s own stage
list and its "R05 addendum" section) was run against the full 494-package eligible cohort,
post header-staging fix (`HDR_FIX_STATUS.md`) — this supersedes `CORPUS_STATUS.md`'s own
earlier, now-stale "Finding review" bullet, which described the PRE-header-staging-fix run
(zero raw findings, traced to c2cpg never resolving `Napi::` calls at all). This run is the
real, current, final one.

**Stopped at 452/494 by explicit instruction** — the pipeline covers exactly one vulnerability
class (confirmed in `study/ANALYZER_CLASS_COVERAGE_MATRIX.md`), and substantial real evidence
on that class was already in hand (`study/r05_near_miss_audit/R05_INTERIM_NEAR_MISS_AUDIT.md`,
`study/r06_stratified_review/STRATIFIED_REVIEW_RESULTS.md`,
`study/nan_prevalence_study/PREVALENCE_STUDY.md`) — not a failure or a resource exhaustion.
Process stopped cleanly (`SIGTERM`), final checkpoint taken and verified complete
(`checkpoints/r05_full_scan_00000451_1a326736275a.*`, 451 rows, the 452nd row's own real
completeness independently confirmed via direct JSON parse before this checkpoint was taken).

## Real final counts (452/494 packages processed)

| Status | Count |
|---|---:|
| `ANALYZED` | 424 |
| `RESOURCE_LIMIT` | 26 |
| `CPP_CPG_FAILED` | 2 |
| **Total processed** | **452** |
| Not yet processed (scan stopped) | 42 |

## Real aggregate classification (R05, all 452 processed rows)

| Real counter | Count | Meaning |
|---|---:|---|
| `ACQUISITION_NAME_MATCH_CANDIDATE` | 33,675 | every real call named `"New"` |
| `ACQUISITION_SIGNATURE_UNRECOGNIZED` | 33,675 | c2cpg never resolves a real `"New"` call to the fully-qualified `Napi.Buffer.New:...` shape directly — confirmed corpus-wide, matches R05's own design docstring's stated reason for existing |
| `R05_RECOVERY_CANDIDATE` | 31,550 | of those, match R05's own unresolved-shape recovery marker |
| `R05_RECOVERY_RESULT_TYPE_UNRECOGNIZED` | 31,545 | rejected at the object-identity gate (see `study/r05_new_gate_classification/README.md` for what this real classification actually checks, and why its name is misleading) |
| `R05_RECOVERY_ARITY_UNRECOGNIZED` | 3 | rejected on real argument-count mismatch |
| `R05_ACQUISITION_CALL_RECOVERED` | 2 | passed all real recovery gates |
| `SIZE_ATTACKER_INDEPENDENT` | 1 | recovered call, but its own size argument is a literal |
| `VALUE_ACQUISITION_GUARD_MISSING` | 1 | the one real finding — see below |

`r04_classification` is identical through `ACQUISITION_SIGNATURE_UNRECOGNIZED` (33,675/33,675)
and produces zero R04-only findings — expected: every real corpus site needing recovery goes
through R05's own additional path, none resolve directly to R04's own matching shape.

## The one real finding

`node-libcurl@5.1.2`, `Easy::ReadFunction`, verdict `VALUE_ACQUISITION_GUARD_MISSING`.

**This is the SAME site already independently confirmed, by direct manual source
verification, as a false positive** — `study/resource_guard_r05/NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md`
(R06's own motivating case) and `R05_INTERIM_NEAR_MISS_AUDIT.md` both establish this
independently: `Easy::ReadFunction` is a libcurl-invoked native callback
(`curl_easy_setopt(ch, CURLOPT_READFUNCTION, Easy::ReadFunction)`), never called by JS at all —
its own `size`/`nmemb` parameters are supplied by libcurl internally, not by any JS caller.
R06's own source-boundary gate (built specifically because of this real site) correctly
reclassifies it as `SOURCE_BOUNDARY_UNRESOLVED`, not a real finding — confirmed by the
aggregation-boundary test (`tests/test_aggregation_boundary.py`) on `claude/r06-precision-fix`.

**This frozen R05 run (the one that actually drove the corpus scan) predates R06's own
source-boundary gate** — R06/FIX01I were developed and validated in parallel, on isolated
branches, never merged back into the frozen R04/R05 lineage this corpus scan itself ran
(per the standing discipline: R01-R05 stay byte-for-byte frozen once corpus scanning starts,
recorded in `ANALYZER_FREEZE.md`). So the real, honest, current state is: **this specific
frozen pipeline's raw output shows exactly 1 finding, corpus-wide, across 452/494 packages,
and that finding is a confirmed false positive** — zero real, verified positive findings from
this corpus run as actually executed. This is not a defect in this write-up; it is the real
result of running the frozen R05 pipeline (not the R06-corrected one) against the corpus.

## What this run does and does not establish

- **Does establish**: real R04/R05 behavior at real corpus scale (452/494 packages, 33,675
  real `"New"`-named candidates examined structurally) — no raw findings beyond the one
  already-known false positive; the recovery mechanism's own real gates (object-identity,
  arity, arg-role) behave as designed, not as a name-matching heuristic that happens to work.
- **Does NOT establish** real-world Buffer-allocation-vulnerability prevalence in this
  corpus — this frozen pipeline (a) only models `Napi::Buffer::New`, not `Nan::NewBuffer`/
  `CopyBuffer` (see `study/nan_prevalence_study/PREVALENCE_STUDY.md` — the largest single gap,
  38 packages / 104 call sites uncovered) or raw N-API/V8 Buffer APIs; (b) predates R06's own
  source-boundary correction and the Nan capability's own reachability-tier and object-identity
  refinements; (c) was stopped at 452/494, not the full 494.
- **`study/r05_new_gate_classification/README.md`** (separate branch,
  `claude/r05-new-gate-classification`) independently confirms the `"New"`-name gate itself is
  not the defect (99.96% of a real, bounded sample of rejected calls are legitimate non-Buffer
  constructors) — the real, precisely-identified gap is the object-identity resolver's own
  blindness to a `static_cast<Napi::Value>(...)`-wrapped Buffer construction, not the name gate.

## Real per-package outliers worth noting (not investigated further here)

The 15 packages with the largest `"New"`-name-match candidate counts are almost entirely
either genuinely Nan-based packages (`swisseph`: 1,496; `indy-sdk`: 764; multiple
`@nodert-win10-*` Windows Runtime binding families: 500-800 each) or auto-generated/bulk
binding packages (`@gjsify/node-gi`: 516) — consistent with `study/r05_new_gate_classification/`'s
own real finding that this volume is overwhelmingly non-Buffer construction, not a sign of
missed coverage. Full list in that study's own README.md Section 1.

## Standing status of related, isolated work

None of the following required this scan to reach 494/494, and none is affected by the scan's
stop point:

- `claude/r06-precision-fix` / `claude/r06-fix01i-integration`: R06's own source-boundary gate
  and the Phase B JS-argument promotion boundary, both frozen and tested independently.
- `claude/r05-near-miss-audit`: the interim near-miss audit, frozen against a 365-row snapshot
  of this same live file taken mid-scan — its own findings stand regardless of this scan's
  final stop point (it never claimed to cover packages beyond its own frozen snapshot).
- `claude/nan-prevalence-study`, `claude/nan-capability`: fully independent of the R04/R05
  corpus scan's own progress — built and validated against individually-fetched real packages.
- `claude/analyzer-class-matrix-audit`: confirms this scan's own real scope (exactly one
  vulnerability class) independently of this document.
- `claude/r05-new-gate-classification`: the `"New"`-gate classification study referenced above.

No further R05 scanning against this corpus is planned. Extending coverage (Nan, raw N-API,
V8 Buffer APIs, the object-identity `static_cast` gap) is real, separate, future work — not
implied or started by this document.
