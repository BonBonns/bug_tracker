# Task #28: corrected pilot conclusion, and the follow-up work it opens

`BEHAVIORAL_VERIFICATION_RESULTS.md` (phase 3) reported real evidence for every step it was
asked to run, but its own framing was read as more conclusive than the evidence supports on two
specific points, corrected here directly rather than edited away silently:

1. **A destination capacity of 100 does not, by itself, establish an OOB write.** The prior
   report's own Section 3.3 said `dest_capacity_bytes: 100` was "verified... against the real
   source" — true only as a claim about the *capacity value itself* (the deriver correctly read
   `char buf[100]`). It never claimed, and should have said so explicitly, that the site's own
   *write length* (the `snprintf` call's own size argument) was shown to exceed 100 — it was not
   checked. `oob_write_verdict.py`'s own CANDIDATE verdict already means exactly this narrower
   thing by design ("no PROVEN bound", not "proven overflow") but the report's prose did not say
   so plainly enough on first read.
2. **A finding inside `re2`'s vendored `abseil-cpp` is not automatically a `re2` finding —
   but it must be CLASSIFIED, not discarded.** Every real OOB_WRITE/OOB_READ candidate this
   pilot found sits under `vendor/abseil-cpp/` — bundled third-party source shipped inside the
   npm tarball, not code the `re2` npm package's own maintainers wrote. The prior report named
   the file paths but did not flag the provenance distinction. **Correction to the correction**:
   this does not mean vendored findings should be thrown away. A vendored dependency that is
   actually compiled into the addon and reachable through it (task #32's own reachability tiers)
   can still contain a real, exploitable bug reachable via the npm package — the fix is
   attribution (report it as "<upstream library> as bundled by <npm package>", not an unqualified
   `re2` finding) and deduplication (the same vendored library bundled near-identically by many
   packages should not count as N independent findings), never silent exclusion. See task #31,
   revised accordingly.

Both corrections, plus two structural gaps the pilot's own real evidence surfaced but did not
resolve, are the basis for the corrected property status below and the five follow-up tasks
opened as a direct result (project task tracker #29-33). **The 494-package multi-class run
remains explicitly not authorized — this document does not change that.**

## Corrected per-property status

| Property | Status |
|---|---|
| `FALLIBLE_BOUNDED_RESOURCE` | Existing corpus baseline (already executed by the stopped 494-package run), but with known precision problems already disclosed elsewhere in this repository (R05's near-miss audit, the node-libcurl false positive, the `static_cast<Napi::Value>` object-identity gap) — not re-litigated here. |
| `LOCK_BALANCE` | **Closest to integration-ready.** Real schema/execution compatibility, a real historical positive+confirmed-negative pair reproduced fresh through the real pipeline, a real explicit-abstention path demonstrated (synthetic, disclosed). Its one open gap: real npm positive-path evidence is still absent (the one real npm lock-call candidate this pilot found, `@2060.io/ffi-napi`'s `closures.c`, never made it into the CPG at all, for an unexplained reason). |
| `PROTECTED_FIELD` | Integration works (schema-compatible, real historical positive and a real, precisely-documented abstention reproduced). **Needs target-domain evidence** — zero real npm evidence either way; its own inference rule (a field protected in one place, unprotected in another, same translation unit) makes real npm exemplars genuinely hard to find by cheap search, not yet attempted at the scale this would need. |
| `OOB_WRITE` | Produced real npm candidates (`re2`'s vendored abseil-cpp) — but **needs correction/reproducibility work before being trusted for corpus use**: (a) those candidates are inside vendored third-party source, which needs classification and dedup, not exclusion (task #31); (b) a resolved destination capacity is not itself proof of an overflow — the write length was never shown to exceed it (documented above, not a new blocker, a framing fix); (c) no tiered JS-reachability classification exists for any candidate this property produces (task #32). |
| `OOB_READ` | **Blocked.** The repeated, implausible `src_capacity_bytes: 5` (including on a function-pointer-typed source) strongly suggests a real, unresolved capacity-derivation defect (task #29) — its positive-path output cannot be trusted at corpus scale until this is root-caused. |
| `OOB_COMPARE` | **Blocked.** Zero positive-path evidence exists anywhere — not in this pilot's real npm/historical testing, not in this repository's own prior Tor-corpus validation (0-for-12 real sites). Its promotability currently rests entirely on gate-fixture soundness, with no real-world positive validation to date (task #33). |

**The pilot is complete as an experiment. Its answer is not "launch the corpus run" — it is "one
property (`LOCK_BALANCE`) is close to integration-ready, one (`PROTECTED_FIELD`) needs
target-domain evidence, and the three OOB properties need a dedicated correction/reproducibility
phase before corpus use, especially `OOB_READ` and `OOB_COMPARE`."**

## Additional blockers, stated plainly

- **[CORRECTED IN PLACE — task #30]** There never was a previously-documented positive result for
  the Tremor CVE-2018-5147 fixture to fail to reproduce. This pilot's real pipeline invocation
  correctly found 0 candidates on both vuln and patched — that IS the real, standalone result on
  Tremor's own fixture, not a failure to reproduce something that existed elsewhere. The apparent
  "previously-documented positive" was `e2e-canonical/SUMMARY.txt`'s "VULN dir -> candidates: 1",
  which — directly verified — was computed on an unrelated Mozilla CVE (`WinWebAuthnManager.cpp`,
  mfsa2022-13), never on Tremor. See the task #30 section below for the full reconciliation and
  the real, newly diagnosed root cause of Tremor's own 0-candidate result (task #44).
- A resolved destination capacity alone does not establish an OOB write; the actual write extent
  must be shown to exceed it — a framing correction to `BEHAVIORAL_VERIFICATION_RESULTS.md`
  Section 3.3, not a new defect, but real enough to restate here plainly.
- Findings inside vendored third-party source (e.g. `re2`'s bundled `abseil-cpp`) must not be
  silently counted as unqualified findings against the npm package under study — but they must
  not be silently discarded either. A reachable vendored bug is a real bug; it needs attribution
  (upstream library, not the bundling package) and deduplication (not counted once per bundling
  package) — task #31, revised.
- If this study's property definition is JS→C/C++ (matching the npm-scoped inventory's own
  framing), a native-code finding needs real evidence linking it to an exposed, JS-callable
  package path — the same discipline `FALLIBLE_BOUNDED_RESOURCE` already applies via
  `link_napi_facts.py` — before it counts as a demonstrated npm-package vulnerability, not merely
  a C/C++-level pattern somewhere in the source tree. **Revised per direct instruction: this must
  be a 6-tier reachability classification (direct linked call; exported registration without an
  internal wrapper call; transitive native helper; registered callback/worker; module-load-time
  execution; unresolved), not a single direct-call-only gate — a single-tier requirement would
  recreate the exact false-negative problem already found and fixed for Nan's exported-but-
  unwrapped methods, and would miss transitively-called native helpers entirely** — task #32.
- Large-package real cost is substantial and now precisely measured, not estimated: ~83s CPG
  generation, ~332s normalization, ~49s for all seven scanner processes combined (re2, 551 real
  files) — real numbers any future corpus-scale cost projection should use, not the small-package
  numbers from phase 1/2 of this pilot.

## Follow-up work opened, in recommended priority order (read-only judgment, no code changed
## by this document)

| Order | Task | Scope |
|---:|---|---|
| 1 | #29 | Root-cause the `src_capacity_bytes: 5` anomaly |
| 2 | #30 | Reconcile the Tremor CVE-2018-5147 reproduction discrepancy |
| 3 | #32 | **Tiered** (6-level) JS/native reachability classification, not a single direct-call gate — per the Nan-capability false-negative lesson |
| 3.5 | #35 (new) | Every finding must preserve its real source path + a content hash at scan time |
| 4 | #31 | Vendored-source **provenance classification and deduplication** (not exclusion) |
| 5 | #33 | Find real positive-path evidence for `OOB_COMPARE`, **or formally retire it from promotion** if a genuine, bounded search finds none |

## Property-specific blockers (revised again: #35 is universal — Resource Guard included)

Per direct instruction, the blockers are property-specific rather than one all-or-nothing gate —
a staged run can enable whichever properties have their own preconditions met, instead of every
property waiting for the weakest one. **Correction to the prior revision**: #35 was scoped there
to `OOB_WRITE`/`OOB_READ` only, on the reasoning that those were the only properties with real
vendored findings observed so far. That was wrong — the underlying fact this pilot itself
established is that **none of the six properties currently preserves source path or content
hash, `FALLIBLE_BOUNDED_RESOURCE` (Resource Guard) included**, so #35 gates every property that
emits findings, not just the two that happened to produce a vendored candidate first, and not
just the five properties task #28 newly integrated.

**#35 is now IMPLEMENTED, VERIFIED, and CLOSED** (`claude/provenance-preservation-task35`,
`provenance.py` + a change to `run_pipeline_one.py` — the real orchestrator, not a side
script). Three rounds — a first pass, a correction, and a THIRD correction of a real semantic
defect the second round itself introduced — are all recorded here for the real history, not
just the final state. **Read the third-round correction (below the numbered list) before
trusting any `actionable=True` mention in the round-2 text that follows — that field no longer
exists, replaced by a strictly narrower `reportable` field for exactly the reason explained
there.**

- The manifest is built immediately after extraction, before header staging/c2cpg/any scanner
  for any property runs, fail-CLOSED (a new `PROVENANCE_FAILED` status, zero scanner output) if
  it cannot be built.
- **Two real, distinct tree-level hashes**, corrected from an initial version that only had one
  (a tarball hash mislabeled as a "source-tree hash"): `tarball_sha256` (the original compressed
  tarball's own bytes — real, but sensitive to compression/packaging, not just content) and
  `source_tree_sha256` (a real, deterministic hash of normalized relative paths + per-file
  content hashes, sorted by path — reproducible independent of tarball compression, extraction
  order, or filesystem walk order). Verified directly: two manifests built from identical real
  file content but different tarball bytes produce identical `source_tree_sha256` and different
  `tarball_sha256`; a real content change changes `source_tree_sha256` even with the same
  tarball bytes.
- **Fail-closed actionability**, added on direct correction ("honest degradation is insufficient
  if an actionable finding cannot be tied to a real file"): every enriched finding now carries
  `provenance["resolved"]` and a mirrored top-level `finding["actionable"]`, both `False` on any
  resolution failure — including a new, more precise `SOURCE_FILE_UNREADABLE_AT_SCAN_TIME` case
  that a real path match with unreadable content previously collapsed into a generic
  `PATH_NOT_IN_MANIFEST`. A finding may still be retained diagnostically with `actionable=False`,
  but is explicitly marked as not to be reported/published as a demonstrated vulnerability.
- **Real per-finding enrichment verified with real positive diagnostics, not just zero-finding
  runs** (a real gap in the first round, corrected on direct instruction: "the Resource Guard
  test used a zero-finding package... proves classification stability, not per-finding
  enrichment"): `node-libcurl@5.1.2` fetched and run for real through `run_pipeline_one.py`'s
  own orchestrator reproduces the real `Easy::ReadFunction`/`VALUE_ACQUISITION_GUARD_MISSING`
  finding (the one real finding the frozen R04/R05 pipeline ever produced across the full corpus
  scan) — `actionable=True`, real `source_path`, `content_hash` matched against an independently
  recomputed hash of the real source file on disk. **This finding is the same site already
  independently confirmed elsewhere as a false positive on security grounds (R06's own
  source-boundary gate reclassifies it) — used here purely as a real, reproducible POSITIVE
  RECORD to test provenance enrichment against, not re-litigated as a vulnerability.**
  `LOCK_BALANCE` and `PROTECTED_FIELD` were similarly verified directly (not merely assumed from
  their pre-existing `method_id` field): both real, committed wolfSSL fixtures rebuilt fresh
  through real c2cpg, each producing a real positive finding, each enriched and confirmed
  `actionable=True` with a matching real content hash.
- `OOB_WRITE`/`OOB_READ`/`OOB_COMPARE`'s own candidates gained two small, additive join keys
  (`call_id`, `function_id`) so a future orchestrator can attach the same provenance once tasks
  #38-40 wire those scanners in — their own verdict logic is unchanged, both real OOB gates
  (`oob-write-r05-sizeof`, `oob-compare-r07`) still pass identically.
- 29/29 real checks (`check_provenance.py`) as of round 2 — see round 3 below for why this
  number and this whole `actionable` field were both superseded.

### Round 3: `actionable=True` on a confirmed false positive was a real, serious defect

Round 2's `finding["actionable"] = True` purely because provenance resolved was flagged directly
and confirmed concretely: **node-libcurl's own real finding — the same site already
independently confirmed elsewhere as a CONFIRMED FALSE POSITIVE — came back `actionable=True`
merely because its source file was resolved.** Provenance resolution is a necessary condition
for reportability, never a sufficient one. This was exactly the false-positive-reporting risk
this whole project exists to avoid, introduced by round 2's own fix.

**Corrected**: `actionable` no longer exists. Five separate fields now govern reportability,
computed by one exact, one-way formula:

```
finding["reportable"] = (
    finding.get("scanner_candidate", False)
    and provenance["resolved"]
    and finding.get("applicability_status") == "APPLICABLE"
    and finding.get("adjudication_status") != "CONFIRMED_FALSE_POSITIVE"
)
```

Unresolved provenance → `reportable=False`, always, no exceptions. Resolved provenance →
`reportable` computed from the other three fields, never automatically flipped true by
resolution alone. `provenance.py` never fabricates `"APPLICABLE"` or clears an adjudication —
`applicability_status`/`adjudication_status` default to `NOT_YET_DETERMINED`/`NOT_ADJUDICATED`
(non-affirmative sentinels) unless a scanner or a later adjudication step already set a real
value — so `reportable` fails closed by construction until real applicability evidence exists
(R06/FIX01I for Resource Guard — task #41; JS reachability for the other five — task #32).

`scanner_candidate` is derived from each scanner's own real verdict vocabulary, not "present in
the findings list" — checked directly: R04/R05's own `findings` list mixes the real positive
verdict (`VALUE_ACQUISITION_GUARD_MISSING`) with abstentions/inapplicable/build-conflict records
and the real negative verdict (`VALUE_ACQUISITION_GUARD_ESTABLISHED`); only the first is a real
candidate. `LOCK_BALANCE`/`PROTECTED_FIELD`/all three OOB properties were checked directly too
and confirmed to contain only real candidates already.

**Re-verified with the exact same real diagnostics, now correctly**: node-libcurl's real finding
comes back `scanner_candidate=True`, `provenance.resolved=True`,
`applicability_status=NOT_YET_DETERMINED` (never fabricated as `APPLICABLE`), and — the point of
this fix — **`reportable=False`**. `LOCK_BALANCE`/`PROTECTED_FIELD`'s own real findings resolve
the same way (provenance resolved, `scanner_candidate=True`) but also correctly stay
`reportable=False` by default, since no applicability/adjudication evidence exists for them
either yet. 40/40 real checks (up from 29), including explicit tests for each of the formula's
four clauses independently and the one combination that legitimately produces `reportable=True`.

Every `actionable=True` mention above (round 2's own text, kept for the real history) should now
be read as: provenance resolved correctly, but reportability was never actually established by
that alone — the field itself has been renamed and its semantics narrowed precisely because that
conflation was a real defect, not merely a naming issue.


  positive finding.

**A real, disclosed gap #35's own implementation surfaced**: the already-collected R04/R05
corpus data (the stopped 452/494-row `full_scan_r05_working.jsonl`) predates this fix and has no
provenance fields at all. If a future run's output is ever merged with that historical data, the
schema mismatch needs explicit handling (e.g. a `provenance: null` marker on old rows), not a
silent assumption both halves look the same.

Two explicit conditions govern when a task is genuinely non-gating for the overall run:

- **#31 stays non-gating only if #35 (source path + content hash, at scan time, for every
  property) is done first.** Without that data captured before the source tree is deleted,
  vendored provenance and cross-package deduplication cannot be reconstructed after any run
  completes — for any property, not only the ones already observed hitting vendored code.
- **#33 alone does not clear `OOB_COMPARE` for enablement.** Finding a real positive example
  would only prove `OOB_COMPARE`'s own property logic is sound — it would still need the same
  cross-language reachability (#32) and source provenance preservation (#35) every other native
  finding needs before being reported as a demonstrated npm-package vulnerability. #33 remains
  the reason `OOB_COMPARE` must stay fully DISABLED (not merely unattributed) until real
  positive-path evidence is found or the property is retired — its own zero-candidate output
  must never be reported as a meaningful negative while #33 is open — but #32 and #35 apply to it
  exactly as they apply to the other four properties.

| Property | Task tracker gate | Blocked by | Status |
|---|---|---|---|
| `FALLIBLE_BOUNDED_RESOURCE` (Resource Guard) | #41 — Merge R06/FIX01I into the driven lineage, rerun gates | R06/FIX01I integration (real, not yet done) | **NOT clear — corrected on direct instruction.** The prior "effectively clear, reachability logic already comes from R06/FIX01I" claim was checked directly and found false: `git diff` between the provenance branch and `claude/r06-fix01i-integration` shows R06/FIX01I's own real work lives entirely in a separate file, `resource_guard_verdict_r06.py` (922 new lines), never merged into `resource_guard_verdict_r04.py`/`_r05.py` — the exact two files `run_pipeline_one.py` actually calls. #35 (provenance) IS genuinely closed for this property; R06/FIX01I integration is real, separate, not-yet-done work. |
| `LOCK_BALANCE` | #36 — Enable in staged run | #32, #35 | #35 satisfied (verified with a real positive diagnostic, not just zero-finding runs); #32 (tiered reachability) still open |
| `PROTECTED_FIELD` | #37 — Enable in staged run | #32, #35 | #35 satisfied (same real verification); #32 still open |
| `OOB_WRITE` | #38 — Enable in staged run | #30, #32, #35 | #35 satisfied; #30, #32 still open |
| `OOB_READ` | #39 — Enable in staged run | #29, #30, #32, #35 | #35 satisfied; #29, #30, #32 still open |
| `OOB_COMPARE` | #40 — Enable in staged run | #33, #32, #35 | #35 satisfied; #33, #32 still open |

**#34 is the SIX-property aggregator** (Resource Guard's own gate #41, plus #36-40), ready only
when all six are individually satisfied. #35 no longer appears as an open blocker for any
property — it is genuinely done, verified with real positive diagnostics for every property that
currently has one available (Resource Guard, `LOCK_BALANCE`, `PROTECTED_FIELD`). What remains
per property: `FALLIBLE_BOUNDED_RESOURCE` needs #41's own real R06/FIX01I integration work;
`LOCK_BALANCE`/`PROTECTED_FIELD` need #32; the three OOB properties need their own
already-tracked combination of #29/#30/#32/#33.

### What #35 preserves, at scan time, verified real per the corrected six fields

Provenance classification itself (#31) may happen later, but the evidence it needs cannot be
recreated once a run's source tree is deleted — #35's own work, now implemented and verified,
captures for every finding before that deletion:

1. package name and pinned version;
2. **two** real, distinct tree-level hashes (corrected from an initial single mislabeled hash):
   `tarball_sha256` (the original tarball's own bytes) and `source_tree_sha256` (a real,
   deterministic hash of normalized relative paths + content hashes, independent of tarball
   compression/extraction/walk order — verified to stay identical across different tarball
   bytes wrapping the same real content, and to change when real content changes);
3. the exact relative source path of the finding's own site;
4. a content hash of that specific source file (verified against an independently recomputed
   hash of the real file, for every real positive diagnostic run);
5. the finding's own line/node identity (already present, unregressed — `method_id` for
   R04/R05/`LOCK_BALANCE`/`PROTECTED_FIELD`, the new additive `call_id`/`function_id` for the
   three OOB candidate producers);
6. a best-effort package-authored-vs-vendored flag, only where already cheaply determinable at
   scan time — not a substitute for #31's own later, authoritative classification;
7. **fail-closed `reportable`** (round-3 corrected name and semantics — `provenance["resolved"]`
   is necessary but never sufficient on its own): `finding["reportable"]` is computed by the
   one-way formula in the round-3 correction above, requiring `scanner_candidate` +
   `provenance.resolved` + `applicability_status == "APPLICABLE"` +
   `adjudication_status != "CONFIRMED_FALSE_POSITIVE"` all at once. A finding that cannot be tied
   to a real file, is not a real scanner candidate, has no established applicability, or has
   already been adjudicated a false positive is never reportable — retained for diagnostics,
   never silently treated as equivalent to a resolved-and-reportable one.

## Task #29: `src_capacity_bytes: 5` anomaly — root cause found and fixed

The pilot's `re2@1.26.1` evidence bundle showed 6 of 7 real `OOB_READ` candidates sharing an
identical, implausible `src_capacity_bytes: 5` — including a site whose "source" was a
function-pointer-typed struct field (`c->callback_` in abseil's `mutex.cc`), which cannot
structurally have a byte capacity of 5.

**Root cause (confirmed against real, freshly rebuilt `c2cpg` facts, not by reasoning alone):**
`oob_read_verdict.py` joined source-capacity facts to a read site with a single dict keyed only
by `storage_value_id`:
```python
scap={f['storage_value_id']:f for f in json.load(...)['src_capacities']}
```
A field access (`p->buf`, `spec->expstr`, `c->callback_`, ...) collapses `storage_value_id` to the
sentinel `-1` — this is the same `CAP-KEY-R01` rule `oob_write_verdict.py` already documents and
correctly handles by joining FIELD-kind facts by `call_id` instead. `oob_read_verdict.py` never
had that split. In the real `re2` bundle there is exactly ONE real FIELD-kind `src_capacities`
fact in the whole package (a real, unrelated `char[5]` struct member). Because every one of the 7
real `OOB_READ` candidates' own field-identity resolution also produces `id: -1`, all 7
spuriously collided on the shared sentinel key `-1` and all reported that one unrelated fact's
capacity (5), regardless of which struct member, function, or file they actually touched.

**Verification before fixing anything:** printed each of the 7 real candidates' own `call_id` and
`READ_SRC` `value_ref`. Six had `call_id`s that did not match the real FIELD fact's own
`call_id` (30064827809) — confirmed spurious. The seventh, `RoundTripFloatToBuffer:804`
(`memcpy(out, spec->expstr, 4)` in `vendor/abseil-cpp/absl/strings/numbers.cc`), had a `call_id`
numerically identical to the fact's `call_id`. Checked directly against the real `calls` and
`functions` tables (not assumed): the call's own `enclosing_function_id` (107374187742) exactly
matches the fact's `function_id`, and the fact's own `derivation.source_node_ids` points directly
at this exact call. This is a genuine match, not a coincidence — after the fix, this one site
correctly resolves `src_capacity_bytes: 5` for `spec->expstr`, while the other 6 correctly abstain.

**Fix:** `oob_read_verdict.py` now mirrors `oob_write_verdict.py`'s `dcap`/`dcap_by_call` split —
`scap` (VALUE_ID facts, keyed by `storage_value_id >= 0`) and `scap_by_call` (FIELD facts, keyed
by `call_id`), with a `_capfact` resolution that tries the VALUE_ID lookup first, then the
per-call FIELD lookup. Verdict logic itself is otherwise unchanged.

**Re-verification after the fix, against the same real `re2` bundle:**
```
OOB_READ CANDIDATES: 1
  CANDIDATE OOB_READ  RoundTripFloatToBuffer:804:memcpy  src_cap=5B
```
The 6 spurious candidates are gone; the 1 genuine one remains, with the correct capacity.
`oob-write-r05-sizeof` and `oob-compare-r07` (the two dedicated OOB gates that currently run in
this environment) pass unchanged — neither touches `oob_read_verdict.py`. `check_provenance.py`'s
40/40 also pass unchanged. The repo's own `tools/oob_read_controls.py`/`oob_write_controls.py`
(guard-r01) could not be re-run in this session: both depend on an external
`/tmp/cap_corpus/g.json` fixture built by an untracked process in an earlier session that no
longer exists in this container — confirmed environmental, not a regression, since the untouched
sibling `oob_write_controls.py` fails identically on the same missing fixture. In its place, a new
self-contained regression test, `tools/oob_read_capkey_controls.py`, was added (does not depend on
any external fixture) covering: the ordinary VALUE_ID join path still resolving correctly
(regression check), the FIELD join resolving correctly at its own matching `call_id`, the FIELD
sentinel no longer spuriously matching an unrelated `call_id`, and the existing
`SOURCE_CAPACITY` bound-suppression path — all 5/5 pass.

Code fix lives on `claude/provenance-preservation-task35` (the branch carrying the rest of the
OOB/PROV-R01 work this fix builds on), not this documentation branch. Task #29 is complete;
`OOB_READ` (gate #39) remains blocked on #30, #32 (still open), not on #29 any further.

### Correction to the #29 writeup above: the surviving candidate is a confirmed negative, not a positive

The #29 section above states the fix correctly (6 spurious sentinel-collision candidates removed;
`RoundTripFloatToBuffer:804` is a genuine `call_id`/`function_id` match, not a coincidence) but
stops short of stating what that genuine match actually means, which must be precise:

- The genuine source-capacity association is real: `spec->expstr` really does have capacity 5.
- It is **not** an OOB-read positive. `memcpy(out, spec->expstr, 4)` copies a compile-time-literal
  `4` bytes from a compile-time-derived 5-byte source — checked directly against the real facts
  (`extent arg: {'code': '4', 'kind': 'LITERAL'}`, `capacity_bytes: 5`). `4 <= 5`: this is a
  **confirmed-safe negative**.
- The scanner's own `verdict: 'CANDIDATE'` on this site does not encode that safety judgment —
  unlike `oob_write_verdict.py`'s `STATIC_EXTENT_SAFE` check (which recognizes `sizeof(dest)` as
  compile-time-safe), `oob_read_verdict.py` has no equivalent numeric-literal-vs-capacity static
  check. `CANDIDATE` here means only "representable, and no `BoundFact`-derived guard was found for
  this extent" — the safety call above required direct inspection of the real facts, not scanner
  output alone. (Whether to add a read-side static-safety check, mirroring the write side, is a
  separate, not-yet-opened design question — not assumed here.)

**Net result: task #29's fix is real and correct (it removed 6 genuinely spurious candidates), but
it did not reproduce an `OOB_READ` positive.** `OOB_READ` still has zero reproduced real positives.
That remains entirely contingent on #30 (the Tremor CVE-2018-5147 reproduction discrepancy) — if
Tremor's case cannot be reproduced, gate #39 must stay closed for missing positive-path evidence,
independent of anything #29 established.

### New follow-up: #42, the guard-r01 OOB control-gate fixture is not reproducible from a clean checkout

`tools/oob_read_controls.py` and `tools/oob_write_controls.py` (the repo's own historical,
richer OOB control gates — isolation checks, bound-suppression edge cases, and more, beyond the
CAP-KEY-R01 join logic) depend on an external `/tmp/cap_corpus/*.json` fixture that was built by
an untracked process in an earlier session and no longer exists in this container. This was
confirmed environmental, not caused by the #29 fix: the untouched `oob_write_controls.py` fails
identically on the same missing file. The new `tools/oob_read_capkey_controls.py` (5/5,
self-contained, added by #29) verifies only the CAP-KEY-R01 sentinel-key fix in isolation — it is
not a substitute for the full historical gate.

Task #42 tracks this and now blocks both #38 (`OOB_WRITE`) and #39 (`OOB_READ`) enablement. Before
either is enabled: rebuild and commit the missing fixture (or a script that deterministically
regenerates it from real source via the repo's own `c2cpg` pipeline), or replace the two
fixture-dependent control scripts with a fully self-contained equivalent covering every assertion
they currently make.

No corpus run follows from any of this — `OOB_READ` remains blocked by #30, #32, and #42;
`OOB_WRITE` remains blocked by #30, #32, and #42.

### Task #43: read-side numeric extent reasoning (STATIC_EXTENT_SAFE), implemented

Direct follow-up from the round-2 correction above: `oob_read_verdict.py` had no equivalent of
`oob_write_verdict.py`'s `STATIC_EXTENT_SAFE` check, so the confirmed-safe `RoundTripFloatToBuffer`
site (`4 <= 5`) was still being reported as `verdict: CANDIDATE` even after the #29 join-key fix.

Implemented `is_static_extent_safe(src_code, ext_code, ext_kind, capacity_bytes)` in
`oob_read_verdict.py`, mirroring the write side's provenance-distinct-safety-reason architecture,
with two conjoined-narrow forms:

1. extent is exactly `sizeof(the read source)` — symmetric to the write side's `sizeof(dest)` case;
2. extent is a compile-time integer literal, and the source's own capacity is a known compile-time
   integer — safe iff `literal <= capacity`.

Anything that doesn't cleanly match one of these two forms (an expression, a macro, a variable, a
hex/suffixed literal) stays a `CANDIDATE` — conservative, no new false negatives. Re-verified
against the real `re2` bundle: `OOB_READ CANDIDATES: 0` — `RoundTripFloatToBuffer:804` is now
correctly excluded, since it was the only genuine candidate remaining after #29's fix. A new
self-contained test, `oob_read_static_extent_safe_controls.py` (13/13), covers the boundary
(`literal == capacity`, safe), the unsafe direction (`literal > capacity`, must stay a candidate),
the `sizeof(src)` form and a mismatched-identifier `sizeof` (must not be suppressed), non-literal
extents, and the conservative hex/suffixed non-matches — plus an end-to-end reconstruction of the
real re2 shape alongside a genuinely-unsafe sibling site that correctly remains a candidate.

**Combined-reporting guarantee, made explicit rather than assumed:** a new test,
`check_oob_reportable_gate.py` (13/13, in `semantic-bucket-pilot/scanner-v2/`), verifies directly
that a raw `CANDIDATE` record from any of the three OOB producers (`oob_write_candidates` /
`oob_read_candidates` / `oob_compare_candidates`) never becomes `reportable=True` through
`provenance.enrich_record()` merely because its source file resolved — for all three OOB
candidate keys, not just OOB_READ — plus a positive control confirming the gate correctly opens
once real, non-fabricated affirmative applicability evidence exists. This closes the same
architectural risk `finalize_reportability()`'s formula was already designed to prevent (#35),
now verified specifically for the OOB producers rather than assumed to hold by construction.

Task #43 is complete. #39 (`OOB_READ` enablement) no longer risks reporting avoidable
statically-safe candidates once it is enabled — but #39 remains blocked by #30 (Tremor —
`OOB_READ` still has zero reproduced real positives) and #32 (tiered reachability), and both #38
and #39 remain blocked by #42 (the missing guard-r01 control-gate fixture) until that gate is
either rebuilt or replaced with a fully self-contained equivalent. No corpus run follows from this.

### Task #30: the Tremor CVE-2018-5147 "discrepancy" reconciled -- it was never a real discrepancy

The original suspicion (Section 3.3 above): this pilot's own direct reproduction found 0
candidates on the real Tremor VULN/PATCHED fixture, which "does not match the
previously-documented `e2e-canonical/SUMMARY.txt` result" (`VULN dir -> candidates: 1`), with "a
real difference in preprocessing mode" proposed as "the leading candidate explanation" -- stated
as genuinely unresolved at the time.

**Directly inspected the actual e2e-canonical artifacts** (`vuln.report.json`,
`vuln.llm_input_1.json`) rather than trusting the `SUMMARY.txt` label. Result: **zero** references
to `tremor`/`codebook`/`vorbis` anywhere in either report. The only file either report ever
analyzed is `WinWebAuthnManager.cpp`; the one real candidate is `finding_id:
oob-index-write:c_cpp#L298:rgExtension`, an `INDEXED_STORE_INTO_FIXED_CAPACITY_ARRAY` shape
(`rgExtension[cExtensions]`) from `oob_index_write_verdict.py` -- and per
`MOZ-OOB-R01-PREREG.md:249`, this is Mozilla bug **mfsa2022-13** (`WinWebAuthnManager::Register`),
a *completely different, unrelated* Mozilla memory-safety CVE. The two data points the earlier
pilot compared were never about the same fixture. There is no cross-run inconsistency to explain;
the "preprocessing mode" theory was answering a question that didn't need asking.

**Re-verified Tremor's own real result is reproducible and mechanically explained.** Freshly
rebuilt the real VULN/PATCHED bundles this session (fresh `c2cpg` -> `export` -> `normalize`,
not reused from before): both `oob_write_verdict.py` and `oob_index_write_verdict.py` still
produce 0 candidates on both files, matching the earlier pilot exactly. Root cause, now precisely
diagnosed rather than left as a gap: the real vulnerable buffer in
`vorbis_book_decodevs_add`/`decodev_add`/`decodevv_add` is a **pointer parameter**
(`ogg_int32_t *a`), whose true capacity is carried by a **separate runtime parameter** (`int n`) —
not a fixed-size local array `T[N]`. Confirmed mechanically against the real facts: the whole
file's `dest_capacities` count is 0, and no local variable named `a` exists at all (it is a
parameter, invisible to the local-array-capacity deriver both current OOB_WRITE producers depend
on). Neither `oob_write_verdict.py` (memcpy-family calls with a directly-typed destination) nor
`oob_index_write_verdict.py` (fixed-size `T[N]` locals only) models a pointer-parameter buffer
whose capacity is carried by a sibling parameter — the classic C "buffer + length pair" API
convention, extremely common in codec/parser code exactly like this one.

**The preprocessing theory was also directly, separately ruled out** on the correct fixture:
`cpp -E` cannot even run on this standalone `.c` file (`ogg/ogg.h` is not part of this
repository, never was — this file was never part of a buildable tree here), so
`scan_repo.py --preprocess` would have *skipped* it entirely had it ever been pointed at Tremor.
And even where preprocessing can run, it could not plausibly have changed this specific outcome:
the vulnerable loop bounds (`o+j`, `n`, `book->dim`) contain zero macros.

**Net: task #30 is genuinely reconciled.** No discrepancy exists to resolve; the real, standalone
finding is that this repository's current `OOB_WRITE` implementation family has a real, precisely
diagnosed capability gap (pointer-parameter + separate-length-parameter buffers), tracked as new
task **#44**, which now blocks #38 (`OOB_WRITE` enablement) in #30's place — #30 itself is closed.

| Property | Task tracker gate | Blocked by | Status (updated) |
|---|---|---|---|
| `OOB_WRITE` | #38 — Enable in staged run | #32, #42, #44 | #35 satisfied; #30 resolved (was a false discrepancy, not a real blocker); #44 (new) tracks the real, diagnosed pointer+length-parameter capacity gap |

No corpus run follows from this.

### Task #44: PARAM-CAP-R01 — evidence-backed pointer-parameter + length-parameter capacity

Real implementation on `claude/provenance-preservation-task35` (`tools/param_length_capacity.py`
+ additive wiring into `tools/oob_index_write_verdict.py`). Full design and required-control
status below; **this task is NOT marked validated, and #38 (`OOB_WRITE` enablement) stays
blocked on it** — the design carries real, disclosed scope limits, not full coverage.

**Evidence model (not a "pointer followed by integer" heuristic):** pairing a pointer parameter
`P` with its real length parameter `L` requires REAL evidence from two combined sources, both
directly verified against real Tremor facts before being trusted:
1. A bounded backward chase through the function's own real `assignments` facts, starting from
   the write's index expression's own identifier tokens. Catches `vorbis_book_decodevs_add`'s
   real chain `step=n/book->dim; o+=step`. `reachingdef.json` was checked directly on the real
   Tremor bundle and found to cover only 3 narrow loop-counter locals (not `step`, not
   parameters) — insufficient for this evidence, so `assignments` facts are used instead.
2. A real, non-assert `<`/`<=` comparison, identity-matched (`value_ref.kind=='PARAMETER'`, not
   text alone) to a real integer parameter — catches `for(i=0;i<n;)`-shaped loop bounds.

Zero candidates → abstain (correctly excludes an unrelated adjacent integer parameter that the
index never actually references). Two or more → abstain, explicitly ambiguous, never guessed.

**Byte-vs-element:** an index-store write (`arr[idx]`) is inherently element-counted; a
`sizeof(...)` scaling factor in the index expression abstains rather than risk a silent unit
mismatch. **Pointer offsets:** one hop of `param + literal` pointer arithmetic reduces the real
capacity by the literal; a non-literal offset abstains rather than guess. **Overflow:** an
`L * sizeof(...)`-shaped expression is flagged untrustworthy when `L`'s own type isn't provably
wide enough — gates call-site allocation-size corroboration so an overflow-prone product is never
trusted as a sound capacity. **Interprocedural corroboration:** real, but honestly scoped —
unambiguous call sites (`resolution=='EXACT'`, one `candidate_target_ids` entry) with a literal
length argument, non-gating enrichment only. No cross-TU allocation-size tracing exists anywhere
in this codebase's exported facts today (checked directly) — this module does not fabricate that
capability.

**Ownership decision (verified, not assumed):** this belongs to `OOB_INDEX_WRITE`
(`oob_index_write_verdict.py`), not the memcpy-surface `OOB_WRITE`. Directly confirmed:
`oob_write_verdict.py` produces 0 candidates on both real Tremor VULN and PATCHED bundles (no
`memcpy`-family call exists at either site at all) — there is no duplicate-finding risk between
the two producers for this shape.

**Required controls (`tools/param_length_capacity_controls.py`, 13/13):** Tremor VULN (real,
freshly rebuilt via `c2cpg` — `a[o+j]` correctly flagged, `length_param=n`) and PATCHED (real,
correctly suppressed); OOB_WRITE non-duplication (real, both files); a correctly bounded
pointer/length loop; an unrelated adjacent integer parameter (correctly excluded); byte length vs
element count (correctly abstains); pointer arithmetic reducing capacity (literal resolved,
non-literal correctly abstains); multiple possible length parameters (correctly ambiguous);
overflow in `n*sizeof(*a)` (narrow flagged, wide not, no-multiplication not flagged).

**Honest, disclosed scope limits — why this is not "validated" yet:**
- Of Tremor's 3 real vulnerable sink functions, only `vorbis_book_decodevs_add` is detected
  end-to-end (candidate on vuln, suppressed on patched).
- `vorbis_book_decodev_add`'s real pairing (`a[i++]`, bounded by the OUTER `for(i=0;i<n;)`) is
  correctly IDENTIFIED but the write abstains on BOTH vuln and patched: the outer loop's `i<n`
  condition is textually unchanged between the two files (the real fix adds a bound inside the
  nested INNER loop instead), and this producer's guard analysis remains
  intraprocedural/heuristic, not dominator-based — the same tradeoff already documented for the
  pre-existing fixed-array logic. Directly confirmed: treating the loop-bound comparison as a
  SUPPRESSION signal (not just an identification signal) would suppress the real vulnerable
  candidate too, since the same `i<n` text exists in both files.
- `vorbis_book_decodevv_add`'s real vulnerability is on a NESTED/2D index (`a[chptr++][i]`, the
  second dimension) — entirely outside this producer's existing single-level `indexAccess` model,
  a limitation shared with the pre-existing fixed-array logic, not newly introduced here.

**Net:** a real, substantive, evidence-backed capability now exists and correctly reproduces one
of Tremor's three real sinks end-to-end, with the other two abstaining for clearly diagnosed,
pre-existing-shaped reasons rather than silently. #44 remains open (not completed) pending review
of these scope limits; #38 (`OOB_WRITE` enablement) stays blocked on it. No corpus run follows
from this — a diagnostic-only run may still generate and preserve evidence once scheduled, but it
cannot yet support a meaningful negative claim about pointer-parameter writes at corpus scale.

### Task #44 phase 2: real CFG dominance + loop-iteration reasoning for `vorbis_book_decodev_add`

Direct follow-up on the review that phase 1 was "one of three vulnerable sinks recovered — not
sufficient for promotion," and that textual guard matching cannot prove whether a guard dominates
the dangerous index on all relevant loop paths. Confirmed exactly as predicted: plain textual
existence AND plain CFG dominance were BOTH insufficient for `vorbis_book_decodev_add`'s real
case — its outer `for(i=0;i<n;)` genuinely dominates the write in both the vulnerable and patched
source (nothing bypasses it structurally), yet the vulnerability is real, because that check is
evaluated only ONCE per outer iteration while the write executes repeatedly per outer pass via the
inner loop's own back-edge, unprotected on every pass after the first. The real fix instead adds
a check to the INNER loop's own header (`for (j=0;i<n && j<book->dim;)`), re-evaluated every
iteration.

**New module, real machinery reused, not reinvented:** `tools/cfg_loop_guard.py`'s
`loop_iteration_safe_dominates()` builds on the SAME dominator-tree code already gated and used
elsewhere in this repo (`allocation_extent.build_cfg_index`/`_dominates`, from
`call_context_guard.py`'s real NSS CVE-2019-17006 work) — no new CFG algorithm, only a new
composition of it. A guard protects a write on EVERY execution iff it dominates the write AND is
at-or-inside the write's own innermost enclosing loop (dominated by, or equal to, that loop's own
header — identified from real back-edges, `(u,v)` where `v` dominates `u`, computed from the same
dominator data). Verified directly against the real Tremor bundles BEFORE being trusted (see
`param_length_capacity_controls.py`): the outer `i<n` fails this check in both files; the real
fix's new inner-loop guard passes it, in both files, correctly.

**Polarity, honestly scoped, not oversold:** for a guard that IS (or feeds directly into) the
loop's own header condition, C loop semantics themselves prove the polarity — no separate graph
search re-derives that guarantee. Full control-dependence + branch-polarity proof for a guard
merely somewhere INSIDE a loop body (not its own header) — the harder case `call_context_guard.py`
solves for straight-line, pre-call guards — remains open here, disclosed rather than assumed
sound. The caller additionally requires the comparison operator to be `<`/`<=` with the write's
own index as the LHS (never a reversed operand order, never `>`/`>=`), ruling out an
accidentally-reversed-polarity guard by construction rather than by a general proof.

**Real re-verification:** `vorbis_book_decodev_add`'s real sink (`a[i++]`) is now detected
end-to-end — candidate on VULN, suppressed on PATCHED — using the same real, freshly-rebuilt
bundles as before. `vorbis_book_decodevv_add` is explicitly re-verified as still correctly
abstaining, per direct instruction NOT to add an ad hoc flattening rule: its real vulnerability
is on a nested/2D index (`a[chptr++][i]`), entirely outside this producer's single-level
`indexAccess` model, and remains an honest, disclosed unsupported case rather than a guessed
result.

**Required controls (`tools/cfg_loop_guard_controls.py`, 9/9):** dominating vs non-dominating
guards; branch polarity (structurally restricted to `<`/`<=` only, verified by inspecting the
source); loop-entry vs loop-back paths (both directions, the exact `decodev_add` discriminator);
an unrelated early-exit distractor branch not confusing the analysis; a guard occurring after the
write not crediting it; a guard on the wrong index/object not suppressing (end-to-end, through the
real matching key). `param_length_capacity_controls.py` is now 16/16 (both real Tremor sinks, the
`decodevv_add` non-flattening check, and all phase-1 controls).

**Current coverage on the Tremor development case, updated:**

| Component | Status |
|---|---|
| Pointer/length pairing | Implemented and controlled |
| `decodevs_add` | Vulnerable/patched differential recovered |
| `decodev_add` | Vulnerable/patched differential now recovered (real CFG dominance + loop-iteration reasoning) |
| `decodevv_add` | Unsupported (explicit) — nested/2D index, no ad hoc flattening added |
| Duplicate ownership | Correctly assigned to `OOB_INDEX_WRITE`, verified (0 duplicate candidates on real Tremor bundle) |
| Cross-TU capacity evidence | Unavailable; correctly abstains |

**Two of three real vulnerable sinks now recovered end-to-end.** #44 remains open (not
completed/validated) — `decodevv_add` is explicitly unsupported by design rather than silently
missed, and full control-dependence/branch-polarity proof for loop-interior (non-header) guards
remains a disclosed, unimplemented refinement. #38 (`OOB_WRITE` enablement) stays blocked until
#44 is reviewed and its gate is reproducible per direct instruction — the 100-package overnight
diagnostic run may proceed independently once scheduled, but `OOB_INDEX_WRITE` must remain
non-reportable during it. No corpus run follows from this.

## Overnight 100-package frozen diagnostic run: launched

Real, non-fabricated launch record. Full implementation on `claude/overnight-diagnostic-100`
(branched from `claude/provenance-preservation-task35` @ `40a447b`).

**Integration branch composition** (cherry-picked, hashes recorded in each commit; never a blind
merge that could reintroduce a stale scanner copy from another branch):
- `evidence_bundle.py` + `run_pipeline_one_r06.py` (reference) + tests, from
  `claude/r06-fix01i-integration` @ `0463bd6` — the real, tested, atomic-write, gzip-compressed
  per-package evidence bundle capability (task #15).
- `promote_via_js_linkage.py`, same source — cherry-picked for record, but **NOT used** in this
  run's pipeline (hard, module-level import dependency on `resource_guard_verdict_r06.py`, which
  this branch deliberately excludes since #41 has not merged R06/FIX01I into the driven r04/r05
  lineage). Reachability defaults to `REACHABILITY_UNRESOLVED` for every finding this run
  produces, consistent with task #32 not being complete.
- FIX01I crosslang linker (`export_neutral.sc`, `normalize_joern_facts.py`,
  `frontends/polyglot/link_napi_facts.py`), same source — the frozen, gated cross-language
  revision. Re-verified on this branch: `gate_crosslang_link_fix.py` passes.
- Explicitly **did not** take `resource_guard_verdict_r06.py` — Resource Guard on this run uses
  the already-driven, already-gated r04/r05 lineage, labeled `PRECISION_FIX_NOT_INTEGRATED`.
- Real corpus-wide primitive-coverage evidence (`primitive_search_results.jsonl`, all 494/494
  eligible packages, task #28), cherry-picked from `claude/oob-lockbalance-integration-pilot` @
  `94bf8c2` — used for real, non-fabricated stratified sample selection, never re-derived.

**provenance.py extended**: `oob_index_write_candidates` (task #44's own producer, driven for
the first time in this run) was never enriched by `provenance.enrich_record` before this —
extended, verified (`check_oob_reportable_gate.py` now 17/17, `check_provenance.py` still 40/40).

**Pre-launch gate battery**: every currently-reproducible gate passes (`prelaunch_gates.log`,
committed) — `check_provenance` 40/40, `check_oob_reportable_gate` 17/17, the adapted
`evidence_bundle` tests, `gate_crosslang_link_fix`, `oob_read_capkey_controls` 5/5,
`oob_read_static_extent_safe_controls` 13/13, `param_length_capacity_controls` 16/16,
`cfg_loop_guard_controls` 9/9, the frozen `oob-index-r01` gate 9/9, `oob-write-r05-sizeof`,
`oob-compare-r07`, `check_lock_balance` 11/11, `check_protected_field` 11/11,
`gate_resource_guard_r04` 12/12, `gate_resource_guard_r05` all pass. Explicitly recorded and
NOT reproducible: guard-r01's OOB control gate (task #42, missing external fixture from an
untracked prior-session process) — this is why OOB output stays diagnostic in this run.

**100-package sample, frozen**: `select_overnight_sample.py` — 75 deterministic greedy
stratified + 25 deterministic random (seed 20260831), built entirely from prior, already-
completed pipeline evidence, never from this run's own output. Deduplicated by real, freshly-
computed `source_tree_sha256` (100/100 unique, 0 replacements needed). All 5 forced-inclusion
packages present (node-libcurl, node-crc16, re2, `@2060.io/ffi-napi`, node-snap7). All 19 real
coverage strata covered.

**`run_diagnostic_100.py`**: additively wires all six property scanners onto the real, proven
`run_pipeline_one.py` stages (never modifies that file). `diagnostic_only` mode (always on):
`enforce_diagnostic_only()` forces `reportable=False` on every finding across all six
properties after `provenance.enrich_record()` runs, preserving `scanner_candidate`, raw verdict,
evidence, `applicability_status`, `adjudication_status` untouched;
`preflight_assert_non_reportable()` independently re-checks and aborts if any record is ever
found with `reportable=True`. Real diagnostic labels: `PRECISION_FIX_NOT_INTEGRATED` (Resource
Guard), `UNVALIDATED_PROPERTY` (`OOB_COMPARE`), `DEVELOPMENT_ONLY` (PARAM-CAP-R01 candidates
specifically — the pre-existing `SYNTACTIC_ELEM_COUNT` fixed-array candidates are NOT labeled
development-only), `REACHABILITY_UNRESOLVED` (all findings). Checkpointing: one record per
line, flushed+fsynced immediately; immutable checkpoints every 10 packages; resume by
`(package_name, version, source_tree_sha256)`; duplicate completed keys refused via a running
`written_keys` set. Resource settings: `NPM_CORPUS_TIMEOUT_MULTIPLIER=5` set before importing
`run_pipeline_one.py` so its own `STAGE_TIMEOUT`/`NORMALIZE_TIMEOUT` land on exactly 900s;
`SCAN_TIMEOUT` overridden to exactly 300s; workers capped at 2; free-disk checked before/after
each package (5GB floor). Stop conditions (>3 consecutive same-stage failures; free disk below
floor) checked incrementally via a proper streaming worker loop
(`concurrent.futures.wait(FIRST_COMPLETED)`, not a batching `.map()`), so in-flight work drains
and a checkpoint is written before the run actually stops.

**Forced-interruption handling**: `install_signal_handlers()` traps SIGTERM/SIGINT and writes an
emergency partial `evidence_bundle` for whatever real evidence exists on disk for any in-flight
package before exiting (SIGKILL cannot be caught by anything — disclosed, not assumed away).

**Full 7-point smoke test (section 6), all real, all passed**: node-crc16 (small), node-libcurl
(medium — reproduced its known real `r05` false-positive finding, `Easy::ReadFunction`, exactly
as established earlier this session), re2 (large, 551 files) — all evidence bundles reopen;
every scanner has independent output keys, no collisions; provenance paths/hashes resolve;
`reportable=False` everywhere (0 across every finding in every smoke run); resume does not
duplicate (0 reprocessed when nothing pending, exactly 1 when 1 was pending); a forced SIGTERM
mid-package (node-snap7) produced a real `PARTIAL` bundle, correctly refused by
`require_complete_bundle()`; resume correctly reprocessed the interrupted package fresh.

**Launch**: real 100-package background run started, `--workers 2 --resume --diagnostic-only`,
confirmed healthy in flight (2 packages already `ANALYZED` — node-crc16, node-libcurl — with re2
and `@2060.io/ffi-napi` processing concurrently at the moment of this check). The remaining 394
packages are explicitly NOT launched, per direct instruction. A morning report (completion
status, per-stage timing, candidate counts by property, abstention counts, reachability-tier
distribution, resource limits hit, and confirmation that every record remained
`reportable=False`) will follow once the run completes or is next checked in — no vulnerability
totals, true-negative claims, or corpus-prevalence claims will be drawn from this diagnostic run.

## Task #31: vendored-vs-package-owned attribution and cross-package dedup — implemented

Directly resolves the "correction to the correction" above (§ line 19): a finding inside a
vendored third-party library must be classified, never silently discarded.

**Implementation** (`semantic-bucket-pilot/scanner-v2/vendored_attribution.py`, on
`claude/provenance-preservation-task35`, commit `e41be3b`):

- `extract_vendored_library_id(relpath)` derives real library identity by reusing
  `provenance.VENDOR_PATH_MARKERS` verbatim (never a second, divergent marker list) — the path
  segment immediately after whichever marker matched. Verified against the real re2 evidence:
  `vendor/abseil-cpp/absl/base/internal/strerror.cc` → `('abseil-cpp',
  'absl/base/internal/strerror.cc')`.
- `attribute_finding(finding, package_name)` attaches a `vendored_attribution` block — `status`,
  `vendored_library_id`, `relpath_within_vendor_dir`, `attribution` (exactly `"<library> as
  bundled by <package>"`, never an unqualified package finding), `dedup_key` — but ONLY when the
  finding's own `provenance.resolved` is true AND `provenance.provenance_hint == 'VENDORED_HINT'`.
  A `PACKAGE_OWNED_HINT` or `UNKNOWN` finding (e.g. re2's own `lib/pattern.cc`) is never touched;
  neither is a `VENDORED_HINT` finding whose provenance failed to resolve (no real path to
  attribute from). Attribution is additive and conditional, not a default classification.
- `aggregate_vendored_dedup(records)` / `summarize(agg)`: cross-package deduplication keyed on
  `(vendored_library_id, relpath_within_vendor_dir, content_hash, per-site signature)`. Using the
  finding's own real `content_hash` — not relpath+line alone — is what makes this sound: two
  packages bundling the exact same vendored file (byte-identical) correctly collapse to one
  deduplicated entry, while two packages bundling *different versions* of the same library at the
  same relpath (different bytes, different `content_hash`, so the vulnerable line may not even
  exist in the other version) correctly do NOT collapse. `relpath_within_vendor_dir` (the path
  *after* the library's own root) rather than the raw package-relative path means the same
  vendored file at a different nesting depth (`vendor/abseil-cpp/...` vs
  `third_party/abseil-cpp/...`) still dedups correctly. Reports `deduplicated_count` and
  `raw_exposure_count` as two separate headline numbers, always — a deduplicated bug count is not
  a corpus-exposure count, and this module never collapses the two into one.
- Deliberately does not touch reportability. Task #35's formula in `provenance.py` remains the
  sole authority on that question; this module only attributes and deduplicates what is already
  there.

**Verification** (`check_vendored_attribution.py`, 16/16 passing): 5 checks run against REAL live
evidence pulled directly from the running overnight-diagnostic-100 output — re2's own real
`vendor/abseil-cpp/absl/base/internal/strerror.cc` `oob_write_candidates` finding extracts
`vendored_library_id == 'abseil-cpp'`, attribution `'abseil-cpp as bundled by re2'`,
`relpath_within_vendor_dir` starting with `absl/`; re2's own real `PACKAGE_OWNED_HINT`
`oob_index_write_candidates` finding at `lib/pattern.cc` is confirmed never attributed. (Written
to SKIP gracefully, not silently, if the live run's re2 record isn't present at test time — it
was.) Remaining 11 checks: unit-level extraction (`vendor/`, `deps/`, no-marker path), three
never-attributed cases (`PACKAGE_OWNED_HINT`, `UNKNOWN`/unresolved, `VENDORED_HINT`-but-
unresolved), and three synthetic cross-package dedup scenarios (byte-identical file at two
different vendor roots → 1 dedup entry, `raw_exposure_count == 2`, both packages listed;
same relpath, different `content_hash` → 2 entries, no false collapse; two distinct real sites in
one file, differing by line+call → 2 entries, not 1).

Task #31 is complete. Downstream consumers (the eventual six-property aggregator, task #34; any
future corpus report) can now call `vendored_attribution.attribute_record()` /
`aggregate_vendored_dedup()` / `summarize()` to get classified, deduplicated vendored-exposure
numbers rather than either an unqualified package-attribution error or a silently dropped
finding.
