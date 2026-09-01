# Track B results: structural fixes for the two roadmap step 7 false-positive families

Per the controlling instruction: "Fix the scanner precision gaps... Implement the two structural
corrections documented by their manual review: lock-primitive wrapper recognition; OOB type/
extent equivalence. Then: 1. Keep the 13 adjudications as regression cases. 2. Rerun the
reachability and applicability gates. 3. Replay the 97 bundles. 4. Confirm the false positives
disappear structurally rather than only through the adjudication registry. 5. Freeze the
corrected native pipeline."

This document is step 5. Steps 1-4 below.

## 1. WRAPPER-SITE-R01: lock-primitive wrapper recognition (`lock_balance_verdict.py`)

**Root cause** (`STEP6_PROMOTIONS_MANUAL_REVIEW.md` section 1-2): Joern's c2cpg represents a
`static inline` C wrapper call (e.g. `ggml_mutex_lock_shared`) as TWO real call nodes at the same
`(owner, line, first_arg_code)` -- an outer wrapper-named node and an inlined-duplicate
primitive-named node -- but only ONE is actually wired into the real CFG per call site,
unpredictably (even within one function, the lock call used the inner primitive representation
while the matching unlock used the outer wrapper). This broke name-based
`LOCK_FUNCS`/`UNLOCK_FUNCS` matching.

**Fix**: group all calls by `(owner, line, first_arg_code)` into a `site_group`; whenever a
recognized LOCK/UNLOCK call is found, also add its own site-group siblings as barriers -- since
siblings sharing `(owner, line, arg0)` are, by direct construction, alternate representations of
the same real source statement.

**Regression controls** (`check_lock_balance.py`, sections 4-5): the two real target packages
(`@fugood/whisper.node@1.1.3`, `smart-whisper@0.8.1`) now come back `BALANCED_ON_ALL_PATHS`, zero
findings; a synthetic negative control confirms an unrelated wrapper-shaped name at a DIFFERENT
site is never treated as a barrier -- a genuine leak with no matching unlock anywhere is still
flagged. `LOCK_SAFE_R01=15/15` (11 pre-existing + 4 new).

## 2. OOB-EQUIV-R01: OOB type/extent equivalence (`oob_index_write_verdict.py`)

**Root cause** (`STEP6_PROMOTIONS_MANUAL_REVIEW.md` section 7-13, corrected): the scanner's own
`_in_assert()` helper checked whether a comparison's code text is a substring of ANY assert-macro
invocation ANYWHERE in the whole file -- unscoped, despite the helper's own comment already
documenting the intended scope as "single-file, same fn." On `@appthreat/sqlite3`'s 212,493-call
single-file amalgamation, an unrelated `assert(i<nCol)` elsewhere in the file happened to contain
`sqlite3_get_table_cb`'s own genuine `i<nCol` loop-bound comparison as a text substring, wrongly
suppressing the guard before the (already-correct) `PARAM_LENGTH_PAIR` dominance check ever ran.

**Fix**: scope `assert_codes` per `enclosing_function_id` (`assert_codes_by_fn`), matching the
helper's own already-documented intended scope.

**Regression controls**: all 9 pre-existing frozen `tests/gates/oob-index-r01/` fixtures
byte-for-byte unaffected (`OOB_INDEX_R01=9/9`) -- the frozen gate uses its own embedded copy of
`oob_index_write_verdict.py`, confirming this fix never touches historical regression fixtures.

## 3. The 13 adjudications stay untouched (instruction point 1)

`adjudication_registry.py`'s `KNOWN_STAGED_ADJUDICATIONS`/`KNOWN_ADJUDICATIONS` tables are
unmodified by this round -- confirmed directly: the same 6 entries from the promotions review
(2 `lock_balance_findings`, 4 `oob_write_candidates`) are still present, byte-identical.
`ADJUDICATION_REGISTRY_CONTROLS=22/22`.

## 4. Full pipeline gate suite (instruction point 2), zero regressions

| Gate | Result |
|---|---|
| `check_lock_balance.py` (LOCK_SAFE_R01) | 15/15 |
| `gate_oob_index_r01.py` (OOB_INDEX_R01, frozen) | 9/9 |
| `check_adjudication_registry.py` | 22/22 |
| `check_applicability_gate.py` | 23/23 |
| `check_provenance.py` | 51/51 |
| `check_reachability_tier.py` | 34/34 |
| `check_six_property_aggregator.py` | 18/18 |
| `check_staged_enablement.py` | 25/25 |
| `check_oob_reportable_gate.py` | 17/17 |

## 5. 97-bundle replay (instruction point 3): `rerun_aggregator_trackb.py`

Reruns both fixed scanners (`lock_balance_verdict.py` live; `oob_index_write_verdict.py`'s
`tchecker-research-complete` copy) fresh over the same 97 preserved evidence bundles -- no Joern
rebuild, no new download; both scanners' real inputs (`cpp_raw/*.tsv`, `cpp_facts.json`) are
already preserved per-bundle. `oob_write_candidates`/`protected_field_findings`/
`oob_read_candidates` are reused verbatim (untouched by either fix). Reruns the full downstream
pipeline (`reachability_tier` -> `applicability_gate` -> `adjudication_registry` ->
`staged_enablement` -> `vendored_attribution` -> `six_property_aggregator`) in the documented
real order. Output: `results/replay_records_v8.jsonl`, `results/trackb_rerun_delta.json`.

**A real bug found and fixed mid-round**: the first version of this script replaced
`lock_balance_findings`/`oob_index_write_candidates` with the two fixed scanners' fresh output,
but never re-ran `provenance.enrich_record()` (or equivalent) on them before the rest of the
pipeline. `provenance.finalize_reportability()` requires `finding["provenance"]["resolved"]`,
which was simply absent on every fresh finding -- `reportable` was silently forced `False` across
the board (`oob_index_write_candidates` funnel went `7 reportable -> 0`, not the correct `7 -> 5`).
Fixed (PROV-REUSE-R01, `rerun_aggregator_trackb.py`'s own docstring) by re-enriching each freshly
replaced finding's provenance, reusing the SAME record's own already-verified provenance (keyed by
`source_path`) from its other, untouched properties -- legitimate reuse (same package, version,
pinned tarball, source tree; not fabrication), avoiding a 97x re-fetch of pinned tarballs from
npm. Coverage confirmed 100%: `provenance_reuse_coverage: {n_reused_from_same_record: 3255,
n_fell_back_to_fresh_enrich_finding: 0}`. Validated first against a 3-bundle subset (the exact
Track B targets) before committing to the full 97-bundle rerun.

### Funnel, before -> after (raw / reportable)

| Property | Raw before | Raw after | Reportable before | Reportable after |
|---|---|---|---|---|
| `lock_balance_findings` | 12 | 8 | 0 | 0 |
| `oob_index_write_candidates` | 3290 | 3247 | 7 | 5 |
| all other properties | unchanged | unchanged | unchanged | unchanged |

`lock_balance_findings` raw dropped by 4 (2 packages x 2 functions), not 2: alongside the
documented `ggml_graph_compute_secondary_thread` false positive, the SAME fix also structurally
removed `ggml_graph_compute_check_for_work` (same wrapper-duplication shape, same file) from both
packages' raw finding lists -- confirmed harmless: that function was already `reportable=False`
(`TIER_INTERNAL_UNREGISTERED`, gated at reachability, never one of the 13 promoted findings), so
this is a bonus reduction in raw diagnostic noise with zero change to any reportable count.

`lock_balance_findings` reportable stayed `0 -> 0` because both real false positives were already
suppressed via `adjudication_registry.py` (instruction point 4's whole point: confirm they now
disappear STRUCTURALLY, not merely via that veto -- see section 6).

## 6. Structural disappearance confirmed (instruction point 4)

Per-site structural status, read directly from `results/trackb_rerun_delta.json`:

| Package | Function | Property | Status |
|---|---|---|---|
| `@fugood/whisper.node@1.1.3` | `ggml_graph_compute_secondary_thread` | `lock_balance_findings` | **STRUCTURALLY_GONE** |
| `smart-whisper@0.8.1` | `ggml_graph_compute_secondary_thread` | `lock_balance_findings` | **STRUCTURALLY_GONE** |
| `@appthreat/sqlite3@9.0.1` | `sqlite3_get_table_cb` | `oob_index_write_candidates` | **STRUCTURALLY_GONE** |
| `@appthreat/sqlite3@9.0.1` | `sha1QueryFunc` | `oob_index_write_candidates` | still present (disclosed, unfixed) |
| `@appthreat/sqlite3@9.0.1` | `lsModeFunc` | `oob_index_write_candidates` | still present (disclosed, unfixed) |

Both `lock_balance_findings` targets and `sqlite3_get_table_cb`'s own `oob_index_write_candidates`
sites are gone because the SCANNER ITSELF no longer emits them (0 raw candidates), confirmed by
direct enumeration of `replay_records_v8.jsonl` -- not merely absent from a `reportable=True`
filter, and not because `adjudication_registry.py`'s veto suppressed them (its own table is
untouched, per section 3).

### A real attribution correction found during this replay

Direct enumeration of the 5 remaining `reportable=True` `oob_index_write_candidates` (funnel:
`7 -> 5`, not `7 -> 2` as `sha1QueryFunc`+`lsModeFunc` alone would give) found the original
`STEP6_PROMOTIONS_MANUAL_REVIEW.md` misattributed all 7 to "three functions in vendored SQLite."
Corrected in that document directly: only 4 are from SQLite (`sha1QueryFunc`:1, `lsModeFunc`:1,
`sqlite3_get_table_cb`:2, the last now structurally gone). The other 3 are `@elchetz/cld`'s own
`GetLanguageFromName` -- confirmed to be the EXACT SAME real `temp[16]` writes already reviewed
and adjudicated as `CONFIRMED_FALSE_POSITIVE` under `oob_write_candidates` (section 3-6 of that
same document), independently re-flagged a second time by the separate `oob_index_write_verdict.py`
scanner under a property key that carries no `site_id` and so has no adjudication coverage. Not a
new root cause and not a new false positive -- the same disclosed `site_id` gap from the original
review, now precisely attributed rather than left folded into an inaccurate SQLite-only count.

## 7. What remains disclosed and unfixed (deliberately, out of this round's scope)

- **`sha1QueryFunc`** (`shell.c:5574`): decrementing-loop-with-safe-initializer bound shape
  (`for(j=8;j>=1;j--)`) -- the scanner's direct-index-bound check only recognizes upper-bound
  comparison shapes (`idx<K`/`idx<=K`), never a decrementing initializer combined with a
  lower-bound guard. Needs new capability, not a scoping fix.
- **`lsModeFunc`** (`shell.c:10277`): compound linear index expression (`1 + i*3`) -- the
  fixed-array bound check only credits a bare index identifier, never a compound expression
  (unlike `PARAM-CAP-R01`'s own compound-expression support for pointer-parameter capacity, never
  extended to the fixed-local-array branch). Needs genuine linear-expression bound arithmetic.
- **`GetLanguageFromName`'s 3 `oob_index_write_candidates`**: not a new bug -- the pre-existing,
  disclosed `oob_index_write_candidates` missing-`site_id` gap (section 6 above), which keeps this
  already-adjudicated false positive `reportable=True` under a second scanner's property key.
- **`GetLanguageFromName`'s own 4 `oob_write_candidates`**: unaffected by this round (different
  scanner, `oob_write_verdict.py`, not touched); already `CONFIRMED_FALSE_POSITIVE`-adjudicated.

None of these were in roadmap step 7's own stated scope (lock-primitive wrapper recognition; OOB
type/extent equivalence) -- fixing them is future work, not silently deferred without disclosure.

## 8. Freeze (instruction point 5)

The corrected native pipeline -- `lock_balance_verdict.py` (WRAPPER-SITE-R01) and
`oob_index_write_verdict.py` (OOB-EQUIV-R01) -- is frozen as of this document. Both fixes are
structural (verified by direct scanner re-run, not adjudication-registry suppression), regression-
tested against the full existing gate suite (zero regressions, see section 4) plus 4 new real/
synthetic controls, and replayed end-to-end across all 97 preserved bundles with the corrected
downstream pipeline. `results/replay_records_v8.jsonl` and `results/trackb_rerun_delta.json` are
the frozen artifacts of this replay.

Per the controlling instruction's explicit constraint, no 494-package corpus run was performed
this round.
