# Nan replay over the preserved 97-package sample (task 4 of 5, Nan-integration finalization)

Per direct instruction ("Replay Nan over the preserved 97-package sample using existing facts --
no Joern rebuild -- so the combined aggregator includes Nan results"). No Joern invoked, no CPG
rebuilt, no C/C++/JS facts regenerated -- `resource_guard_verdict_nan.py`'s own verdict logic
ran fresh over each of the 97 bundles' already-preserved `cpp_raw/*.tsv`, matching the exact
discipline `replay_100_bundles.py`'s own R06 rerun (task34-replay item 1) already established
for this corpus.

## The real gap this closes

The 100-package evidence bundles never preserve the raw jssrc2cpg TSV export
(`resource_guard_verdict_nan.py`'s own `load_js_raw()` reads `calls.tsv`/`arguments.tsv`
directly from a directory) -- only the NORMALIZED `js_facts.json`
(`evidence_bundle.py`'s own module docstring: raw `js_raw` is deliberately excluded, "js_facts
.json, its normalized form" already carries what a bundle consumer needs).

## What was built

1. **`resource_guard_verdict_nan.load_js_raw_from_facts_json()`** -- a real adapter from
   `js_facts.json`'s own `calls`/`arguments` shape into the exact same `{"calls",
   "calls_by_name", "args_by_call"}` dict `load_js_raw()` already returns. Not a
   reimplementation: `js_facts.json`'s `calls` array already carries per-call `id`/`name`/`code`
   and per-argument `call_id`/`index`/`kind`/`code` -- the SAME neutral-frontend schema
   `load_js_raw()`'s own module comment documents, just already parsed into JSON.

   **Confirmed byte-identical, not merely "runs without error":** a real `js_facts.json` was
   generated from the Nan capability's own `comprehensive_fixture` (the exact fixture
   `NAN_CAPABILITY_DESIGN.md`/`NAN_CAPABILITY_FREEZE.md` validated the whole capability
   against) via the real `normalize_joern_facts.py` the live pipeline itself uses.
   `load_js_raw(tsv_dir)` vs. `load_js_raw_from_facts_json(json_path)` over the SAME underlying
   facts produced **0 mismatches across all 40 real calls and their arguments**, and
   `compute_findings(cpp, ...)` fed each loader's output produced **exact-equal** classification
   dicts and finding lists (7 findings each, byte-for-byte identical).

2. **`resource_guard_verdict_nan.compute_findings(cpp, js)`** -- the full verdict loop, factored
   out of `main()` so a replay caller reuses the EXACT SAME logic `main()` uses, never a second,
   drifting copy. Purely mechanical extraction (no logic changed) -- confirmed behavior-
   unchanged by rerunning `check_nan_integration.py` after the refactor: still 47/48 (23/23
   synthetic + the same real live-smoke result as before the refactor, kafka-javascript's own
   known `RESOURCE_LIMIT` unchanged -- see task 1's own results).

3. **`study/task34_replay/nan_replay_over_97.py`** -- the replay driver, modeled directly on
   `replay_100_bundles.py`'s own real pipeline-order discipline (documented in `rerun_
   aggregator_applicability.py`): per package, extract the bundle -> compute `nan_findings` via
   `compute_findings(load_cpp_raw(...), load_js_raw_from_facts_json(...))` -> re-fetch and hash-
   verify the pinned source (reusing `replay_100_bundles.download_and_verify_source()` verbatim,
   scoped to `nan_findings` alone via `provenance.enrich_record({"nan_findings": findings}, ...)`
   -- which only ever touches keys present in the record passed to it, so the v5 record's own
   already-resolved r04/r05/r06/staged provenance is never re-verified or touched) ->
   `applicability_gate.apply_applicability()` (re-run over the WHOLE merged record; idempotent
   on every already-`APPLICABLE` finding) -> `adjudication_registry.apply_known_adjudications()`
   (idempotent re-apply) -> `staged_enablement.enforce_staged_enablement()` ->
   `vendored_attribution.attribute_record()` (now covers `nan_findings` too -- a real, disclosed
   pre-existing gap fixed this round, see `vendored_attribution.py`'s own updated
   `ALL_FINDING_KEYS`) -> `six_property_aggregator.aggregate_record()`.

## Real result: 97/97 packages replayed, 0 failures

```
packages_attempted: 97
packages_succeeded: 97
packages_failed: 0
total_nan_findings_raw: 22
total_nan_findings_reportable: 3
```

Verdict distribution across all 97 packages' real `nan_findings`:

| Verdict | Count |
|---|---|
| `NAN_NEWBUFFER_UNBOUNDED_ALLOCATION_SOURCE_BOUNDARY_UNRESOLVED` | 12 |
| `NAN_COPYBUFFER_SOURCE_CAPACITY_SOURCE_BOUNDARY_UNRESOLVED` | 6 |
| `NAN_NEWBUFFER_UNBOUNDED_ALLOCATION` (candidate) | 3 |
| `NAN_COPYBUFFER_SOURCE_CAPACITY_UNRESOLVED` | 1 |

Five packages besides node-snap7 produced at least one raw Nan candidate-shaped call
(`@automattic/yara`: 1, `@codeporter/robotjs`: 1, `@confluentinc/kafka-javascript`: 2, `re2`: 5)
-- every one of them a real, disclosed abstention (`SOURCE_BOUNDARY_UNRESOLVED`/`UNRESOLVED`:
the size argument's own `info[N]` origin, or the copy source's own capacity, could not be
structurally traced), never a false `reportable=True`. **All 3 reportable candidates remain
exactly node-snap7's own `ReadArea`/`Upload`/`FullUpload`** -- the same 3 this round's own
`NODE_SNAP7_NAN_MANUAL_REVIEW.md` (task 2) independently confirmed against the real, current
pinned source. Zero new reportable candidates, zero regressions, zero surprises: this replay
is real corroborating evidence for the existing result, not a new discovery.

Combined output: `study/task34_replay/results/replay_records_v6_nan.jsonl` (97 REPLAYED records
carrying `nan_findings` + a recomputed `_six_property_summary` that now includes Nan, plus the
3 INHERITED_UPSTREAM_FAILURE records carried through unchanged) and `results/nan_replay_
summary.json`.

## Disclosed scope

- No Joern rebuild anywhere -- every C/C++/JS fact came from the preserved bundle. The only new
  computation is `resource_guard_verdict_nan.py`'s own CPU-bound verdict logic (real, but not a
  scan) and a real re-fetch-and-verify of each package's own already-pinned tarball (same
  discipline `replay_100_bundles.py` already established, never a new download target).
- This is the SAME 97-package sample every prior replay round (`replay_records_v2`...`v5`) used
  -- not a new or wider sample. `node-snap7-micro-client` (task 3's own subject) is real corpus
  membership but was never part of this 97-package frozen set (confirmed, see task 3's own
  `NODE_SNAP7_DEDUP_REVIEW.md`), so it is not, and could not be, replayed here.
