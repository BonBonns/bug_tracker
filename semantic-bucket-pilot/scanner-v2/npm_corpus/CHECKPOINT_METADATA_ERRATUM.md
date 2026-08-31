# `make_checkpoint.py` metadata bug -- audited, fixed, real data confirmed intact

## The bug

`make_checkpoint.py` unconditionally assumed its source file was a TSV file with a header
row: `row_count = len(lines) - 1` and `last_package_key = lines[-1].split("\t", 1)[0]`. This
is correct for a real headered TSV source (e.g. `eligible_packages.tsv`), but every
full-scan checkpoint this project has ever taken (`full_scan_remaining_*`,
`r05_full_scan_*`) was snapshotting `full_scan_working.jsonl` / `full_scan_r05_working.jsonl`
-- a real, headerless, one-JSON-record-per-line file. Neither assumption holds there.

## What was and was not affected -- proven, not assumed

The actual immutable snapshot `.tsv` file is a **raw byte copy** of the source (minus a
torn trailing line, if any) -- writing that file never depended on the header assumption.
Proven directly against the real, still-live `full_scan_r05_working.jsonl` at the time this
was found (255 real lines at snapshot time):

- The committed snapshot `checkpoints/r05_full_scan_00000254_e129f2141bbd.tsv` contains
  **all 255 real lines**, byte-identical to `head -255 full_scan_r05_working.jsonl` taken
  from the still-live file afterward.
- Its first line is the real first record (`node-addon-api@8.9.2`) -- **not dropped**.
- The same check against an older checkpoint from this project's history
  (`full_scan_remaining_00000317_1434e354bcb0.tsv`, named "317") shows it actually contains
  **318 real lines** -- the pattern is systemic across every headerless-JSONL checkpoint
  ever taken, and in every case checked the underlying snapshot data was intact.

So: **no package record was ever dropped from a snapshot.** What was wrong, every time, was
only the two metadata fields:

- `row_count` -- undercounted by exactly 1 for every headerless-JSONL checkpoint (the
  filename and the JSON sidecar both carry this wrong number).
- `last_package_key` -- for a JSONL source, `.split("\t", 1)[0]` finds no tab and returns
  the **entire last JSON record** instead of a real key (visible directly in every prior
  `r05_full_scan_*`/`full_scan_remaining_*` sidecar's `last_package_key` field).

## The fix

`make_checkpoint.py` now requires an explicit `has_header: bool` argument -- never inferred
-- consistent with this project's standing discipline of abstaining/requiring evidence
rather than guessing (the same reason auto-detecting "does the first line parse as JSON" was
rejected: a real TSV row can itself parse as valid, if degenerate, JSON, and a wrong guess
would silently reintroduce the same class of bug). `last_package_key` extraction now
recognizes this project's own real JSONL record shape (`package_name`/`version` fields) and
renders `package@version`; anything else falls back to the original tab-split, unchanged.

Verified against 5 real fixtures (`tests/test_make_checkpoint.py`, all PASS): headerless
JSONL row-count and key correctness; headered TSV behavior unchanged; `has_header` rejects a
non-bool rather than coercing; a single-data-line headerless file (the old code returned `""`
for the key in this case); a torn trailing line is still correctly discarded under the new
header-aware counting.

## Historical checkpoint commits are NOT rewritten

The prior `r05_full_scan_*`/`full_scan_remaining_*` checkpoint commits keep their existing
(mislabeled-count) metadata -- their **snapshot data was never wrong**, only cosmetic/audit
metadata was, and this project does not rewrite already-pushed history for that. A fresh,
correctly-labeled checkpoint of the live R05 scan (using this fixed script) is taken
separately and committed to the R05 lineage branch as an ordinary checkpoint-only commit,
per that branch's standing discipline.

## Frozen

- `make_checkpoint.py` (fixed, this branch only): see git log for hash; NOT committed to the
  R05 lineage branch -- only the corrected checkpoint DATA this script produces is.
