# Run records and derived findings

One directory per pinned target:

- `run_<lang>.json` — the run record: commit, file-set hash, CPG counts,
  parse coverage as a set intersection against the frozen manifest, attempt
  counts per stage, and the final classification tally.
- `findings_<lang>.json` — the derived findings from the frozen reducers.
- `cpg_files_<lang>.txt` — every FILE node name in the CPG, which is what
  coverage is measured against.
- `raw_<lang>/` — the producer fact tables the reducers consumed.

`raw_*/parser_anchors.tsv` is not kept. It is a working intermediate — one
row per candidate anchor site considered by the reachability producer, 31,863
rows and 5 MB for the Firefox run — and its outcome is already recorded in
the `reachability_line` field of the run record. Re-running `run_target.py`
against the same pinned CPG regenerates it.
