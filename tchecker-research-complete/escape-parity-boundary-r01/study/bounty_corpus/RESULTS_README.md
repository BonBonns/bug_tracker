# Run records and derived findings

One directory per revision (`results/` predates R05, then `results_r05/`,
`results_r06/`, `results_r07/`), and inside it one directory per pinned target:

- `run_<lang>.json` — the run record: commit, file-set hash, CPG counts, parse
  coverage measured as a set intersection against the frozen manifest, attempt
  counts per stage, and the final classification tally.
- `findings_<lang>.json` — the derived findings from the frozen reducers.
- `cpg_files_<lang>.txt` — every FILE node name in the CPG, which is what
  coverage is measured against.
- `raw_<lang>/` — the producer fact tables the reducers consumed.

## A note on `parser_anchors.tsv`

From `results_r07/` onward this file is **pruned, not deleted**. It enumerates
every anchor the producer considered — 31,863 rows and 5 MB on the Firefox C/C++
run — but only the rows keyed to a finding's site or method matter to the chain,
so the archive keeps those and drops the rest. `anchor_rows_total` and
`anchor_rows_kept` in the run record say how many of each.

Earlier archives under `results/`, `results_r05/` and `results_r06/` have the
file removed entirely. That was a mistake, and the note that once stood here
("re-running regenerates it") did not cover the real cost: with the file gone,
the stored facts no longer reproduced the stored findings. Re-deriving the
Mozilla chain from one of those archives reports
`PARSER_NEVER_CALLED_IN_ANALYSED_SOURCE` and `parser_call_sites: 0` for a parser
that was in fact called once.

Those archives are left as they are rather than rewritten, because they are the
record of what each revision produced at the time. Only `results_r07/` onward
round-trips.
