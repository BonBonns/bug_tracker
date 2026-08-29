# Pre-registration: full SecVulEval as the fourth reachable held-out source

Amendment to PREREGISTER_BIGVUL.md / PREREGISTER_ARVO.md, frozen BEFORE any
full-SecVulEval mapping/family/pooling output is computed. The original SecVulEval
freeze (study/secvuleval/) explicitly anticipated this expansion: "this freeze is the
reachable population; expansion needs an unblocked fetch." The fetch is now unblocked
in the current environment (the 403 was environment-specific). The pilot stays frozen
and untouched; the full set SUPERSEDES it as the SecVulEval population (the pilot
contributed 0 pooled sites, so nothing is re-counted).

## Dataset identity (pinned)

- HuggingFace `arag0rn/SecVulEval`, revision `bde3e7c3225cc61c9ad727133737255428a2ea3d`
  (last modified 2026-04-29), single `train` split, 25,440 rows.
- Source file `data/train-00000-of-00001.parquet`,
  sha256 `56593aaee0b84611cc85d59ffd716a63f0639960c4815e9e678ed15ad06180c2`.
- Processing input: the export `secvuleval_full.jsonl.gz`,
  sha256 `d37bab32cf172a7f03b9048c793e52e58334a537a4697128bfaa92440ea037a9`
  (uncompressed jsonl sha256 `bf88b77ee9c58435c0a363dd0e10eaa313929d991e820c3891231419cfc9722e`);
  one JSON object per parquet row, order preserved. The raw dataset is NOT committed to
  the repo; the frozen manifest pins it by these hashes.

## Rules applied UNCHANGED (imported from secvuleval_freeze.py, not reimplemented)

RULE 1 `map_write` (labeled statement -> unique destination write within +-3 source
lines, or the sole write if no anchor; mapped/ambiguous/no_write_found; only mapped
sites score) and RULE 2 `family_id`, exactly as in the pilot. The only adapter logic is
field format, pre-registered here:
- labeled statements: `json.loads(changed_statements)` — the same [line, text] pair
  shape `locate_label` consumes in the pilot.
- CWE: the pilot's per-record `cwe` becomes `cwe_list`. A record is EXCLUDED if
  CWE-119 appears in `cwe_list` (the pilot's ambiguous-CWE exclusion); otherwise
  INCLUDED iff `cwe_list` intersects the pilot's INCLUDE_CWE {CWE-787, CWE-122,
  CWE-120}. All other records excluded.
- CVE: `cve_list` (all recorded; any element participates in CVE dedup).
- Same frozen `MAGMA_PROJECTS` exclusion on `project.lower()`; same in-source dedup key
  `(project, commit_id, filepath, func_name)`.
- ENTIRE 25,440-row set processed in one pass; no early stop at any count.

## Pool amendment (pre-registered before the run)

`pool_heldout_freeze.py` gains full-SecVulEval as a fourth pooled source. Only mapped
AND `is_vulnerable` sites pool (mapped non-vulnerable sites are recorded in the slice
manifest exactly as the pilot recorded them, but do not pool). Dedup keys, same
concept as before: drop a full-SecVulEval mapped-vulnerable site if any of its
`cve_list` matches a PostCutoff or Big-Vul site CVE, or `(project.lower(), commit_id)`
matches a Big-Vul or ARVO pooled site's (project, commit); Magma projects are excluded
at inclusion. The pilot needs no dedup handling: it contributed no pooled sites, and
its reachable rows are a subset of the full set (they pool once, via the full slice).
Family dedup stays at counting time (distinct family_id counted once across the whole
pool). Gate stays >= 12 pooled distinct vulnerable families; the pooled count is
re-frozen at whatever the honest number is — it cannot fall below the already-frozen
19 because no existing pooled site or rule is touched.

## Ordering note

These are corpus-construction artifacts, scanner-independent by design; the definitive
scanner commit declaration in RECONCILIATION.md is unaffected. Any capability-2
measurement still happens only at or after that reconciliation point, against the
then-current frozen pooled manifest, with capabilities frozen before any pooled yield
is inspected.
