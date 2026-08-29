# Raw producer outputs

- `mozjpeg_pilot_findings.json` / `nss_freebl_pilot_findings.json` — **v1 driver output.**
  Correct candidate counts, but the `capability`/producer labels in these files' summary
  blocks mislabel `cap_counted_loop_writer.py` as "cap4" — see
  `../reports/PILOT_REPORT.md`'s correction section. Kept for the audit trail (this is
  what the original report was actually built from), not the authoritative labels.
- `mozjpeg_v2_findings.json` / `nss_freebl_v2_findings.json` — **v2 driver output
  (authoritative).** Correct capability labels (`real_capability` field), per-module
  provenance (`__file__` + sha256, captured live), and a `deduped_operations` list — the
  cap2a+cap2b+cap3 physical-write identities after `cap_write_site_dedup.dedup()`
  precedence, alongside the raw per-producer records. Reproduced from a second, clean
  worktree with `PYTHONPATH` cleared; totals are identical to the v1 run (118 / 352).
- `module_provenance.json` — the module-provenance block alone (identical across both
  targets — same clean worktree, same run pattern), for a quick contamination check
  without loading either full findings file.

See `../reports/PILOT_REPORT.md` for the categorized read, including which counts are
deduplicated and which are raw producer records.

The intermediate `cpp.json` fact files (~270MB mozjpeg, ~610MB nss/freebl) and `cpg.bin`
CPGs are NOT committed here (too large for the repo); they were generated fresh by the
commands in `../commands/*_pipeline.sh` against the pinned commits in `../sources_pin/`
and are reproducible byte-for-byte from those two inputs + joern-cli v4.0.608.
