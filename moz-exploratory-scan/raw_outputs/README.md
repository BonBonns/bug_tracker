# Raw producer outputs

- `mozjpeg_pilot_findings.json` / `nss_freebl_pilot_findings.json` — full findings
  (every field each producer emitted, unmodified, plus this scan's `_bucket`/
  `_source_label`/`physical_write_identity_simplified`/`file` additions) + a summary
  block. See `../reports/PILOT_REPORT.md` for the categorized read.

The intermediate `cpp.json` fact files (~270MB mozjpeg, ~610MB nss/freebl) and `cpg.bin`
CPGs are NOT committed here (too large for the repo); they were generated fresh by the
commands in `../commands/*_pipeline.sh` against the pinned commits in `../sources_pin/`
and are reproducible byte-for-byte from those two inputs + joern-cli v4.0.608.
