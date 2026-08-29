# Held-out run — protocol deviation record

This run is **NOT** described as perfectly blind or untouched. Before the run manifest and
runner were frozen, five held-out sites were executed during runner validation, and two of
them were additionally inspected by hand while debugging the recognition-extraction code. The
scanner capabilities and producers were already frozen and were **not** changed, so this does
not invalidate the scanner *measurement*, but it is a protocol deviation and is recorded here
in full.

## Exposed sites (5) and families (4 distinct)

All five are the first five SecVulEval sites in pooled order; they were run via
`heldout_run.py <dir> 5` (and 8) during runner validation.

| site_id            | function                    | family_id         | family_signature                  | write_kind    |
|--------------------|-----------------------------|-------------------|-----------------------------------|---------------|
| `ee5cad67577fa31d` | `pfkey_register`            | `fam_42418a7cbf67`| `pointer_deref\|unknown\|deref`     | pointer_deref |
| `d232778c9a7f7df0` | `wilc_wfi_cfg_parse_ch_attr`| `fam_83e36e70488c`| `copy_sink\|struct_field\|V->V`     | copy_sink     |
| `6a970f8fab53b550` | `ice_free_q_vector`         | `fam_9152d9e125ef`| `index_write\|struct_field\|index`  | index_write   |
| `1a58eb99070d0fbe` | `nxp_fspi_fill_txfifo`      | `fam_bbab2acb2e20`| `copy_sink\|unknown\|V`             | copy_sink     |
| `4aad12d8262078cf` | `mlxsw_sp_acl_tcam_init`    | `fam_42418a7cbf67`| `pointer_deref\|unknown\|deref`     | pointer_deref |

Distinct exposed families (4): `fam_42418a7cbf67` (2 sites), `fam_83e36e70488c`,
`fam_9152d9e125ef`, `fam_bbab2acb2e20`.

## What was observed

- **Validation runs (5 then 8 sites):** every exposed site passed stages 1–3 (source
  available, build/parse OK, labeled write mapped) and was **NOT recognized** by any producer
  or capability (`stage4_recognized = false`, `distinct_recognized_ops = 0`). Identical across
  the validation run, the first (superseded) full run, and the re-run — deterministic.
- **Manual inspection #1 — `pfkey_register`:** scanned the reconstructed body; ran the three
  frozen producers directly → **0 records each**. The labeled write
  (`struct pfkey_sock *pfk = pfkey_sk(sk);`) is a pointer declaration, outside all four
  capabilities.
- **Manual inspection #2 — `wilc_wfi_cfg_parse_ch_attr`:** scanned the body (73 calls); the
  labeled write is `memset(e->ch_list, sta_ch, e->no_of_channels)` — a `memset` into a
  struct-member destination with a symbolic length; ran the three producers → **0 records**.
  Confirmed this is a correct abstention (struct-field capacity + symbolic length are outside
  the producers' recognized shapes), not a bug.

No result observed during exposure was a recognition/promotion; all were misses/abstentions.

## Runner changes made AFTER those sites were exposed

These are RUNNER / REPORTING changes only. They do not touch any capability, producer,
normalizer, exporter, or the frozen physical-write identity module.

- Replaced `dedup_recognized` with `reconcile_identity`, which asserts the chain
  `raw recognized records >= identity-bearing records >= unique physical operations` and marks
  records with no matched CPG write node `identity_unverifiable` (never silently merged).
- Relabelled the 83 non-SecVulEval sites from `source_not_in_frozen_artifacts` to
  `source_not_reconstructable_from_frozen_manifest` (data-packaging attrition; repos+commits
  may be retrievable later — not proof the source is gone).
- Added `analysis_mode = "frozen_function_level_source_packet"` to SecVulEval rows (function-
  packet recognition, not full-repository recall).
- Summarizer rewritten for two denominators (end-to-end coverage over 258; conditional recall
  over CPG-mapped sites), macro family recall, and family *coverage* vs *recall* naming.

## Confirmation: no producer / capability changed

`git diff --stat 544a606 HEAD` over every capability (1–4), the three frozen producers,
`oob_runtime_capacity_v2`, `cap_write_site_dedup` (frozen identity), the exporter, and the
normalizer is **empty**; the working tree has no modifications to any of them. Their SHA-256
in `RUN_MANIFEST.json` are the frozen-commit values. The scanner is byte-for-byte the frozen
`544a606`.

## Handling in the report

The full result is reported, AND a **sensitivity analysis** is reported that excludes the five
exposed sites and their four entire families, to show the measurement does not depend on the
exposed material.
