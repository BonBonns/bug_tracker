# Held-out run — protocol deviation record

This run is **NOT** described as perfectly blind or untouched. During runner validation, the
first **eight** SecVulEval sites (pooled order) were executed, and two of them were additionally
inspected by hand while debugging the recognition-extraction code. The scanner capabilities and
producers were already frozen and were **not** changed, so this does not invalidate the scanner
*measurement*, but it is a protocol deviation and is recorded here in full.

Two validation passes exposed sites:
- **first 5 sites** — `heldout_run.py <dir> 5`, run on the INITIAL runner (before the
  identity-reconciliation changes);
- **first 8 sites** — `heldout_run.py <dir> 8`, run on the MODIFIED runner (after the
  identity-reconciliation / relabel / function-packet changes). This pass re-ran sites 1–5 and
  additionally exposed sites 6–8.

The exposed set is the union: the **first 8 SecVulEval sites**, spanning **6 distinct families**.

## Exposed sites (8) and families (6 distinct)

| # | site_id            | function                    | family_id         | family_signature                   | write_kind    | exposed in |
|---|--------------------|-----------------------------|-------------------|------------------------------------|---------------|------------|
| 1 | `ee5cad67577fa31d` | `pfkey_register`            | `fam_42418a7cbf67`| `pointer_deref\|unknown\|deref`      | pointer_deref | 5 & 8; hand-inspected |
| 2 | `d232778c9a7f7df0` | `wilc_wfi_cfg_parse_ch_attr`| `fam_83e36e70488c`| `copy_sink\|struct_field\|V->V`      | copy_sink     | 5 & 8; hand-inspected |
| 3 | `6a970f8fab53b550` | `ice_free_q_vector`         | `fam_9152d9e125ef`| `index_write\|struct_field\|index`   | index_write   | 5 & 8 |
| 4 | `1a58eb99070d0fbe` | `nxp_fspi_fill_txfifo`      | `fam_bbab2acb2e20`| `copy_sink\|unknown\|V`              | copy_sink     | 5 & 8 |
| 5 | `4aad12d8262078cf` | `mlxsw_sp_acl_tcam_init`    | `fam_42418a7cbf67`| `pointer_deref\|unknown\|deref`      | pointer_deref | 5 & 8 |
| 6 | `9eeeaa5836bf7a49` | `mi_enum_attr`              | `fam_42418a7cbf67`| `pointer_deref\|unknown\|deref`      | pointer_deref | 8 only (modified runner) |
| 7 | `c342772544ffe23d` | `psi_write`                 | `fam_4bdb4421b431`| `index_write\|local_array\|index`    | index_write   | 8 only (modified runner) |
| 8 | `09dc95c27e7d38c6` | `rtw_wx_set_scan`           | `fam_31f08ea2c79e`| `copy_sink\|unknown\|V[V].V`         | copy_sink     | 8 only (modified runner) |

Distinct exposed families (6): `fam_42418a7cbf67` (sites 1, 5, 6), `fam_83e36e70488c`,
`fam_9152d9e125ef`, `fam_bbab2acb2e20`, `fam_4bdb4421b431` (site 7), `fam_31f08ea2c79e` (site 8).

## What was observed

- **Validation runs (5 then 8 sites):** every one of the 8 exposed sites was **NOT recognized**
  by any producer or capability (`stage4_recognized = false`, `distinct_recognized_ops = 0`);
  raw recognized records = 0 for each. Sites 1,3,4,5,6,8 passed stages 1–3 (source available,
  build/parse OK, labeled write mapped); site 7 (`psi_write`) built but its labeled write did
  not map into the CPG (stage-3 pipeline attrition). Identical across the 5-site pass, the
  8-site pass, the first (superseded) full run, and the re-run — deterministic.
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

The **full 258-site result is PRIMARY**, with this protocol deviation clearly stated. A
**secondary sensitivity analysis** excludes the 8 exposed sites and their 6 entire families to
show the measurement does not depend on the exposed material — it is a sensitivity check, NOT a
replacement denominator.
