# Frozen scanner + corpus

## What is frozen

The **complete scanner** is frozen at commit **`0d82c84`** ("Harmonize
runtimecap record shape with cursor/interproc before freeze") — the last
commit that touches producer / scanner code. Everything downstream (this
corpus, the A/B/C prompts, the routing evaluation) is derived from that
frozen scanner and adds no scanner logic.

The freeze covers the three reason-emitting producers that carry the full
accounting + reason layer:

- `oob_runtime_capacity_verdict` (RUNTIME_CAPACITY, width-vs-capacity)
- `oob_cursor_write_verdict` (CURSOR, count-based)
- `oob_interprocedural_verdict` (INTERPROCEDURAL, single-hop propagated capacity)

Their warning verdicts (`emit_candidates`) are unchanged by any of the
accounting work; the accounting layer (`analyze_operations`) is additive.
The other producers (call_sink, copy_length, pointer_increment, index_write)
still emit warning candidates but no accounting records, and are out of this
corpus by design — stated in `manifest.json`, not silently dropped.

## The two corpora (built by `build_frozen_corpus.py` from the frozen output)

| file | contents | consumer |
|------|----------|----------|
| `llm_eligible.jsonl` | records with `llm_eligible == true` (44) | A/B/C prompt experiment |
| `all_records.jsonl` | every analysis record (192) | bucket-assignment + routing evaluation |

Both come from the **same** frozen scanner run over the same real CVE fact
files. `manifest.json` records the scanner commit and the sha256 of every
input, so the corpus regenerates byte-identically from the same commit + the
same inputs (producers are deterministic — verified below).

### Distribution (192 records over 12 real vuln/patched fact files)

By status: `abstained` 148, `open_candidate` 42, `deterministic_complete` 2.

By uncertainty bucket:

| bucket | count |
|--------|-------|
| insufficient_evidence | 126 |
| relationship_unresolved | 42 |
| conflicting_definitions | 16 |
| identity_ambiguous | 4 |
| external_contract_unknown | 2 |
| (none, deterministic) | 2 |

This is the point of finishing cursor + interproc abstention emission before
freezing: the corpus is **not** almost-entirely `relationship_unresolved`.
Five distinct buckets appear, driven by six distinct primary reason codes,
all in frozen schema v1 — no reason was invented to fit, and v1 was not
mutated.

## Freeze-validation checklist (all green)

- [x] **Synthetic positive + negative controls per new reason.**
  `ANALYSIS_RECORD_R01` gate 53/53, including the `cursor_accounting`
  fixture (positive controls for `destination_identity_ambiguous`,
  `required_evidence_absent`, `write_count_bound_not_established`, and a
  `deterministic_complete` negative control) and the interproc
  conflicting-vs-required-evidence split.
- [x] **≥1 real-corpus abstention from cursor AND interproc inspected against
  source.**
  - cursor `rsa_FormatOneBlock:132` `*bp++` → `required_evidence_absent`
    (`bp` aliases `block = PORT_Alloc(modulusLen)`, a symbolic allocation;
    identity established, capacity not a literal → no evidence, not ambiguity).
  - cursor `sec_asn1d_concat_group:2305` `group` → `destination_identity_ambiguous`
    (multiple/unresolved destination bases).
  - interproc `eme_oaep_decode:655` `PORT_Memcpy(output,...)` →
    `required_evidence_absent` (`output` is a resolved parameter but no
    bounded capacity fact propagates to it — not conflicting, not ambiguous).
- [x] **No change to existing warning verdicts.** Frozen producer gates all
  green: cursor 10/10, interproc 6/6, runtimecap 18/18, runtimecap-cfg 6/6,
  adj 10/10, callsink 7/7, copylen 11/11, ptrinc 6/6, index 9/9, callctx 11/11.
- [x] **No fallback reason sources.** `build_auto_buckets.py` 3/3, every record
  `reason_source == "explicit_producer_reason"`.
- [x] **Every emitted reason belongs to frozen schema v1.** All six
  primary reason codes are v1; the builder asserts required abstention fields
  and aborts on any absent one.
- [x] **Deterministic output across repeated runs.** `all_records.jsonl` and
  `llm_eligible.jsonl` are byte-identical across two builds (sha256 verified);
  the gate independently checks per-producer determinism.
- [x] **Accounting equality.** The builder asserts, per (input file, producer),
  `recognized = deterministic_complete + open_candidate + abstained +
  rerouted`, and aborts the build on any violation. No violation across the
  12 files.

## Important downstream caveat (research integrity)

The 44 `llm_eligible` records are **raw frozen-scanner outputs**, not
ground-truth-labelled cases. They are the routable material for A/B/C, but no
accuracy claim can be made until each selected case has an independently
verified safe / vulnerable / unknown label. Selecting and labelling the
A/B/C cases from this corpus is the next step and is deliberately separate
from the freeze.
