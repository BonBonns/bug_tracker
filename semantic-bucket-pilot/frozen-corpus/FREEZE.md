# Frozen scanner + corpus

## What is frozen

The **complete scanner** is frozen at the commit recorded in
`manifest.json → scanner_commit`. That is the last commit touching producer /
schema code; everything downstream (this corpus, the A/B/C prompts, the routing
evaluation) is derived from it and adds no scanner logic. The freeze covers the
three reason-emitting producers that carry the full accounting + reason layer:

- `oob_runtime_capacity_verdict` (RUNTIME_CAPACITY, width-vs-capacity)
- `oob_cursor_write_verdict` (CURSOR, count-based)
- `oob_interprocedural_verdict` (INTERPROCEDURAL, single-hop propagated capacity)

Their warning verdicts (`emit_candidates`) are unchanged by the accounting work;
`analyze_operations` is additive. The other producers emit warning candidates
but no accounting records and are out of this corpus by design (stated in
`manifest.json`), not silently dropped.

## Build sequencing (why the corpus is attributable)

The corpus must never be the product of an uncommitted builder. Sequence:

1. Commit the machinery — `build_frozen_corpus.py`, the three producers, and
   `analysis_record.py` — first.
2. From that clean commit, run the builder. It **refuses to run** if any
   machinery file has uncommitted changes (`--allow-dirty` is a dry-run escape
   only), so the emitted `scanner_commit` and `builder_sha256` in the manifest
   are always a committed state.
3. Verify a second run is byte-identical (producers are deterministic).
4. Commit the derived outputs + manifest + audit.

`manifest.json` records the full attribution chain: `scanner_commit`,
`analysis_record_version` + `analysis_record_sha256`, `builder_sha256`,
per-producer `producer_sha256`, per-input fact `sha256`, source repo + revision
per input, and the toolchain (joern-c2cpg 4.0.608, schema
portable-program-facts/0.3, `scan_pkg.sh`). `REBUILD_RECIPE.md` is the
deterministic recipe to regenerate the inputs from public sources.

## Artifacts

| file | contents |
|------|----------|
| `all_records.jsonl` | every analysis record, one per (producer, recognized op) — the raw producer boundary; accounting equality asserted here |
| `distinct_operations.jsonl` | **the experimental-case universe**: one canonical record per physical operation after cross-producer de-duplication |
| `llm_eligible.jsonl` | the distinct operations whose canonical record is `llm_eligible` — what A/B/C may draw from |
| `manifest.json` | full attribution (above) |
| `audit.json` / `audit.md` | distributions + de-duplication statistics |
| `REBUILD_RECIPE.md` | regenerate the input fact files from public sources |
| `REAL_SOURCE_VALIDATION.md` | every corpus reason inspected against real source |

## De-duplication (one operation = one case)

The same physical write is recognized by more than one producer (e.g. a memcpy
into a pointer parameter seen by both RUNTIME_CAPACITY and INTERPROCEDURAL), and
the same operation can be reached through multiple cached fact files. Those must
not become multiple independent experimental cases. Each record carries a
producer-independent `op_fingerprint`; `distinct_operations.jsonl` collapses to
one canonical record per fingerprint.

Canonicalization is **evidence-monotone**, not producer-name-privileged: the
record that established the most evidence (furthest along identity → capacity →
bound) wins; ties break deterministically. All producer verdicts are kept under
`producer_verdicts`, and genuine disagreements are flagged `dedup_conflict`, so
the merge hides nothing. In this corpus: **192 raw records → 151 distinct
operations** (41 merged; 4 genuine conflicts, all `runtime abstained
required_evidence_absent` vs `interproc open_candidate
capacity_relation_not_established`, resolved to interproc's more-informed
verdict).

## Distribution over the 151 distinct operations (scanner-emitted, not truth)

By status: `abstained` 107, `open_candidate` 42, `deterministic_complete` 2.

| bucket | count | | primary reason | count |
|--------|-------|-|----------------|-------|
| insufficient_evidence | 85 | | required_evidence_absent | 85 |
| relationship_unresolved | 42 | | write_count_bound_not_established | 30 |
| conflicting_definitions | 16 | | conflicting_reaching_allocations | 16 |
| identity_ambiguous | 4 | | capacity_relation_not_established | 12 |
| external_contract_unknown | 2 | | destination_identity_ambiguous | 4 |
| (none, deterministic) | 2 | | unknown_allocator_contract | 2 |

Five uncertainty buckets from six v1 reason codes — the reason the cursor +
interproc abstention layer was finished before freezing. See `audit.md` for
by-CVE, by-revision-side, and by-producer breakdowns.

## Freeze-validation checklist (all green)

- [x] **Synthetic positive + negative controls per reason.** `ANALYSIS_RECORD_R01`
  53/53.
- [x] **A real record for every corpus reason inspected against source**, incl. a
  real cursor abstention (`sec_asn1d_concat_group` → `destination_identity_ambiguous`)
  and the near-singleton `unknown_allocator_contract` — see `REAL_SOURCE_VALIDATION.md`.
- [x] **No change to existing warning verdicts.** Frozen producer gates all green.
- [x] **No fallback reason sources.** `build_auto_buckets.py` 3/3, all
  `explicit_producer_reason`.
- [x] **Every emitted reason belongs to frozen schema v1.** Builder asserts
  required abstention fields and aborts on any absent one.
- [x] **Deterministic output across repeated runs.** Corpora byte-identical
  across two builds (verified in the build sequence).
- [x] **Accounting equality** per (input, producer):
  recognized = det + open + abstained + rerouted. Builder aborts on violation.
- [x] **Cross-producer de-duplication** to distinct operations, conflicts
  surfaced not hidden.
- [x] **Full attribution** (scanner + schema + builder + producer + input
  hashes, source revisions, toolchain) and a **rebuild recipe**.

## Scanner state ≠ ground truth (hard boundary)

The 151 distinct operations are the **scanner corpus**, not the experimental
corpus. An emitted `uncertainty_bucket` or candidate is **not** the correct
final answer. Before any case enters A/B/C, a separate layer must independently
establish, per operation: the scanner-emitted bucket (here), the **verified
bucket**, the **verified program outcome** (safe / vulnerable), and the
**evidence-relative answer**. Only then are cases selected — by frozen criteria,
and without running condition B first. No accuracy claim may be made on these
raw scanner outputs.

Once tagged, future scanner changes produce a **new** corpus version; the frozen
v1 corpus is not modified in place.
