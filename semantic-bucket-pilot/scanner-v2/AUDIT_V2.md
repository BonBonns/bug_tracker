# v2 evidence-expansion — corrected audit (steps 2–4, no fix)

Redo of the audit with the three requested corrections, all invariants
validated before diagnosing. Counts are trustworthy: the canonical fingerprint
is imported (not reimplemented), deterministic records carry an explicit reason
(never `"None"`), and vulnerable/patched are kept distinct at the operation level
while paired at the case-family level.

Provenance (in `audit_v2.json`): scanner commit, audit-script sha256, and the
sha256 of every input `cpp.json`. Fingerprint sourced from
`frozen-corpus/build_frozen_corpus.py:_fingerprint`.

## Invariants (all PASS)

| invariant | result |
|-----------|--------|
| raw records total 3,246 | PASS |
| every record maps to exactly one operation fingerprint | PASS |
| counts by producer sum to the raw total (runtime 2174 + cursor 382 + interproc 690 = 3246) | PASS |
| counts by status / route / reason each sum to the distinct total (2,532) | PASS |
| no null/unknown reason (deterministic → `not_applicable_deterministic_complete`) | PASS |
| no null/unknown reason silently counted as additional-evidence | PASS |
| duplicate groups preserve all producer verdicts | PASS |
| cross-producer disagreements marked as conflicts | PASS |

3,246 raw records → **2,532 distinct operations** → **983 case families**.

## Two-number ranking of additional-evidence reasons

Ranked by independent case families, then distinct operations, so a reason
repeated inside one large/macro function does not automatically win.

| reason | distinct ops | independent functions | case families | families |
|--------|-------------|-----------------------|---------------|----------|
| `required_evidence_absent` | 1,882 | 525 | 772 | E1–E5 |
| `destination_identity_ambiguous` | 350 | 79 | 80 | E1,E2,E4,E5 |
| `conflicting_reaching_allocations` | 16 | 3 | 3 | E1 |

`required_evidence_absent` wins on BOTH numbers and spans all five families — it
is genuinely widespread, not an artifact of one function. `conflicting_reaching_allocations`
touches only 3 functions and does not generalize.

### `required_evidence_absent` (1,882) by sub-pattern (with generalization)

| sub-pattern | ops | ind. functions | case families |
|-------------|-----|----------------|---------------|
| `N * sizeof(T)` array write | 964 | 266 | 439 |
| length-variable width | 300 | 86 | 104 |
| `sizeof(TYPE)` single-object | 292 | 98 | 118 |
| other / no-sizeof | 238 | 76 | 94 |
| `sizeof(*dest)` single-object | 56 | 28 | 28 |
| non-runtime (cursor) | 32 | 8 | 8 |

## Loss-location classification (representative cases inspected against source + facts)

| reason / sub-pattern | ops | loss location | evidence |
|----------------------|-----|---------------|----------|
| req-ev: `N*sizeof` array out-param | 964 | **Evidence absent from source** | dest is a caller-provided out-param (`pSlotList`, `phObject`); capacity is the caller's buffer, only contractually asserted via a count parameter. Correct local abstention. |
| req-ev: `sizeof(TYPE)` into literal `T*` | ~32 | **Producer generated but consumer ignored** | dest `type_full_name` (e.g. `NSSLOWCERTCertificate*`) is in `cpp.json`; the producer does not use it. |
| req-ev: `sizeof(TYPE)` into `X_PTR` typedef | ~260 | **Evidence absent from (scanned) source** | the header defining `typedef … CK_MECHANISM_INFO_PTR` (`pkcs11t.h`) is outside the module-only scan; `type_decls` mark `X_PTR` `is_external` with no alias. Recoverable by widening scan scope — NOT by assuming `X_PTR == X*`. |
| req-ev: `sizeof(*dest)` | 56 | **Analysis model does not yet support it** | width literally references `*dest` (e.g. `memset(ctx,0,sizeof(*ctx))`); the single-object inference is simply not made. |
| req-ev: length-var / other | 538 | mixed — predominantly evidence-absent (alloc site is the caller's) / analysis-model | `width = name->len` etc. into a bare pointer. |
| `destination_identity_ambiguous` | 350 | **Evidence absent from source** | bare-pointer-parameter destinations (`do_xor(unsigned char *dest,…)`, out-param arrays `pMechanismList[i]`) with no local allocation; capacity is the caller's. |
| `conflicting_reaching_allocations` | 16 | **Correct abstention (not a loss)** | genuinely multiple differently-sized allocations reach the sink (`NSC_DeriveKey` reused `buf`, `lg_searchCertsAndTrust` `tmp_name` written `name->len` then `email->len`). |

## Selection for the first evidence capability (no fix applied in this step)

Only categories where the evidence is present in the pipeline (produced-but-ignored,
analysis-model, normalizer-dropped) are fixable **without** adding new evidence or
making assumptions. Ranked within that class:

1. **Single-object-copy** — `sizeof(*dest)` (analysis-model, 56 ops) + `sizeof(TYPE)`
   into a literal `T*` (produced-but-ignored, ~32 ops) = **~88 sound operations**,
   generalizing across ~126 functions / ~146 case families in all five families.
   This is the highest-volume soundly-fixable gap. **Selected as the first capability.**

2. `sizeof(TYPE)` into `X_PTR` (~260 ops) — evidence-absent-from-*scanned*-source.
   The natural second capability: widen the scan to include the PKCS#11 typedef
   headers so `X_PTR` resolves to `X*` in the facts, then the same single-object
   logic applies. Deferred; requires a scan-scope change, not a naming assumption.

`N*sizeof` array out-params (964) and `destination_identity_ambiguous` (350) are
evidence-absent-from-source (caller's buffer) — they require interprocedural
caller-contract analysis and are assumption-prone; NOT the first capability, even
though `N*sizeof` has the highest raw count.

A prototype of capability #1 already exists (`single_object_pass.py`) and, on the
corrected denominator, moves **88** operations `required_evidence_absent →
deterministic_complete` with 0 soundness violations (`compare_v1_v2_result.json`).
This corrected audit is what justifies that selection; per instruction, no new
scanner fix is applied here.
