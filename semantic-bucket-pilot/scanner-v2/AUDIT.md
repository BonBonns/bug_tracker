# v2 evidence-expansion — producer-to-consumer audit (steps 2–4)

Question: can improving the scanner's evidence reduce the cases that are not yet
ready for meaningful review? First, find the highest-volume *generalizable,
sound* gap — without implementing anything until the audit identifies it.

Baseline: frozen scanner **v1** is untouched. All numbers are DISTINCT
operations (deduplicated by the exact frozen operation fingerprint), not raw
producer records.

## Step 2 — distinct-operation distribution (broader population)

3,246 raw producer records → **2,532 distinct operations**.

| route | distinct ops | share |
|-------|--------------|-------|
| ADDITIONAL_EVIDENCE_REQUIRED | 2,248 | 88.8% |
| LLM_SEMANTIC_REVIEW | 198 | 7.8% |
| SEMANTIC_CONTRACT_REVIEW | 62 | 2.4% |
| DETERMINISTIC_COMPLETE | 24 | 0.9% |

ADDITIONAL_EVIDENCE_REQUIRED by exact reason:

| reason | distinct ops |
|--------|--------------|
| **required_evidence_absent** | **1,882** |
| destination_identity_ambiguous | 350 |
| conflicting_reaching_allocations | 16 |

`required_evidence_absent` is the highest-volume category by far (74% of all
distinct operations). Audit focuses there.

## Step 3–4 — where is the missing evidence?

`required_evidence_absent` (1,882) by write-width form:

| width form | ops | verdict |
|------------|-----|---------|
| `N * sizeof(T)` array write | 964 | **correct abstain** — destination capacity is the caller's buffer size, genuinely absent from a single-function view. NOT a scanner gap; leave as-is. |
| `sizeof(T)` single-object (needs dest-type match) | 292 | **fixable** — evidence produced but unused |
| `sizeof(*dest)` single-object (syntactic) | 56 | **fixable** — purely syntactic |
| non-`sizeof` (length-var / other) | 570 | mixed; deferred (needs per-case evidence) |

**Producer-to-consumer categorization of the fixable single-object subset (348):**

- Source: the write is `memcpy/memset(dest, …, sizeof(T))` where `dest` is a
  pointer to `T` — e.g. `PORT_Memcpy(pInfo, &info, sizeof(CK_MECHANISM_INFO))`
  with `pInfo : CK_MECHANISM_INFO_PTR`. The capacity relationship is present in
  the source.
- Joern: exports the destination's type (`typeFullName`) — confirmed in the raw
  `identifiers.tsv` (`pInfo`, `cert`, …).
- Normalization: **carries it through** — `cpp.json` identifiers hold
  `type_full_name` (verified: `pInfo`→`CK_MECHANISM_INFO_PTR`,
  `cert`→`NSSLOWCERTCertificate*`, `pSlotList`→`CK_SLOT_ID_PTR`, …).
- Producer: **does NOT use it.** `oob_runtime_capacity_verdict` abstains with
  `required_evidence_absent` even though the destination type + the `sizeof(T)`
  width together prove the write is exactly one pointee object.

**Category: PRODUCED BUT UNUSED.** The fix is purely in analysis (a v2 producer
copy) — no Joern or normalization change needed.

## The one evidence capability to add (v2)

**Single-object-copy bounding.** A recognized buffer write whose width is
`sizeof(*dest)` / `sizeof(dest[0])` (syntactic), or `sizeof(T)` with **no
multiplier** where the destination's `type_full_name` is a pointer to `T`,
writes exactly one pointee object. The destination, being a valid pointer to
`T`, has capacity ≥ `sizeof(T)`, so the write is **deterministically bounded**.

- General, not CVE-specific: any single-object struct/scalar copy.
- Sound under the standard valid-pointer-parameter assumption the analysis
  already relies on. It never fires for `N * sizeof(T)` array writes (capacity
  genuinely unknown) — those correctly stay `required_evidence_absent`.
- Establishment: capacity established from the destination TYPE + the `sizeof`
  width, both already in `cpp.json`. Provenance preserved (records the type and
  the width that justified it).

Soundness guards (to avoid promoting on assumption):
1. Width must be exactly one `sizeof(...)` with no `*` multiplier outside the
   `sizeof` argument.
2. `sizeof(*dest)` / `sizeof(dest[0])` — accepted syntactically (pointee of the
   exact destination).
3. `sizeof(T)` — accepted only when the destination type literally ends in `*`
   and its pointee equals `T`, OR a `T_PTR` typedef is resolved to `T *` via the
   exported type facts. A `_PTR`-suffix name alone, unresolved, is NOT accepted.

Expected reach: up to ~348 of the 1,882 `required_evidence_absent` operations
move toward deterministic resolution — measured exactly by the v1-vs-v2
comparison, which reports every operation that changes route and the type+width
evidence responsible. Not implemented until this audit (done) identified the gap.
