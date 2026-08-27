# A/B/C feasibility over the frozen llm-eligible corpus

This is the ground-truth + case-selection layer over the frozen scanner corpus.
It answers one question before any prompt is written: **does the frozen
llm-eligible corpus contain enough genuinely-independent, independently-verified
routable cases to support a balanced A/B/C accuracy experiment?** The honest
answer is **no** — and that is the reason this layer exists.

## The pool shrinks a lot under honest de-duplication

| stage | count |
|-------|-------|
| frozen `llm_eligible.jsonl` records | 44 |
| distinct experimental cases (by code identity, `case_identity.py`) | 7 |
| genuinely independent cases (dropping shared-defect duplicates) | 5 |
| vuln/patched differentials (text-level) | 1 |
| effective differentials (incl. macro-capacity) | 2 |

Why 44 → 7:
- Many records are multiple write-lines within one function (28 for
  `encode_one_block` alone).
- `sftk_compute_ANSI_X9_63_kdf` appears under **both** CVE-2019-11745 and
  CVE-2019-11759 (same `pkcs11c.c`, byte-identical body) — one case, not two.
  The frozen fingerprint kept these separate (keyed on the CVE label); this
  layer folds them by code identity.

Why 7 → 5 independent:
- `flush_bits` shares the exact mozjpeg `BUFSIZE` defect with `encode_one_block`
  (same file, same buffer, same fix) — not a second bug.
- `nsc_pbe_key_gen@11759` is the same function as `@11745` at a slightly
  different revision — weakly independent at best.

## Verified outcomes of the 5 independent cases (see `ground_truth.json`)

| case | scanner bucket | verified outcome (vuln → patched) | independent |
|------|----------------|-----------------------------------|-------------|
| `rsa_FormatOneBlock` (CVE-2019-17006) | relationship_unresolved | **vulnerable → safe** (padLen `int`→`unsigned int`) | yes — the one true differential |
| `encode_one_block` (mozjpeg) | relationship_unresolved | **vulnerable → safe** (BUFSIZE 136→256) | yes — differential is in the macro, not the body text |
| `sftk_compute_ANSI_X9_63_kdf` | relationship_unresolved | safe → safe | yes — incidental, provably safe (alloc sized to fit) |
| `nsc_pbe_key_gen` | relationship_unresolved | unresolved → unresolved | yes — incidental, needs caller contract |
| `sec_asn1d_add_to_subitems` | external_contract_unknown | safe → safe | yes — incidental, safe once allocator contract established |

Distinct-defect balance: **2 vulnerable / 2 safe / 1 unresolved** = 5. The
vulnerable count (2) is the binding constraint.

## Verdict: not enough for a balanced accuracy claim

The user's target was ≥9 genuinely routable cases, balanced 3 safe / 3
vulnerable / 3 unresolved, with no manufactured or six-variations-of-one-function
padding. This corpus yields **5 independent cases with only 2 genuine
vulnerable differentials**, and the routable buckets are dominated by
`relationship_unresolved` (6 of 7 cases); the other candidate-review buckets
(`identity_ambiguous`, `conflicting_definitions`) are **not `llm_eligible`** —
they route to `additional_evidence_required` and never enter A/B/C at all. So
even the bucket *diversity* the experiment is meant to test is mostly absent
from the LLM-eligible set.

Consequences, stated plainly:
- These 5 cases support a **mechanics dry run** (does the A/B/C prompt pipeline
  render and score correctly?) — nothing more.
- They **cannot** support an A/B/C accuracy comparison, and B-vs-C in particular
  has almost no bucket variety to discriminate on.

## Recommendation

To make any A/B/C accuracy claim, **enlarge the genuine routable-vulnerable pool
by scanning more disclosed CVEs through the frozen scanner** (the scanner and
schema stay frozen at v1; only inputs are added). Targets: cases that land in
the under-represented eligible buckets and, especially, more true
vulnerable/patched differentials. Manufacturing balance from the current 5 —
or promoting incidental vuln==patched candidates to "vulnerable" — is exactly
what the earlier guidance forbade, so this layer stops here and surfaces the
constraint instead of papering over it.
