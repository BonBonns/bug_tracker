# v2 evidence-expansion — results (single-object-copy capability)

Research question: can improving the scanner's evidence reduce the cases not yet
ready for meaningful review? Answer for this one capability: **yes, soundly, for
88 operations**, with zero incorrect movements.

## The capability

Single-object-copy bounding (see AUDIT.md for why this is the highest-volume
generalizable gap). A write of `sizeof(*dest)` / `sizeof(dest[0])` (syntactic),
or `sizeof(T)` into a **literal `T *`** destination (pointee match), writes
exactly one pointee object → deterministically bounded. Implemented as a
post-pass over frozen v1 (v1 unmodified); uses the destination `type_full_name`
already in `cpp.json` (produced-but-unused). Excludes `N * sizeof(T)` array
writes and unresolvable `X_PTR` typedefs — **no naming-convention assumptions**.

## v1-vs-v2 on byte-identical inputs (broader population, 2,150 distinct ops)

| measurement | v1 | v2 | Δ |
|-------------|----|----|---|
| additional-evidence-required | 1,974 | 1,886 | **−88** |
| deterministically resolved | 20 | 108 | **+88** |
| ready for focused LLM review | 156 | 156 | +0 |
| operations changed route | — | 88 | — |
| **previously-correct outcomes changed incorrectly** | — | **0** | — |
| soundness violations (must be 0) | — | **0** | — |

- **Remaining additional-evidence-required: 1,886** (down from 1,974).
- **Deterministically resolved: +88** — these leave the review queue entirely
  (proven safe), which is the goal: they were never review-worthy, only
  evidence-starved.
- **LLM-review-ready: unchanged (+0)** — correct. Single-object writes are proven
  safe, not routed to review; the capability does not inflate the review queue.
- **Zero incorrect movements.** Every change is
  `abstained/required_evidence_absent → deterministic_complete`, each carrying
  the exact evidence (the `sizeof(*dest)` form, or the destination type + the
  `sizeof(T)` width). The comparison's soundness check — v2 may ONLY make that
  transition, never touch a warning verdict, an open candidate, or any other
  route — passed with 0 violations.

## Generalization

The 88 promotions span **4 NSS modules** (softoken, freebl ×2 revisions, certdb)
and **28 distinct functions** — overwhelmingly the canonical
`memset(ctx, 0, sizeof(*ctx))` / `memcpy(dst, src, sizeof(*ctx))` idiom in
context destroy/clone/init routines (AES/BLAKE2B/CMAC/CTR/ChaCha20/MD5/SHA
`DestroyContext` & `Clone`, `sftk_InitGeneric`, `fe_copy`, `CERT_*FromDERCert`,
…). 56 promotions via the syntactic `sizeof(*dest)` form, 32 via the typed
`sizeof(T)`-into-`T*` form. The idiom is a general C pattern, not NSS-specific;
the capability keys on the write shape + destination type, not on any function
or project.

The expansion corpus is single-repo (NSS); the mozjpeg corpus is cursor-based
(count writes, out of this capability's scope). Cross-repo generalization of the
single-object idiom is expected but is asserted here only within NSS's four
modules — a limitation stated, not hidden.

## Ground-truth safety

By construction the pass touches only `required_evidence_absent` abstentions. All
five independently-verified corpus cases are `open_candidate`
(capacity/count-relationship) or `unknown_allocator_contract` — never
`required_evidence_absent` — so none can be moved by v2 (structural guarantee).
Empirically confirmed on a frozen-corpus input subset (8 files, 21 distinct ops
covering `rsa_FormatOneBlock`, `encode_one_block`, `sec_asn1d_add_to_subitems`):
**0 operations changed route, 0 soundness violations, 0 ground-truthed cases
moved** (`compare_v1_v2_frozen.json`). The remaining two (`sftk_compute_ANSI_X9_63_kdf`,
`nsc_pbe_key_gen`) are `open_candidate` and thus untouchable by the same
guarantee. No ground-truthed vulnerable, safe, or unresolved case changes route.

## What this shows

Improving the scanner's evidence — here, *using* a fact it already had — moves
real operations out of the not-yet-reviewable queue **without** sending them to
the LLM and **without** any unsound promotion. It confirms the routing-evaluation
thesis from the other direction: a large part of the 88.8% additional-evidence
majority is not a semantic-review problem at all but unused deterministic
evidence, recoverable one sound capability at a time. `X_PTR`-typedef single-object
writes (excluded here for soundness) are the natural next capability, gated on
resolving those typedefs from the source headers rather than assuming the naming
convention.
