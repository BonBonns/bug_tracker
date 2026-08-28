# Per-operation evidence trace — where the evidence is actually lost

This supersedes the "misrouting" framing in `MISROUTING_AUDIT.md`. That write-up
jumped from "capacity is in the source" to "misrouted." The three levels must be
kept separate:

1. **L1 source** — `T buf[N]` exists in the .c/.h.
2. **L2 normalized fact** — `cpp.json` `locals` carries `T[N]` for `dest` in the function.
3. **L3 producer binding** — `compute_allocation_extents` ESTABLISHED an extent
   for `(fn, dest)`; i.e. the producer actually **consumed** the capacity.

Only L3 proves a pure routing mistake. Checking L3 changes the conclusion.

## Accounting (938 operations, no gaps)

| | count |
|--|------|
| local operations (caller inspection) | 938 |
| distinct destinations `(source, function, dest)` | 738 |
| collapsed extra operations (multiple write-ops to the same destination) | 200 |
| operation-level records traced | 938 |

The 200 are not a missing group — they are additional write operations to the
same 738 destinations, each traced.

## Defect category split (per operation) — validated

| defect | ops | what it means |
|--------|-----|---------------|
| **producer_consumer_gap** | **594 (63%)** | L2 yes, L3 no — the capacity is in `cpp.json`, but `compute_allocation_extents` only binds heap `direct_allocation` sites and **never consumes stack fixed-array capacities**, so the producer had no extent and abstained. |
| frontend_or_genuinely_absent | 270 (29%) | L2 no, raw locals no — the destination is a pointer with no local array capacity in the facts. |
| audit_identity_collision | 62 (7%) | a same-named array exists only in a **different** function; scoping by method-id prevents crediting it (the category-5 error, now caught). |
| normalizer_evidence_loss | 12 (1%) | raw `locals.tsv` carries the array in this function, but normalization dropped it from `cpp.json`. |
| **router_misclassification** | **0** | none were L3-bound yet abstained. There are **no pure routing bugs**. |

**Verification.** `compute_allocation_extents` on the freebl scan yields 66
extents, **all `provenance=direct_allocation` (heap)** — zero stack-array
extents; `s_mp_mul_comba_4` gets no extent for any destination, so `at[8]` is
never bound. The `normalizer_evidence_loss` and `audit_identity_collision`
categories were separated by function-scoping the raw check (e.g.
`Hacl_Hash_SHA3_update_last_sha3:lastBlock` is a `uint8_t*` in that function; the
`lastBlock[MAX_BLOCK_SIZE]` array lives in a different function — an identity
collision, not a dropped fact).

## The earlier "misrouted" claim was wrong

There are **0 pure routing misclassifications**. v1's `required_evidence_absent`
was, from the producer's own state, correct: it genuinely lacked a bound
capacity. The evidence exists upstream (normalized facts for 594, raw Joern for
another 12) but is **not consumed** — a producer–consumer integration gap and a
small normalizer loss, **not** a wrong reason label. Recovering it requires
fixing the producer (and the normalizer), not relabeling.

## G4 provable subset — each validated individually

The 16 G4 operations are 4 unique functions (`s_mp_mul_comba_4/8/16/32`) × E2/E4
× vuln/patched. Each, validated against source (not generalized from one):

| function | dest | write | offset | lifetime | verdict |
|----------|------|-------|--------|----------|---------|
| s_mp_mul_comba_4 | `mp_digit at[8]` | `memcpy(at, …, 4*sizeof(mp_digit))` | 0 | fresh stack, no free/reassign | 4 ≤ 8 ✓ |
| s_mp_mul_comba_8 | `at[16]` | `8*sizeof(mp_digit)` | 0 | fresh | 8 ≤ 16 ✓ |
| s_mp_mul_comba_16 | `at[32]` | `16*sizeof(mp_digit)` | 0 | fresh | 16 ≤ 32 ✓ |
| s_mp_mul_comba_32 | `at[64]` | `32*sizeof(mp_digit)` | 0 | fresh | 32 ≤ 64 ✓ |

Provably safe via the compiler-defined `sizeof` relationship (`k·sizeof ≤
N·sizeof ⇒ k ≤ N`), no ABI sizes guessed. (The sibling `memcpy(at+K, …)` writes
use a non-bare `at+K` destination the producer does not flag; they are also safe
but require offset accounting.) These become `deterministic_complete` **only
after** the producer consumes the stack-array capacity — today they are
`producer_consumer_gap`, not routing bugs.

## Corrected v2 target and the 91% caveat

- **Capability #1 candidate is the producer–consumer fix**: extend
  `compute_allocation_extents` to bind **stack fixed-array** capacities (594
  operations gain a bound capacity), plus the small normalizer fix (12). Then the
  producer would correctly emit `relationship_unresolved` where the count is
  symbolic, and `deterministic_complete` where the comparison is provable (the
  comba subset). This is a *binding* improvement, not a reroute and not
  single-object copying.
- **The 91% figure stands as "the route frozen v1 emitted."** It is **not** the
  verified fraction that truly lacks evidence. A corrected v2 percentage can be
  computed only after (a) implementing the producer/normalizer fixes, (b)
  re-running over all inputs, and (c) tracing all 938 (plus the rest of the
  additional-evidence population) to completion. No corrected percentage is
  claimed here.

No scanner fix is applied. The deliverable is the trace: it shows exactly where
the system loses or fails to consume semantic evidence.
