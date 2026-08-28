# Per-operation evidence trace — where the evidence is actually lost (closing)

This supersedes the "misrouting" framing in `MISROUTING_AUDIT.md`. That write-up
stopped at L2 (capacity is in the normalized facts) and wrongly called cases
"misrouted." The three levels must be kept separate:

1. **L1 source** — `T buf[N]` exists in the .c/.h.
2. **L2 normalized fact** — `cpp.json` `locals` carries `T[N]` for `dest` in the function.
3. **L3 producer binding** — `compute_allocation_extents` ESTABLISHED an extent
   for `(fn, dest)`; i.e. the producer actually **consumed** the capacity.

Only L3 proves a pure routing mistake. Checking L3 changed the conclusion.

## Closing totals (assertions in `evidence_trace.py` pass)

| | value |
|--|------|
| operation instances traced | **938** (== 938) |
| distinct destination identities `(source, function, dest)` | **738** (== 738) |
| unaccounted operations | **0** |
| distinct declaration-node identities | 714 |

Both denominators are reported: **938 operation instances** vs **738 destination
identities**. The 200 difference is additional write operations to the same
destinations; each keeps its own offset and write length and is traced
individually (not assumed to share a disposition). Every operation record
carries: `normalized_capacity_status`, `producer_binding_status`,
`destination_identity` (declaration-node id, never the bare name),
`offset`, `write_length`, `v1_reason`, and `proposed_v2_reason`.

## Defect category split (per operation) — validated, identity by decl node

| defect | ops | meaning |
|--------|-----|---------|
| **producer_consumer_gap** | **538** | L2 yes, L3 no — capacity in `cpp.json`, but `compute_allocation_extents` binds only heap `direct_allocation` sites and **never consumes stack fixed-array capacities**. |
| frontend_or_genuinely_absent | 270 | pointer / no local array capacity in the facts. |
| audit_identity_collision | 118 | a same-named array is shadowed / lives in a different function; keying on declaration-node identity prevents crediting it. |
| normalizer_evidence_loss | 12 | raw `locals.tsv` carries the array in this function, normalization dropped it from `cpp.json`. |
| **router_misclassification** | **0** | none were L3-bound yet abstained. **No pure routing bugs.** |

**Verification.** `compute_allocation_extents` on the freebl scan yields 66
extents, **all `provenance=direct_allocation` (heap)** — zero stack-array
extents; `s_mp_mul_comba_4` gets no extent for any destination, so `at[8]` is
never bound. v1's `required_evidence_absent` was, from the producer's own state,
correct: it genuinely lacked a bound capacity. The evidence exists upstream but
is **not consumed** — a producer–consumer integration gap (and a small
normalizer loss), **not** a wrong reason label.

## Proposed v2 disposition (after the capacity-import capability, no fix applied)

| proposed v2 reason | ops | why |
|--------------------|-----|-----|
| relationship_unresolved | 534 | capacity bound, but the write count is symbolic (`count·sizeof`) → a relationship to prove, not a missing fact. |
| required_evidence_absent | 270 | genuinely no local capacity (pointer / caller-scope) — unchanged. |
| destination_identity_ambiguous | 118 | shadowed / repeated declaration — identity must be resolved first. |
| deterministic_complete | 16 | literal, type-matched, offset-0, `k ≤ N`, fresh lifetime — provable via the sizeof-preserving comparison. |

These are what the dispositions **would become** once the producer consumes the
capacity; nothing is promoted here.

## G4 provable subset — 16 instances, but 4 unique functions / one pattern

The 16 `deterministic_complete` proposals are `s_mp_mul_comba_4/8/16/32` × E2/E4
× vuln/patched — **only 4 unique functions and one repeated code pattern; not 16
independent examples.** Each validated individually against source (offset 0):

| function | dest (decl node) | write | offset | lifetime | k ≤ N |
|----------|------|-------|--------|----------|-------|
| s_mp_mul_comba_4 | `mp_digit at[8]` | `memcpy(at, …, 4*sizeof(mp_digit))` | 0 | fresh, no free/reassign | 4 ≤ 8 |
| s_mp_mul_comba_8 | `at[16]` | `8*sizeof(mp_digit)` | 0 | fresh | 8 ≤ 16 |
| s_mp_mul_comba_16 | `at[32]` | `16*sizeof(mp_digit)` | 0 | fresh | 16 ≤ 32 |
| s_mp_mul_comba_32 | `at[64]` | `32*sizeof(mp_digit)` | 0 | fresh | 32 ≤ 64 |

**Offset writes validated separately:** each comba function also has a sibling
`memcpy(at + K, …, K*sizeof(mp_digit))` (K = N/2). These are DIFFERENT operations
that the producer does **not** recognize (the destination `at + K` is not a bare
identifier), so they are **outside the 938**. They are also in-bounds
(`K + K = N ≤ N`) but require offset-aware handling — they are not credited by
the offset-0 capability and are reported here explicitly, not assumed.

## The first sound v2 capability (narrowly defined)

**Import normalized fixed local-array capacity facts into the existing extent
model**, preserving declaration identity, element type, capacity expression,
source provenance, and lifetime scope. It establishes **capacity only** — it must
never declare a copy safe on its own. After integration:

- symbolic write length → `relationship_unresolved` (534);
- literal, type-matched, offset-0, `k ≤ N` → `deterministic_complete` only after
  the offset-aware comparison (16);
- pointer parameters / unresolved destinations → `required_evidence_absent` (270);
- conflicting / shadowed identities → `destination_identity_ambiguous` (118).

This is a *binding* improvement (evidence produced but unused → consumed), not a
reroute and not single-object copying.

## The 91% caveat (preserved)

The 88.8–91% additional-evidence figure is **the route frozen v1 emitted**, not
the verified fraction that truly lacked evidence. A corrected v2 percentage may
be computed only after (a) implementing the capacity-import (and normalizer)
fixes, (b) re-running over all inputs, and (c) tracing the full additional-evidence
population to completion. No corrected percentage is claimed here. This deliverable
is the trace: it shows exactly where the system loses or fails to consume
semantic evidence. No scanner fix is applied.
