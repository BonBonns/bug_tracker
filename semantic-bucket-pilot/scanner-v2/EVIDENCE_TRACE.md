# Per-operation evidence trace — where the evidence is actually lost (closing)

Supersedes the "misrouting" framing in `MISROUTING_AUDIT.md`. Three levels are
kept separate: **L1 source** (`T buf[N]` exists), **L2 normalized fact**
(`cpp.json` `locals` carries `T[N]` for `dest` in the function), **L3 producer
binding** (`compute_allocation_extents` ESTABLISHED an extent for `(fn, dest)` —
the producer actually consumed it). Only L3 proves a routing mistake.

## Closing totals (assertions in `evidence_trace.py` pass)

| | value |
|--|------|
| operation instances traced | **938** |
| distinct destination identities `(source, function, dest)` | **738** |
| unaccounted operations | **0** |

Both denominators are reported: **938 operation instances** vs **738 destination
identities** (the 200 difference are additional write-ops to the same
destinations, each traced with its own offset and write length). Destination
identity is keyed on the **declaration node** (`array_decls` returns per-node
decls), never the bare name, so shadowed/repeated names cannot collapse. Every
operation carries: `normalized_capacity_status`, `producer_binding_status`,
`destination_identity`, `offset`, `write_length`, `v1_reason`,
`capability_1_reachable`, `proposed_v2_reason`.

## Cross-tabulation (defect → proposed v2), closes to 938

This is a real mapping, row by row — not two parallel columns.

| defect location | required evidence | proposed v2 disposition | count |
|-----------------|-------------------|-------------------------|-------|
| **producer_consumer_gap** | stack capacity already normalized, count symbolic | relationship_unresolved | **522** |
| **producer_consumer_gap** | stack capacity + literal, type-matched, offset-0 comparison | deterministic_complete | **16** |
| local_pointer_no_local_array | none locally (dest is a pointer; backing elsewhere) | required_evidence_absent | 270 |
| name_collision_other_function | none here (array is a different function's variable) | required_evidence_absent | 62 |
| genuine_multi_identity | TChecker facts hold >1 array decl for dest in this fn | destination_identity_ambiguous | 56 |
| normalizer_evidence_loss | capacity dropped by normalization — must be recovered first | **not reachable by capability 1** | 12 |
| **TOTAL** | | | **938** |

`router_misclassification = 0` (verified): no operation was L3-bound yet
abstained. v1's `required_evidence_absent` was correct from the producer's own
state — the evidence exists upstream but is not consumed.

### The two previously-collapsed categories, now separated

- **`frontend_or_genuinely_absent` (270) → all 270 are `local_pointer_no_local_array`.**
  Checked against Joern's raw `locals.tsv` (function-scoped): every one is a local
  **pointer**, not a fixed array. There are **0** "present in source but missing
  from Joern" and **0** "out of scan scope" here — the category did not actually
  collapse three causes; it is uniformly local-pointer, whose capacity is a
  separate allocation/backing question, not a local array.
- **`audit_identity_collision` (118) → 56 genuine + 62 not.** 56 have **>1 array
  declaration for `dest` in the same function** (a real identity ambiguity in
  TChecker's facts) → `destination_identity_ambiguous`. The other 62 have **no
  array in this function**; the same name is an array only in a *different*
  function — not a TChecker ambiguity, so they are **not** placed in the
  identity-ambiguous bucket; they get `required_evidence_absent`
  (`name_collision_other_function`).

## Capability 1 — actual reach = 538, not 938

The narrow stack-capacity integration can affect only operations where (a) a
normalized local-array capacity fact exists, (b) its declaration identity
**uniquely** matches the destination, and (c) the producer currently fails to
consume it — i.e. exactly `producer_consumer_gap`:

| capability-1 reach | count |
|--------------------|-------|
| **total reachable** | **538** |
| → relationship_unresolved | 522 |
| → deterministic_complete | 16 (**4 unique functions**, one repeated pattern) |

Everything else is **out of capability 1's reach** and needs separate work:
`normalizer_evidence_loss` (12, normalizer fix), `local_pointer_no_local_array`
(270, allocation/backing analysis), `name_collision_other_function` (62, audit
join / identity resolution), `genuine_multi_identity` (56, identity resolution).
Capability 1 does **not** borrow any of that evidence.

## G4 deterministic subset — 16 instances, 4 unique functions, one pattern

`s_mp_mul_comba_4/8/16/32` × E2/E4 × vuln/patched. Each validated individually
against source (offset 0, fresh stack, `k ≤ N`, `mp_digit` type-matched):
`at[8]`←4, `at[16]`←8, `at[32]`←16, `at[64]`←32. **Not 16 independent examples.**

**Offset writes validated separately:** each comba function also has a sibling
`memcpy(at + K, …, K*sizeof(mp_digit))` (K = N/2). Those are DIFFERENT operations
that the producer does **not** recognize (destination `at + K` is not a bare
identifier), so they are **outside the 938**. They are in-bounds (`K + K = N ≤ N`)
but require offset-aware handling — reported, not credited by the offset-0
capability.

## Clean conclusion

The trace identified a general **producer–consumer integration gap affecting 538
operations**: normalized stack-array capacity evidence exists but is not consumed
by the runtime-capacity producer (which binds only heap `direct_allocation`
extents). A narrow v2 integration — import normalized fixed local-array capacity
into the extent model, preserving declaration identity, element type, capacity
expression, source provenance, and lifetime scope, establishing **capacity
only** — can recover that evidence **without** changing the frontend or
normalizer. It would turn 522 into `relationship_unresolved` and 16 (4 functions)
into `deterministic_complete` after the offset-aware, type-matched comparison.
The other cases require separate frontend, normalization, identity-resolution, or
allocation/backing work.

## The 91% caveat (preserved)

The 88.8–91% additional-evidence figure is **the route frozen v1 emitted**, not
the verified fraction that truly lacked evidence. A corrected v2 percentage may
be computed only after implementing the capacity-import fix, re-running over all
inputs, and tracing the full additional-evidence population to completion. None
is claimed here. No scanner fix is applied.
