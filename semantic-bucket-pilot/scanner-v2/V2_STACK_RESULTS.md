# Capability 1 — stack fixed-array capacity: implementation results

Frozen v1 untouched. v2 (`oob_runtime_capacity_v2`) consumes normalized stack
fixed-array capacity keyed by declaration node, only for operations v1 abstained
on with `required_evidence_absent`.

## Validation gate — 15/15 (all 11 required cases)

`gate_stack_capacity_v2.py`: direct fixed array accepted; same name in different
functions separated by `(fn, decl-node)`; shadowed arrays resolved uniquely by
node id; pointer parameter not treated as an array; pointer alias excluded; VLA
and multidimensional excluded; offset write (`at+4` → `value_ref.kind=CALL`)
excluded; mismatched element types not simplified; symbolic write count →
`relationship_unresolved`; literal safe vs oversized distinguished; heap behavior
unchanged. Frozen v1 gates still green (runtimecap 18/18, cfg 6/6,
analysis-record 53/53).

## v1-vs-v2 over identical inputs (10 scans, 2,150 runtime operations)

| | value |
|--|------|
| operations changed | **620** |
| → relationship_unresolved | 566 |
| → deterministic_complete | 54 |
| **unjustified changes** (no stack evidence) | **0** |
| **unsupported deterministic promotions** | **0** |
| **heap / other records touched** | **0** |

Every change carries `stack_fixed_array` evidence (provenance, declaration node,
element type, element count, capacity expression, width, comparison note); every
`deterministic_complete` carries a type-matched, offset-0, `k ≤ N` comparison.
The three invariants — only-justified changes, zero unsupported promotions, heap
untouched — all hold.

### Reconciliation with the audit's expected reach (538 / 16)

The audit estimated 538 changed / 16 deterministic over the **938
local-destination subset**. The actual v2 reach is larger — **620 / 54** — and
this is expected, not a discrepancy:

- The 938 audit subset came from the caller-inspection `array_out_param` filter,
  which required a `sizeof` in the width. That filter **missed literal-byte-width
  writes** (`memcpy(kk, key, 24)`, `memcpy(firstBlock, header, 13)`), which are
  stack fixed-array writes v2 correctly binds. So the audit's 16 deterministic
  (comba only, `k*sizeof`) was a subset undercount.
- The extra promotions are all runtime `required_evidence_absent` ops outside
  that filter; none touch heap or non-abstained records (invariant verified).

So 538/16 was a lower bound on a filtered view; 620/54 is the full, justified
reach over the runtime population.

### Deterministic promotions — validated against source

54 operations across 15 function names (crypto routines; E2/E4 are both freebl,
so several source functions recur across the two scans). Spot-checked
individually:

| function | declaration (normalized) | write | check |
|----------|--------------------------|-------|-------|
| s_mp_mul_comba_4/8/16/32 | `mp_digit at[8..64]` | `(N/2)*sizeof(mp_digit)` | k ≤ N, type-matched |
| camellia_setup192 | `unsigned char kk[32]` | `memcpy(kk, key, 24)` | 24 ≤ 32, offset 0 |
| fe_frombytes | `uint8_t s_copy[32]` | `memcpy(s_copy, s, 32)` | 32 ≤ 32, offset 0 |
| MAC (hmacct.c) | `unsigned char firstBlock[144]` | `memcpy(firstBlock, header, 13)` | 13 ≤ 144, offset 0 |
| sftk_CryptInit | `unsigned char newdeskey[24]` | 16 bytes | 16 ≤ 24 |
| NSC_DeriveKey | `unsigned char des3key[24]` | 24 bytes | 24 ≤ 24 |
| ec_secp256/384/521_* | `uint8_t hash[32/48/…]` | 32/48/… bytes | k ≤ N |

In every case the sibling **offset writes** (`kk+24`, `firstBlock+13`,
`at+4`, …) resolve to `value_ref.kind == CALL` and are correctly **excluded** —
they are separate operations, not credited by this offset-0 capability.

## What this establishes

The producer–consumer integration gap is closed for the reachable class: stack
fixed-array capacity that was present in the normalized facts but unconsumed is
now bound at the declaration node and compared. 566 operations move from
`additional_evidence_required` to `relationship_unresolved` (reviewable
relationship — capacity bound, count symbolic), and 54 to `deterministic_complete`
(provable, type-matched, offset-0). No unsupported promotion, no heap effect, and
frozen v1 remains the untouched baseline.

The audit-driven implementation is complete: only operations justified by newly
consumed stack-capacity evidence changed. Out-of-reach classes (normalizer loss,
local pointers, name collisions, genuine multi-identity, heap) are unchanged and
remain future work.
