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

## v1-vs-v2 over identical inputs (10 scans)

| | value |
|--|------|
| operations changed | **620** |
| → relationship_unresolved | 566 |
| → deterministic_complete | 54 |
| **unjustified changes** (no stack evidence) | **0** |
| **unsupported deterministic promotions** | **0** |
| **heap / other records touched** | **0** |

Every change carries `stack_fixed_array` evidence (provenance, declaration node,
element type, element count, capacity expression, width, comparison note). The
three invariants — only-justified changes, zero unsupported promotions, heap
untouched — all hold (`compare_v1_v2_stack.py`).

---

## Four tightened claims

### 1. The denominator: 2,174 raw runtime records → 2,150 distinct operations

The runtime producer emits **2,174 raw records** over the 10 scans; the frozen
operation fingerprint (`_source_label|file|function|line|dest`) collapses these to
**2,150 distinct operations**. The missing **24** are **within-scan fingerprint
collisions** — not dedup across producers, not a filter, not a failed join:

- **12 distinct fingerprints**, each emitted **2–4 times** by the runtime producer
  (2+2+2+2+3+3+3+3+4+4+4+4 = 24 extra records over 12 fingerprints).
- **All 12 are in E4** (both `vuln` and `patched`), functions
  `sample_matrix_A_e7` / `e70` / `e71`, one source line each (8149 / 6235 / 3124),
  destinations `copy_of_seed` and `copy_of_seeds` — the same
  `(file, function, line, dest)` site emitting several raw call records (a
  macro/repeat expansion at one source location).
- **Every one is `abstained → abstained`** in both v1 and v2. The frozen
  fingerprint deliberately treats one physical destination-operation as one case,
  so the collapse removes only duplicate records and **changes no route
  conclusion**. (`denom_detail`, archived in the results JSON.)

### 2. `deterministic_complete` proves ONLY write-length-within-capacity

A `deterministic_complete` promotion here does **not** mean the operation is
safe. It establishes exactly one property:

> `established_property = "write_length_within_destination_capacity"`

i.e. the write length is ≤ the destination's stack capacity, type-matched and at
offset 0. Each such record now carries, explicitly:

    "established_property":    "write_length_within_destination_capacity"
    "unaddressed_properties":  ["source_length_sufficiency", "pointer_validity", "lifetime"]

For a `memcpy(dest, src, k)` this says nothing about whether the **source** holds
`k` valid bytes, whether `src`/`dest` are valid pointers, or lifetime. Those are
separate properties this capability does not attempt. The scope is the destination
capacity bound and only that.

### 3. Independent source validation of all 54 deterministic promotions

The comparison's "zero unsupported promotions" is a **contract-conformance**
check: it asserts every deterministic record satisfies the predicate v2 itself
implemented (same code path), so on its own it is circular.

To break the circularity, `validate_deterministic_source.py` re-derives the
result from **L1 source text with a separate predicate** — it does **not** call
`v2.compare()` and does **not** read the normalized `cpp.json` capacity facts.
For each of the 54 it independently:

- parses the array declaration bound `N` from raw C, handling **multi-declarator**
  statements (`mp_digit c0, c1, c2, at[8];`) and **macro bounds** with
  indirection (`firstBlock[HASH_BLOCK_LENGTH_MAX]` →
  `SHA3_224_BLOCK_LENGTH` → `144`);
- confirms the declaration's leading type matches the claimed element type;
- re-parses the literal write count `k` from the width expression;
- checks `k ≤ N` at offset 0.

Result: **54 / 54 independently CONFIRMED from source**, verdicts
`{CONFIRMED: 54}`. This independently validates the **single property**
`write_length_within_destination_capacity` (per claim 2) — not source
sufficiency, not pointer validity. All 54 rows (function, dest, source bound,
derivation method, literal k, verdict) are archived in
`validate_deterministic_source.json`.

So the honest phrasing is: **every one of the 54 was independently source-validated
for the destination-capacity property** — not merely contract-conforming, and not
a representative spot-check.

### 4. The 566 are NOT all "LLM review" — reason-specific routes preserved

`relationship_unresolved` is a bucket, not a single route. The 566 keep their
distinct routes, matched to what evidence is actually missing:

| v2 route | ops | what is missing | who should handle it |
|----------|----:|-----------------|----------------------|
| **semantic_relationship_review** | 498 | code meaning: `count`/width is symbolic or `count*sizeof(other-type)` — a relationship between program values | LLM semantic review |
| **range_arithmetic_review** | 68 | numeric bound only: width is `count*sizeof(T)` with `T` = element type; capacity bound, count symbolic — a numeric range fact | deterministic range / interval analysis |
| deterministic_complete | 54 | nothing (destination-capacity property proven) | none |

Only the **498** semantic-relationship operations are LLM-eligible
(`llm_eligible = (route == "semantic_relationship_review")`). The **68**
range/arithmetic operations are better routed to numeric range analysis than to an
LLM — a symbolic length relationship over a matched element type is a bounds
question, not a code-meaning question. Equating all 566 with LLM review would
overstate the LLM surface by 68.

---

## Reconciliation with the audit's expected reach (538 / 16)

The audit estimated 538 changed / 16 deterministic over the **938
local-destination subset**. Actual v2 reach is **620 / 54**, and this is expected:

- The 938 audit subset came from the caller-inspection `array_out_param` filter,
  which required a `sizeof` in the width, so it **missed literal-byte-width writes**
  (`memcpy(kk, key, 24)`, `memcpy(firstBlock, header, 13)`) that are valid stack
  fixed-array writes v2 binds. The audit's 16 deterministic (comba `k*sizeof` only)
  was a subset undercount.
- The extra promotions are all runtime `required_evidence_absent` ops outside that
  filter; none touch heap or non-abstained records (invariant verified).

## What this establishes

The producer–consumer integration gap is closed for the reachable class: stack
fixed-array capacity present in the normalized facts but unconsumed is now bound at
the declaration node and compared. 566 operations move from
`additional_evidence_required` to reviewable relationship routes (498 semantic,
68 range/arithmetic), and 54 to `deterministic_complete` for the
destination-capacity property only. No unsupported promotion, no heap effect, and
frozen v1 remains the untouched baseline.

Out-of-reach classes (normalizer loss, local pointers, name collisions, genuine
multi-identity, heap) are unchanged and remain future work.
