# Capability #1 review — single-object copy is NOT yet justified

Three corrections applied to the audit before selecting any capability. Result:
the provisional single-object implementation is **not sound as written and must
not be promoted**. Single-object copies remain a promising recoverable class,
but backing-object validation and caller inspection are still required.

## 1. Exact counts (were impossible before)

The earlier "≈88 operations spanning ≈126 functions" mixed a subset (88) with the
full candidate set's function count (126). Exact, deduplicated by the canonical
operation fingerprint, single-object candidate set (v1 abstained
`required_evidence_absent`, width = one `sizeof` with no multiplier):

| metric | count |
|--------|-------|
| distinct operations | **348** |
| distinct function names | 87 |
| distinct (family, function) | 126 |
| distinct source files | 35 |
| case families | 146 |

## 2. Caller inspection — "absent from source" was wrong

For pointer-parameter destinations the capacity usually lives in the caller. The
964 `N*sizeof` array writes and 350 `destination_identity_ambiguous` pointer
destinations, split by inspecting callers in the scanned scope:

| class | array (964) | identity (350) |
|-------|-------------|----------------|
| dest is a **local** (not a parameter) — capacity is local | 746 (77%) | 192 (55%) |
| caller_outside_scope (API entry / external caller) | 144 (15%) | 104 (30%) |
| caller_propagates_param (capacity one frame up) | 28 | 28 |
| **capacity_visible_in_caller (recoverable interprocedural)** | **24** | 0 |
| genuinely_unavailable | 20 | 26 |
| conflicting_capacities | 2 | 0 |

Findings that change the diagnosis:
- **Interprocedural propagation is a real but MODEST recoverable slice** (24
  array ops where a caller passes a local array/alloc of visible capacity). It is
  **not** the largest recoverable gap.
- The largest slice is **local destinations** (746 array + 192 identity): the
  buffer is local, so the capacity is in the function, but the **count-vs-capacity
  relationship** (write count ≤ local array size) is unproven. That is a
  *local* evidence gap, larger than the interprocedural one.
- A genuine external slice remains (caller_outside_scope, 144 + 104): PKCS#11 API
  entry points whose buffer is the application's — correct abstention.

So neither "absent from source" nor "interprocedural propagation is the biggest
gap" holds. The biggest recoverable gap is the **local count-vs-capacity
relationship**, followed by a modest interprocedural slice and a genuine
external remainder.

## 3. `sizeof(*dest)` does not prove capacity — backing validation

`sizeof(*dest)` / `sizeof(T)` proves the intended **write length**, not that
`dest` is backed by storage that large. Backing class of the 348 candidates:

| backing class | ops | locally established? |
|---------------|-----|----------------------|
| `stack_object` (local `T buf[N]` / object) | 190 | backing exists (capacity `N`) — but write ≤ N **not yet checked** |
| `pointer_parameter` (backing is the caller's) | 136 | **no** — interprocedural |
| `unresolved_pointer` | 22 | **no** |

- **158 of 348 (45%) have no local backing** (pointer parameter or unresolved).
- The provisional `single_object_pass` promoted several of these on `T*`+`sizeof`
  alone — e.g. `DestroyCertificate:cert`, `nsslowcert_DestroyTrust:trust`,
  `sftk_InitGeneric:keyTypePtr`, `NSC_GetMechanismInfo:pInfo`, all
  `pointer_parameter`. Those promotions are **unsound**: they assume the caller
  passed a fully-backed object, which is exactly the assumption forbidden.
- Even the 190 `stack_object` cases are **not** fully validated: a write of
  `sizeof(T)` into `unsigned char buf[64]` is safe only if `sizeof(T) ≤ 64`, and
  many are `sizeof(<struct>)` whose size is not resolvable from the facts (the
  struct is external). So "backing exists" ≠ "write ≤ capacity".

A sound single-object promotion requires the FULL chain — concrete pointee type,
destination identity, a real backing object, that object's capacity, no offset /
lifetime invalidation, and write length ≤ capacity. The prototype established
only the first (write length). `transition_audit.json` records, per candidate:
`v1_reason`, `new_evidence`, `evidence_provenance`, backing class, `proposed_v2`,
and `sound` — showing 158 that must NOT move and 190 that need the residual
write-≤-capacity check.

## Corrected conclusion

The audit identified single-object copies as a promising recoverable evidence
class, but **caller inspection and backing-object validation are still required
before selecting it as v2's first capability**, and the current classification
was hiding a larger local count-vs-capacity gap. Specifically:

- Do **not** promote `single_object_pass` — it is unsound for the 158
  no-local-backing cases and unvalidated for the rest.
- The soundly-recoverable single-object subset is at most the `stack_object`
  cases (190) AND only those where `sizeof(T) ≤ N` can be established — a smaller,
  yet-to-be-counted number requiring struct-size resolution.
- The **local count-vs-capacity relationship** (local-array destinations, ~938
  ops across the two reason groups) is a larger recoverable gap and a candidate
  for the first capability in its own right.
- Interprocedural capacity propagation is real but modest (~24 ops) here.

No scanner fix is selected yet. Next step: quantify the fully-sound stack-object
subset (with `sizeof(T) ≤ N` established) and the local count-vs-capacity subset,
and compare their sound, generalizable reach before choosing capability #1.
