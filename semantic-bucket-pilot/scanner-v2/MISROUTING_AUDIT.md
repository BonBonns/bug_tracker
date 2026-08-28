# Misrouting audit — the largest group is misclassified, not missing evidence

The review's hypothesis holds. Of the local-destination operations that v1
labelled `required_evidence_absent`, **most have their capacity AND write length
established locally; only the RELATIONSHIP is unproven.** `required_evidence_absent`
is the wrong reason for them — they are `relationship_unresolved` (or, for a
subset, provably safe). This materially deflates the earlier "91% need
additional evidence" figure.

## The four-group split (738 distinct local destinations, from the 938 local ops)

| group | meaning | count |
|-------|---------|-------|
| **G3 range/arithmetic required** | capacity + width both bound, a symbolic operand blocks the comparison | **528** |
| G1 identity/evidence missing | capacity not bound to the destination (pointer, no local array) | 194 |
| **G4 relationship unresolved** | capacity + width both bound and evaluable, relationship not proven (some provably safe) | **16** |
| G2 write not bound | — | 0 |

**Capacity is available locally for 544 / 738 (73.7%).** G3 + G4 = **544
operations are MISROUTED**: their reason should be `relationship_unresolved`
(route: range/arithmetic or focused relationship review), not
`required_evidence_absent` (route: additional evidence).

## Verified against source

- **G4, provably safe:** `s_mp_mul_comba_4` — `mp_digit at[8]; memcpy(at, A->dp,
  4 * sizeof(mp_digit))`. Capacity 8 elements, write 4 elements; the `sizeof`
  cancels (4 ≤ 8) with no ABI knowledge. Provably in-bounds, yet v1 said
  `required_evidence_absent`. (The very next line, `memcpy(at + 4, …, 4*sizeof)`,
  shows why the **offset** must be accounted for: 4 + 4 = 8 ≤ 8.)
- **G3, relationship unresolved:** `chacha20_encrypt_last` — `uint8_t plain[64U]`
  written `len * sizeof(uint8_t)`; `poly1305_padded_32` — `uint8_t tmp[16U]`
  written `r * sizeof(...)`. Capacity established (64 / 16); write length
  established but the runtime count (`len`, `r`) is symbolic, so `count ≤ N`
  needs range/guard evidence — a *relationship*, not a missing fact.
- **G1, genuinely missing:** `lg_EvaluateConfigDir:cdir`, `s_mpv_mul_d:px` — the
  destination is a pointer with no local array capacity; `required_evidence_absent`
  is correct there.

## Why this is central to the thesis

TChecker currently cannot tell **"I lack information"** from **"I have the
information but cannot establish the relationship."** It collapses both into
`required_evidence_absent`. Correcting the causal bucket:

- moves 544 local operations from `additional_evidence_required` to
  `relationship_unresolved` (range/arithmetic or focused review) — the routes the
  bucket method is actually about;
- reveals a provable subset (G4-style, offset-0, literal `N_write ≤ N_array`)
  that should be `deterministic_complete`;
- and therefore **lowers the "91% additional-evidence" headline substantially**:
  a large share of that majority is reviewable-relationship or provable, not
  evidence-starved.

This is a stronger v2 improvement than single-object copies or new vulnerability
detection: it fixes a *classification* error in the scanner's own reasoning about
its own evidence.

## Corrected next step (still no scanner fix)

Capability #1 should be reconsidered as **causal-bucket correction**, not
single-object copying:

1. **Reroute** — when the destination is a local object/array whose capacity is
   established AND the write length is established, but the relationship (write ≤
   capacity) is not proven, emit `relationship_unresolved` (route to
   range/arithmetic or relationship review), NOT `required_evidence_absent`.
   Reach here: ~544 local operations.
2. **Resolve the provable subset** — promote to `deterministic_complete` ONLY
   when the full sound chain holds: exact destination identity, actual
   array/object capacity `N`, correct write length, **no destination offset**
   (or an accounted one), no invalidating lifetime event, and a proven
   `write ≤ capacity` via the **compiler-defined `sizeof` relationship**
   (`k·sizeof(T) ≤ N·sizeof(T)` ⇒ `k ≤ N`, never guessing ABI type sizes).

G1 (194) stays `required_evidence_absent` (genuinely no local capacity) — many
of those are the pointer-parameter / caller-scope cases from the caller
inspection.

Before implementing, the remaining validation is: confirm per-operation that the
producer truly has the array-capacity fact bound to the destination (so the
reroute is a classification fix, not a new inference), and measure the exact
provable subset after applying the offset and identity requirements. No fix is
applied in this step.
