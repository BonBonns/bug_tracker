# Design note: unsigned-underflow-fed length/offset capability

**Status: BUILT and validated** — `cap_underflow_length.py` /
`cap_underflow_length_test.py` / `cap_controls/underflow/`, results in
`UNDERFLOW_CAPABILITY_RESULTS.md` (11/11 synthetic checks pass; real-world run against
mozilla/nss `lib/freebl` found the exact motivating `hmacct.c::MAC` site plus 26 more
candidates). This is the "biggest build" item from the improvement notes —
best-corroborated (3 independent hits: 2 old-TChecker-corpus CVEs + this session's
`hmacct.c` write-2). The design below is unchanged from when it was written (before
implementation); the scoped-first-cut shape it describes is exactly what got built —
see the results doc for what shipped vs. what stayed explicitly out of scope
(pointer-arithmetic offsets).

## The gap

No current capability (cap1-4, base v1/v2) asks "can this subtraction go negative before
it's used" — all of them ask "is the write length ≤ destination capacity." A derived
quantity computed as `A - B` (both unsigned, or of unknown signedness) that feeds a
`memcpy`-length, array index, or pointer-arithmetic offset underflows to a huge value if
`A < B` at runtime. `hmacct.c`'s `overhang = headerLen - mdBlockSize` (this session's
manual audit) is real, live NSS code with exactly this shape, safe today only because its
one caller happens to keep `A >= B` — nothing locally enforces it. The old TChecker
corpus hit the same root cause twice (`CVE-2016-1950`'s `item->len += len` accumulation,
bug 1418780's `ino[0] - (moved + 2)`), filed as "integer-underflow-in-an-index/length-
expression" and explicitly flagged as not yet built.

## What already exists and is directly reusable

`call_context_guard.py` (used today by the base V1 producer for a different purpose —
crediting a CALLER-side guard on a callee's capacity check) already has real, tested
CFG-dominance machinery that solves the hard part of this capability:

- `_controls_call(g, cmp_node, call_id)` — proves a comparison genuinely gates whether a
  call executes (not just dominates it; at least one CFG successor must NOT reach the
  call).
- `_branch_polarity(g, cmp_node, call_id)` — proves, from CFG structure alone (never
  source-line order), whether reaching the call proves the comparison's NEGATION —
  the `if (P) { return ERR; } target();` shape.
- `_split_predicate` / `_entails_safe_bare` — exact two-bare-operand comparison
  matching, deliberately refusing to reason about compound adjustments
  (`cap - X <= cap` needs proving `X >= 0`, explicitly rejected as an unproven-arithmetic
  assumption).

This is precisely the shape needed for "does a guard `A >= B` (or equivalent polarity)
dominate the use of `A - B`" — the SAME dominance/polarity proof, just applied to a new
operand pair (the subtraction's own operands) instead of (write-length, capacity).

## Proposed shape (mirrors the existing producer family's posture exactly)

1. **Recognize**: `<operator>.subtraction` calls whose `code` is a syntactically simple
   `A - B` (two bare identifiers or `x->field`/`x.field` chains — no nested calls, no
   further arithmetic on either side; same "abstain on anything complex" discipline as
   the rest of this family). Only when the RESULT feeds one of:
   - a copy-family sink's length argument (`CALLEE_CONTRACTS`, reused verbatim),
   - an array index expression,
   - a pointer-arithmetic offset (`ptr + (A - B)` / `ptr[A - B]`).
2. **Search for a guard**: any comparison in the SAME function relating the SAME two
   operands (`A` and `B`, exact bare-text match — no compound adjustment credited,
   matching `_entails_safe_bare`'s existing discipline) that PROVABLY dominates the
   subtraction's use, via `_controls_call`/`_branch_polarity` (retargeted from "call" to
   "the CPG node consuming the subtraction's result").
3. **Route**:
   - guard found, proven to entail `A >= B` on every path reaching the use →
     `deterministic_complete` for the property `subtraction_does_not_underflow` ONLY —
     explicitly NOT a claim the write itself is safe (the destination-capacity property
     is separate and orthogonal; this producer establishes underflow-safety, not
     length-vs-capacity).
   - no guard, or guard shape not provably matching (compound adjustment, ambiguous
     polarity, comparison doesn't dominate) → `open_candidate`, new reason
     `subtraction_may_underflow`, route `range_arithmetic_review`, `llm_eligible=True` —
     flag, never assume unsafe either (signedness may make this benign in some
     contexts; a human/LLM reviewer's job, same posture as every other open-relationship
     route in this family).
4. **Signedness**: fire regardless of resolved signedness by default (an unsigned type is
   the catastrophic case; a signed type still produces a negative index/length, itself
   dangerous when the same value later gets implicitly converted to a size_t/unsigned
   parameter — exactly what happened in `AESKeyWrap_EncryptKWP`-adjacent NSS code
   elsewhere in this exploratory scan). Attach resolved signedness (reuse
   `call_context_guard._signedness`) as evidence, not as a filter — never silently
   drop a candidate because it "looked signed."

## What this explicitly does NOT attempt (scoped out up front, same discipline as
`oob_interprocedural_verdict.py`'s own explicit non-goals)

- Multi-hop guards (a guard in a CALLER protecting a callee's subtraction) — this is a
  same-function-only pass, matching capability 3 and the base producer's own boundary.
- Accumulated underflow across loop iterations (`CVE-2016-1950`'s actual shape,
  `item->len += len` across a decode loop) — a real refinement on top of this capability,
  not a prerequisite; flagged in the old TChecker corpus writeup as "a smaller
  incremental step than building offset-tracking from nothing" once this base capability
  exists.
- Proving `A >= B` via anything beyond an exact bare two-operand comparison — a compound
  guard (`if (A - CONST >= B)`) is left `open_candidate`, never credited, matching
  `_entails_safe_bare`'s existing refusal to assume adjustment safety.

## Validation plan (not run)

Synthetic controls mirroring `hmacct.c`'s real shape directly (a same-function
`overhang = headerLen - mdBlockSize` with (a) no guard, (b) a real dominating
`if (headerLen < mdBlockSize) return;` guard, (c) a guard on the wrong operand pair, (d) a
compound-adjustment guard) plus a regression proving zero existing route/disposition
changes anywhere else in the frozen suite (same `ANALYSIS_RECORD_R01`/CAP2/CAP3/CAP4
gate re-run pattern used for every change this session). Given the corroboration count,
worth also re-running this producer directly against `hmacct.c`'s real source once built,
as a real-world positive control before considering it complete.
