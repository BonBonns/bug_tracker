# DEV: emission-gap fix — form-aware abstention for recognized memcpy with a non-bare destination

**Development branch `claude/emission-gap-fix`.** Scanner development motivated by the held-out
misses. Per the discipline, any recognition improvement measured on the consumed 258-site corpus is
a DEVELOPMENT result; a NEW, unseen held-out corpus is required for any confirmatory generalization
claim. The 258 corpus (its cached CPGs) is used here only as REGRESSION evidence.

## The gap (root cause)

`oob_runtime_capacity_verdict.analyze_operations` recognized a memcpy-family sink but then
**dropped the operation** when the destination was not a bare pointer identifier
(`if not re.fullmatch(r'[A-Za-z_]\w*', dest): continue` — "bare pointer destination only, MVP").
The recognized operation never reached the router.

## Two-stage fix

**Stage 1 (superseded).** Emit an explicit abstention instead of dropping. But its single reason
(`required_evidence_absent` + `destination_form=member_or_expression`) was **too coarse**: a
non-bare *text* form does not prove destination capacity is absent, and it conflated three
different causes.

**Stage 2 (this branch) — FORM-AWARE.** The reason is chosen from the **CPG-resolved form** of the
destination, driven by Joern reference-target / declaration resolution — never by the destination
text matching a non-bare regex. "Identifiable" means the base identifier's `ref_target_ids`
resolves to exactly ONE declaration; a fixed extent means that declaration's type is a
compile-time-sized array or a modeled scalar. The split:

> **CORRECTED** (see `RECONCILIATION.md`): the table below is the ORIGINAL,
> internally-contradictory design — a real fits/exceeds comparison, computed for
> the "fixed extent, literal offset+width" row, was labeled
> `capacity_relation_not_established` regardless of the outcome, conflating
> "the relationship IS established, V1 just doesn't finalize it" with "the
> relationship genuinely could not be determined." Struck through, not silently
> edited. The CURRENT design: V1 never computes this comparison at all for a
> fixed extent (any offset/width, literal or symbolic) — it emits a REROUTED
> handoff, `delegated_to_stack_capacity_v2`, and V2's stack-capacity integration
> is the sole adjudicator, reusing the exact `compare()` bare destinations
> already go through.

| CPG-resolved form | `analysis_status` | `reason_code` | bucket |
|---|---|---|---|
| base ref unresolved / ambiguous; side-effecting (`p++`); unsupported expr | abstained | `destination_identity_ambiguous` | identity_ambiguous |
| identity known, pointer object / pointer member / cast-of-pointer / unknown member/object extent | abstained | `required_evidence_absent` | insufficient_evidence |
| ~~fixed extent, symbolic offset or symbolic width~~ **fixed extent, ANY offset/width** | ~~abstained~~ **rerouted** | ~~`capacity_relation_not_established`~~ **`delegated_to_stack_capacity_v2`** | ~~relationship_unresolved~~ **(none: rerouted, see V2)** |
| ~~fixed extent, literal offset + literal width, **fits**~~ | ~~abstained~~ | ~~`capacity_relation_not_established`~~ | ~~relationship_unresolved~~ |
| ~~fixed extent, literal offset + literal width, **exceeds**~~ | ~~open_candidate~~ | ~~`capacity_relation_not_established`~~ | ~~relationship_unresolved~~ |

V1 now attaches `established_facts = [{element_type, element_count, offset_elements,
width_expr}]` (the CPG-resolved structure) instead of a computed comparison. See
`oob_runtime_capacity_v2.py`'s `_adjudicate_delegated()` for what V2 does with it —
`fits → deterministic_complete`, `exceeds → open_candidate/write_exceeds_stack_capacity`,
symbolic offset or width (or a unit relationship `compare()` won't assume, e.g. a
raw byte literal against a non-byte-typed element) `→ open_candidate/capacity_relation_not_established`.

### Scope / soundness boundary (deliberate, now enforced by construction)

This is the **V1 heap-capacity producer**. Its capacity SOURCE is heap allocation extents; it has
none for stack/scalar/member objects (that is the V2 stack-capacity integration's domain). The
form-aware layer **never computes or finalizes** a non-heap destination's capacity relation at all
— not "under-claims" it, doesn't touch it: the arithmetic (element-vs-byte units, `sizeof(T)`
relationships) lives in exactly ONE place, `oob_runtime_capacity_v2.compare()`, used identically
for bare and non-bare destinations. `delegated_to_stack_capacity_v2` is not a candidate-review
bucket (`bucket=None`, `llm_eligible=False`) — the next step is deterministic arithmetic, not a
semantic judgment call, the same posture `free_dominates_sink`'s handoff already established for
the lifetime layer.

## Validation

- **Synthetic controls** (`controls.c` + `test.py`, **16/16 PASS**, single-file scan so there is no
  cross-file CPG id collision). Each control names the exact CPG resolution required, not a text
  pattern:
  - `&local_scalar` (`&obj`, int) → within-bounds comparison (4 ≤ 4);
  - fixed-array member (`s->buf` char[16]) vs pointer member (`s->pbuf` char\*) →
    `capacity_relation_not_established` vs `required_evidence_absent`;
  - known array + literal offset (`a+4`) and + symbolic offset (`a+i`) → relationship-unresolved
    with/without a resolvable offset;
  - known array + literal offset + literal width, fits (`a+4`,8 into char[64]) vs exceeds (`a+8`,32
    into char[16]) → abstained vs `open_candidate`, both with the computed comparison;
  - cast/alias (`(char*)dst`) → unwrapped to the pointer object → `required_evidence_absent`;
  - side-effecting (`p++`) → `destination_identity_ambiguous`;
  - **shadowed same-name bases** (`f_shadow`): an inner-block `a` (char[8]) shadows an outer `a`
    (char[64]); ref-target resolution binds each `memcpy` to the declaration in scope — resolved
    extents `[8, 64]`. A name / nearest-declaration heuristic would collapse them.
- **Frozen suite unchanged**: `ANALYSIS_RECORD_R01 = 53/53`; `CAP2_GATE = PASS` ("frozen outputs
  unchanged outside cap2's domain"). The change touches only the non-bare branch of
  `analyze_operations` plus new helpers; no existing bare-identifier record changed.
- **Regression on the consumed corpus (development evidence only)** — replay over the 276 cached
  function-packet CPGs (`regression.py`):
  - **Body-wide:** 45 non-bare recognized memcpy destinations (old behaviour: **silently
    dropped**) → **45/45 now emit** a visible record; **0** still dropped; **0** safe promotions.
    Reasons: required_evidence_absent 30, destination_identity_ambiguous 13,
    capacity_relation_not_established 2. Forms: member_extent_unknown 15 (struct definition absent
    from the reconstructed packet), object_extent_unknown 11, unsupported_expression 8,
    unresolved_member_base 5, pointer_object 4, fixed_array_object_write_within_bounds 2.
  - **Labeled group-A subset** (labeled vulnerable, `copy_sink`, non-bare dest): 20 sites → **13
    now emit at the labeled destination** (required_evidence_absent 10,
    destination_identity_ambiguous 3). The other 7 fall to unsupported sinks (`strcpy`/`strncpy`/
    `snprintf` etc., outside `CALLEE_CONTRACTS`) or macro/text mismatch — separate scope (below).
    This supersedes the earlier coarse "18/19" figure, which was measured before the labeled join
    was made precise.

The branch now demonstrates not only that the silent drops became visible abstentions, but that
their **causal reasons are correct per CPG-resolved form**, with no unsound safe promotion.

## Not done here (scope)

- The 28 unsupported-sink cases (`memset`/`snprintf`/`sprintf`/`strcpy`/`strncpy`) still need sink
  contracts; the 89 unsupported-form (general index/deref) cases need new models; the 69
  parse-collapse cases need better function-packet parsing or full-repository builds. Separate
  development items.
- No confirmatory recognition number is claimed. Establishing that the fix improves generalization
  requires a fresh held-out corpus.
