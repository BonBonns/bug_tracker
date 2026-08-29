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

| CPG-resolved form | `analysis_status` | `reason_code` | bucket |
|---|---|---|---|
| base ref unresolved / ambiguous; side-effecting (`p++`); unsupported expr | abstained | `destination_identity_ambiguous` | identity_ambiguous |
| identity known, pointer object / pointer member / cast-of-pointer / unknown member/object extent | abstained | `required_evidence_absent` | insufficient_evidence |
| fixed extent, symbolic offset or symbolic width | abstained | `capacity_relation_not_established` | relationship_unresolved |
| fixed extent, literal offset + literal width, **fits** | abstained | `capacity_relation_not_established` | relationship_unresolved |
| fixed extent, literal offset + literal width, **exceeds** | open_candidate | `capacity_relation_not_established` | relationship_unresolved |

For a fixed-extent object with literal offset and width, the remaining-capacity comparison is
**computed and attached** (`capacity_comparison = {destination_fixed_extent_bytes, byte_offset,
write_width_bytes, remaining_capacity_bytes, write_fits}`), and `established_facts` carries it.

### Scope / soundness boundary (deliberate)

This is the **V1 heap-capacity producer**. Its capacity SOURCE is heap allocation extents; it has
none for stack/scalar/member objects (that is the V2 stack-capacity integration's domain). So the
form-aware layer **never finalizes a non-heap destination as safe**:

- a fixed-extent write that provably **fits** is **under-claimed** (abstained, *not*
  `deterministic_complete`) — the safe direction — with the comparison attached so the
  stack-capacity owner / adjudicator can finalize;
- a fixed-extent write that provably **exceeds** is surfaced as an **`open_candidate`** (a
  candidate for review, never a hard vulnerable verdict — "flag, never assume safe"), with the
  comparison attached.

The comparison itself is pure literal arithmetic over a CPG-resolved compile-time size — the same
class of sound reasoning as the pre-existing `int(len) <= N` literal check in `emit_candidates`. No
new stack/scalar capacity source is added to V1's candidate/guard logic; the arithmetic lives only
in this abstention-diagnosis layer.

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
