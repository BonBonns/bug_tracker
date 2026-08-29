# Reconciliation: V1/V2 delegation correction, and the three regression numbers

## The design correction (this change)

`70805e2`'s form-aware diagnosis computed a real fits/exceeds comparison for a
CPG-resolved fixed-extent (array or scalar) destination, but labeled **both**
outcomes `capacity_relation_not_established` — internally contradictory: if the
comparison was computed soundly, the relationship *is* established; the reason
for not finalizing it is producer ownership (V1 has no capacity SOURCE for
non-heap objects), not missing evidence.

**Fixed**: V1 no longer computes the comparison at all. It emits a REROUTED
handoff (`delegated_to_stack_capacity_v2`, the same shape as the pre-existing
`free_dominates_sink` handoff — new reason registered in `analysis_record.py`,
`SCHEMA_VERSION` bumped 1→2) carrying the CPG-resolved structure (element type,
element count, offset, raw width expression). V2's stack-capacity integration
(`oob_runtime_capacity_v2.py`) is the sole adjudicator, reusing its own existing,
unit-aware `compare()` — the same function bare destinations already go through —
so there is exactly one arithmetic implementation, not two independently
maintained copies. Two safeguards from the design review are enforced by
construction, not by a new check bolted on:

- **element vs. byte units**: V1 passes `element_count` (a count) and
  `element_type` (a name), never a pre-multiplied byte value; `compare()`'s own
  `BYTE_TYPES` / `k_sizeof` logic is the only place a byte-vs-element or
  `sizeof(T)` relationship is decided. Proven by a control the ORIGINAL
  `70805e2` implementation could not have caught (it never delegated the
  arithmetic to `compare()` at all): `int obj; memcpy(&obj, src, 4)` does **NOT**
  resolve `deterministic_complete` — a literal byte count `4` against an `int`
  (non-byte-typed) element is correctly left `relationship_unresolved`, because
  equating it with `sizeof(int)` would be an assumed ABI fact, not a proven one.
- **`&scalar` capacity is `sizeof(type)`, not an assumed byte count**: modeled as
  `element_count=1, element_type=<scalar type>`, so `compare()`'s existing
  `k_sizeof` path naturally computes `1*sizeof(type)` when the width expression
  itself carries `sizeof(type)` — proven by the new `f_addr_scalar_sizeof`
  control (`memcpy(&obj, src, sizeof(int))` → `deterministic_complete`).

## Validation performed this change (all on `claude/emission-gap-delegation`,
worktree isolated from both `claude/emission-gap-fix` and the frozen
`claude/previous-conversation-context-6gr99h`)

| Check | Result |
|---|---|
| `dev_controls/emitgap/test.py` (rewritten: 16 V1-delegation-shape checks + 9 V2-adjudication checks + 2 shadow checks, including 2 new controls proving the scalar `sizeof` happy path and the byte-vs-element trap) | **27/27 PASS** |
| `cap_addr_indexed_test.py` (cap1 — imports the same `oob_runtime_capacity_v2.compare()`/`compute_stack_fixed_array_extents`, unaffected by the `_analyze_both` refactor) | **16/16 PASS** |
| `tests/gates/analysis-record-r01/gate_analysis_record_r01.py` | **53/53 PASS** |
| `gate_capability_2.py` | **CAP2_GATE=PASS** |
| `gate_capability_3.py` | **CAP3_GATE=PASS** |
| `gate_capability_4.py` | **CAP4_GATE=PASS** (includes its own re-checks of cap2/cap3/cap1/analysis-record-r01, all PASS) |

## Reconciling 19 / 13-of-20 / 45 (the changing regression denominator)

All three numbers come from **the same script**, `dev_controls/emitgap/regression.py`,
run at two different points in `claude/emission-gap-fix`'s own history — NOT from
three different corpora or inclusion rules:

- **"18/19" (stage 1, superseded)** — `70805e2`'s own commit message: *"Supersedes
  the earlier coarse 18/19 figure, which was measured before the labeled join was
  made precise."* This was the FIRST emission-gap fix (collapsing every non-bare
  destination into one `required_evidence_absent`/`member_or_expression` reason),
  measured before the labeled-site join (`raw_diagnosis.jsonl` ↔ the regression
  cache) was made precise. It is not comparable to the other two numbers and
  should not be cited going forward — `70805e2` itself already retired it.
- **"45 body-wide"** — `regression.py`'s `dropped_old`/`emitted_new`: every
  recognized memcpy-family sink, across all 276 cached function-packet CPGs,
  whose destination fails the bare-identifier regex (`re.fullmatch(BARE, dest)`).
  Inclusion rule: `CALLEE_CONTRACTS`-matched call + non-bare `dest` string, full
  stop — no vulnerability-label filter, no write-kind filter. This is the
  **denominator of the emission gap itself** (sites the OLD code silently
  dropped), not a labeled-recall figure.
- **"13/20 labeled group-A"** — `regression.py`'s `lab_vuln_nonbare`/
  `lab_vuln_emitted`: the SUBSET of the 45 (or rather, the subset of ALL 276
  packets' non-bare sites) that are also (a) the packet's own labeled vulnerable
  write, (b) `label_class == destination_write`, (c) `write_kind == copy_sink`.
  This is why it's smaller than 45 and why "the other 7" are explicitly *not*
  a soundness failure: `regression.py`'s own comment names them — unsupported
  sinks (`strcpy`/`strncpy`/`snprintf`, outside `CALLEE_CONTRACTS`) or a
  macro/text mismatch between the label and the CPG-visible call — separate,
  documented scope, not new unsupported-sink cases appearing inside a
  previously-clean group. Nothing in this change touches `CALLEE_CONTRACTS` or
  the labeled join, so this membership is unaffected by the delegation fix.

**What changes under this correction, and what provably doesn't:** the SET of
sites `nonbare_memcpy_sites()` finds, and thus both the 45 and the 13/20
denominators, is governed entirely by the bare-identifier regex + contract match
— untouched by this change. What changes is the **reason_code** those 45 (and 13)
records carry: previously `capacity_relation_not_established` for every
fixed-extent case (both fits and exceeds collapsed together); now
`delegated_to_stack_capacity_v2` for that same subset, with V2's adjudication
producing the actual fits/exceeds/still-unresolved breakdown on top. `REASON_OK`
in `regression.py` is updated to include the new code.

**Precise impact on the two live numbers, read from `DEV_EMISSION_GAP.md`'s own
already-archived breakdown** (not re-run, just re-read correctly): body-wide, the
45 sites break down as `required_evidence_absent` 30 + `destination_identity_ambiguous`
13 + `capacity_relation_not_established` **2**; the labeled 13/20 break down as
`required_evidence_absent` 10 + `destination_identity_ambiguous` **3 = 13, zero**
in the `capacity_relation_not_established` bucket. So this correction changes the
reason_code of **exactly 2 of the 45 body-wide sites**, and **0 of the current 13
labeled group-A sites** — it does not move the 45/45 or 13/20 counts themselves
(same predicate governs whether a site is emitted at all), and in THIS regression
snapshot it doesn't even change many individual reason labels. Its value is
correctness/honesty of the delegation shape (and unblocking V2 adjudication on
those 2, plus any FUTURE labeled site whose destination is a fixed extent), not a
recall change in the current 258-corpus snapshot.

## Schema-v2 validation caught two PRE-EXISTING bugs in frozen V2 (not introduced
by this change, never previously checked)

Adding `AR.validate_record()` against every emitted record (both V1's rerouted
handoff and V2's final output) -- something no prior gate or script did for
`oob_runtime_capacity_v2.py`'s output -- immediately caught two real schema
violations, both present in the ORIGINAL frozen `_analyze_both()` logic
untouched by this branch until now:

1. **`write_exceeds_stack_capacity` was never registered in `REASON_DEFINITIONS`
   at all.** V2 has emitted this reason code since its introduction; nothing
   ever validated it against the schema module. Fixed by registering it
   (`bucket=relationship_unresolved`, `route=range_arithmetic_review`,
   `llm_eligible=False` -- matching exactly what the emitting code already
   assumed) and adding it to `PRECEDENCE`.
2. **`recommended_route` could diverge from the reason code's own registered
   route.** `compare()`'s literal-byte-count-vs-non-byte-element sub-case
   returns `route="range_arithmetic_review"`, but V2 always finalizes it under
   `reason_code="capacity_relation_not_established"`, whose registered route is
   `"semantic_relationship_review"` -- verbatim-copying `compare()`'s route into
   the output produced a record where `recommended_route` didn't match
   `route_for_reason(reason_code)`, exactly what `validate_record()` exists to
   catch. Fixed by deriving `recommended_route`/`llm_eligible`/`uncertainty_bucket`
   from `analysis_record`'s registered functions (the schema's own source of
   truth) rather than from `compare()`'s raw return value; `compare()`'s own
   note/route is still preserved in `_v2_evidence` for diagnostic purposes.

Also added: `v1_provenance` is now explicit and unconditional on every
V2-adjudicated delegated record (previously only implicit via `_v2_evidence`'s
established facts) -- matching the canonical-record/preserved-provenance shape
`heldout_correction_run.py` already established for the bare-destination case.
And `compare_v1_v2_stack.py`'s own invariants (a: "only stack evidence
justifies a change", c: "only V1 abstained+required_evidence_absent moves")
were extended to recognize the new delegated path
(`stack_or_scalar_object` provenance; V1 rerouted+delegated_to_stack_capacity_v2)
as an equally legitimate mover -- without this fix, that script would have
raised FALSE invariant violations against every correctly-delegated record
(verified: reverted the fix locally, re-ran against controls.c, confirmed it
produces exactly the false positives predicted -- then re-applied the fix and
confirmed clean).

Full re-validation after these fixes: `test.py` 28/28 (now including the schema
check), `cap_addr_indexed_test.py` 16/16, `ANALYSIS_RECORD_R01` 53/53,
`CAP2_GATE`/`CAP3_GATE`/`CAP4_GATE` all PASS, `compare_v1_v2_stack.py` against
`controls.c` directly: 18 total V1 operations, 11 changed, 0 unjustified, 0
unsupported, 0 heap/other touched.

**Not run this change**: the actual 276-packet cache (`study/heldout_diagnosis/cache/`)
is gitignored and was not present in this worktree — regenerating it requires
re-running the SecVulEval body-reconstruction + CPG-build pipeline for 276 sites,
a substantial separate operation. The 27 synthetic controls above exercise every
DISTINCT code path `regression.py` would touch (member-fixed symbolic width,
scalar `&obj` with both a byte-literal and a `sizeof()` width, array+literal-offset
with symbolic width, array+symbolic-offset, array literal-fits, array
literal-exceeds, and ref-target-resolved shadowed declarations) — high confidence
the site SET reproduces at 45/45 and 13/20 unchanged, but this is not a substitute
for actually re-running `regression.py` against a real cache before treating those
exact numbers as re-confirmed under this change. Offering to regenerate the cache
and re-run it if that confirmation is wanted before merge.
