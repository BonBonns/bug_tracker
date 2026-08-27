# Semantic-Evidence Bucket Pilot

Tests the thesis's **typed semantic-bucket** approach against literature-derived
semantic-review baselines: does preserving *why* deterministic analysis stalled,
classifying that uncertainty into a causal bucket, and routing a narrow semantic
question to the reviewer, produce better judgments than a general review or a
generic "unresolved" warning?

## SUPERSEDED earlier design (do not use as methodology)

An earlier instruction in this project framed a **2-condition information ladder**
— `raw` code vs `structured` evidence — to test "does giving the LLM more scanner
information help?" **That design is obsolete and must not be mistaken for the
final methodology.** It did not isolate the bucket contribution (it confounded
*more information* with *typed, routed uncertainty*, and let the structured
condition win merely by carrying more text or a different candidate). The
`raw`/`structured` prompts and any outputs produced under them are excluded; see
`excluded_pre_freeze/`.

## The experiment (corrected)

The experimental boundary is **after detection, before LLM review**. All
conditions share the same scanner, the same real candidate, the same code, the
same highlighted operation, the same model, and the same answer format. Only the
representation of the scanner's uncertainty changes:

| Condition | Content | Role |
|---|---|---|
| **A** | code + highlighted operation | general-review baseline |
| **B** | A + established facts + generic "unresolved" status | structured-but-unbucketed baseline |
| **C** | B + typed uncertainty category + focused question | TChecker bucket-guided review |

`A ⊂ B ⊂ C`. **The load-bearing comparison is B vs C** — same facts, the only
difference being the typed bucket and the focused question. C is generated as
literally B plus a category line and a focused-question line (enforced in
`generate_prompts.py`), so the B/C established-facts field is byte-for-byte
identical and any C effect is attributable to the bucketing, not to extra facts.
Because C is longer than B, token counts are recorded; the real experiment will
add a token-matched B variant (same facts restated in untyped prose) rather than
arbitrary padding.

Baselines A and B are **literature-derived conditions**, not reproductions of
GPTScan / IRIS / LLMxCPG / RepoAudit / ZeroFalse. The defensible claim is that
TChecker's bucketed interface beats general and unbucketed baselines on this
corpus — never that it out-runs those systems as deployed.

## The two SEPARATE thesis evaluations

1. **A/B/C accuracy** (`prompts/`, `rubric/scoring.py`): for cases the scanner
   genuinely flags AND routes to the LLM, does bucket-guided review improve the
   answer? Scored against `verified_ground_truth`.
2. **Routing evaluation** (`routing_eval.json`): for every case, did the bucket
   lead to the appropriate ACTION (route to LLM / repair analyzer-or-frontend /
   require more evidence / abstain / deterministic-complete)? Costs no model
   calls. This is where non-routable buckets belong — `producer_evidence_missing`
   must NOT enter the A/B/C accuracy comparison, because the architecture says
   those cases should not reach the LLM at all.

The scanner-detection evaluation (old scanner vs expanded scanner: how many known
cases detected) is a THIRD, separate evaluation and is not mixed into either of
the above.

## Hard rule: no manufactured candidates

A/B/C requires a **real** frozen-scanner candidate: `real candidate → bucket →
review`. Cases the frozen scanner did not actually flag are NOT recast as
hypothetical candidates to balance the experiment. Doing so would test a scanner
output invented for the experiment. Such cases go to the routing/detection
evaluation instead.

## Scanner state vs verified ground truth are separate fields

`scanner_state.assigned_uncertainty_category` (what the scanner concluded, e.g.
`relationship_unresolved`) and `verified_ground_truth.conclusion` (the
independently established final answer, e.g. `safe`) are distinct. SB-07 is a
prime A/B/C case precisely because they differ: scanner = relationship
unresolved, verified = safe.

## Current corpus roles (8 cases)

| Case | Scanner candidate? | Role | Bucket / gap | Verified answer |
|---|---|---|---|---|
| SB-01 | yes | A/B/C mechanics dry run | relationship_unresolved | unresolved (insufficient at snippet level) |
| SB-02 | yes | A/B/C mechanics dry run | relationship_unresolved | unresolved (insufficient) |
| SB-07 | yes | A/B/C mechanics dry run | relationship_unresolved | safe |
| SB-03 | no | routing eval only | producer_evidence_missing | (vulnerable; not routed) |
| SB-04 | no | routing eval only | producer_evidence_missing | (vulnerable; not routed) |
| SB-05 | no | detection/capability eval | analysis_capability_missing | vulnerable |
| SB-06 | no | detection/capability eval | analysis_capability_missing | vulnerable |
| SB-08 | no | detection/capability eval | analysis_capability_missing | vulnerable |

**The three A/B/C cases are a PROMPT-MECHANICS dry run only** — they validate
prompt clarity and rubric usability. No A/B/C accuracy claim may be made from
them (only 3 cases, and all verified-unresolved-or-safe, no vulnerable control
with a live candidate).

## Fresh cases required before any A/B/C accuracy claim

The real pilot needs **≥9 genuine routable candidates** the frozen scanner
actually emits and assigns to an LLM-routable bucket, balanced by verified
eventual answer:

- 3 ground-truth **safe** (candidate enters unresolved, reviewer proves safe)
- 3 ground-truth **vulnerable** (candidate enters unresolved, reviewer proves vulnerable)
- 3 legitimately **unresolved** (evidence genuinely insufficient)

Frozen inclusion criteria (a case qualifies iff ALL hold), applied BEFORE any
model call and never because a preliminary answer looked good:
1. the frozen scanner emits a real candidate at a specific highlighted operation;
2. its uncertainty is an LLM-routable bucket (relationship_unresolved or
   semantic_contract_unknown);
3. `verified_ground_truth` is independently established (real patch diff / CVE
   record / fully traced source);
4. the established facts can be stated without revealing the answer.
Prefer multiple functions and multiple repositories / representation shapes.

## Model-call status

- Ground-truth + prompt infrastructure: **reusable**.
- 2-condition prompts: **obsolete** (removed).
- Existing raw/structured outputs: **preliminary only**, quarantined in
  `excluded_pre_freeze/`.
- Condition B: **built**.
- Routing experiment: **separated** (`routing_eval.json`).
- Final controlled A/B/C model calls: **not yet run**.

The `Agent`-tool calls used in this project approximate an isolated call (fresh
subagent, no inherited conversation, instructed to use no tools) but are
acceptable only for **debugging prompt clarity**, not as final thesis
observations. The final experiment requires actual isolated model calls with a
fixed model+version, no inherited context, no tools, frozen prompts, randomized
condition order, and archived raw outputs (prompt text + SHA-256 hash +
timestamp + model version), which `runs/` already records.

## Quarantine policy (research integrity)

Outputs produced under a superseded prompt, or any non-frozen condition, are
**quarantined in `excluded_pre_freeze/` and excluded via its manifest — never
silently discarded.** The manifest records each excluded run's count, old prompt
hash (where preserved), exclusion reason, whether it was viewed before
exclusion, and that it was never scored. Future invalid runs must be MOVED there
at the moment of invalidation.

## Two bucket families (must not be mixed)

The taxonomy (`tools/analysis_record.py`) separates:

- **Candidate-review buckets** — assigned when TChecker RECOGNIZED an operation
  and produced an analysis record (open candidate or recognized-but-abstained):
  `relationship_unresolved`, `external_contract_unknown`, `identity_ambiguous`,
  `conflicting_definitions`, `insufficient_evidence`. These are scan-time
  derivable from the producer's own reason code and decide whether/how a case
  reaches the LLM. **These are the A/B/C-relevant buckets.**
- **Coverage-gap categories** — assigned when a KNOWN-POSITIVE case produced no
  candidate: `operation_not_recognized`, `frontend_fact_missing`,
  `unsupported_representation`, `propagation_not_modeled`,
  `required_fact_not_produced`. TChecker generally cannot self-assign these
  during a scan (it may not know it missed anything; telling "the fact doesn't
  exist" from "the frontend failed to export it" needs an external
  known-positive oracle). **These belong to the scanner-coverage evaluation,
  never the A/B/C evaluation.**

## Reason-emission layer (buckets from causes, not from candidate presence)

The earlier router assigned `relationship_unresolved` to any open candidate —
tautological, and unable to distinguish causes. Producers now emit an explicit
machine-derived **reason code** per recognized operation, and the router
TRANSLATES reason → bucket (`analysis_record.REASON_TO_BUCKET`); it does not
infer a bucket from candidate presence/absence.

### Frozen decision table (`analysis_record.py`)

| reason_code | exact condition | bucket | route |
|---|---|---|---|
| `capacity_relation_not_established` | capacity & width known; width≤capacity unproven | relationship_unresolved | llm_semantic_review |
| `allocation_overflow_relation_unresolved` | allocation expr known; no-overflow/operand range unproven | relationship_unresolved | llm_semantic_review (hint: llm_or_range_evidence) |
| `unknown_allocator_contract` | allocator recognized but size semantics unknown | external_contract_unknown | llm_semantic_review (hint: contract_review) |
| `conflicting_reaching_allocations` | same dest has multiple incompatible reaching allocations | conflicting_definitions | additional_evidence_required |
| `destination_identity_ambiguous` | cannot establish which object is written | identity_ambiguous | additional_evidence_required |
| `free_may_reach_sink` | lifetime differs across feasible paths | relationship_unresolved | llm_semantic_review (hint: focused_path_question) |
| `free_dominates_sink` | allocation definitely freed before the op on every path | *(none)* — deterministic lifetime finding | separate_finding |
| `required_evidence_absent` | no more specific recoverable property | insufficient_evidence | additional_evidence_required |

Two corrections applied during the taxonomy review (before extending to other
producers, since the schema is now a cross-producer interface): **multiplication
overflow is a specific arithmetic relationship** (`allocation_overflow_relation_unresolved`
→ relationship_unresolved), not generic insufficiency; and **`capacity_invalidated_by_free`
was split** into free-dominates (deterministic lifetime finding), free-may-reach
(relationship_unresolved), destination-identity-ambiguous (identity_ambiguous),
and truly-unrecoverable (insufficient_evidence) — they no longer share one bucket
merely because capacity can't be used.

**Precedence.** A candidate can trip several prerequisites at once. Producers emit
ALL detected reasons in `all_reason_codes`; the PRIMARY reason (which fixes the
bucket) is the *earliest failed prerequisite* per a fixed `PRECEDENCE` order —
never dict/iteration order. (identity → conflicting → unknown-allocator →
free-dominates → free-may-reach → overflow → capacity → required-absent.)

**Validated (`tests/gates/analysis-record-r01`, 30/30):** four candidate-review
buckets with ≥3 independently-constructed examples each; `relationship_unresolved`
reached by two distinct reason codes; the precedence tie-break (conflict beats
overflow, both recorded); the free/lifetime split (dominates→deterministic_finding,
may-reach→relationship_unresolved, after-write→open_candidate) on the independent
runtimecap-cfg fixture; and reason↔bucket↔route schema consistency on every
record. Real bucket-distinction evidence, not a same-label smoke test.

**Maturity, stated honestly.** The reason layer's OPEN-CANDIDATE emission is now
implemented for three producers — runtime-capacity, cursor
(`write_count_bound_not_established`), and interprocedural
(`capacity_relation_not_established`). All three pilot cases now carry an explicit
producer reason (`reason_source: "explicit_producer_reason"`) and are
corpus-eligible: **SB-01, SB-02, SB-07 → 3/3 agreement, zero fallback.** The
generator REJECTS any record whose `reason_source != "explicit_producer_reason"`.

Still incomplete (before the COMPLETE scanner is frozen): the ABSTENTION-reason
emission for cursor/interprocedural (e.g. cursor's unresolved-alias →
`destination_identity_ambiguous`, interproc's conflicting propagations →
`conflicting_reaching_allocations`) is a documented future extension — those
producers currently emit explicit reasons only for their open candidates.
`identity_ambiguous` therefore still has no real emitter, so it remains
untested and unmanufactured.

`identity_ambiguous` is defined but NOT yet emitted by any instrumented producer;
it will be added only when a producer genuinely detects that condition — examples
are not manufactured to populate the category.

**This gate proves the implementation follows the mapping; it does NOT yet prove
the mapping is conceptually right or that these buckets occur in real code.**
Real-corpus validation of the taxonomy comes after it is frozen.

## Automatic bucket assignment (the piece that makes C a real test)

The bucket, unresolved property, and route shown in Condition C MUST be emitted
by the scanner from its own candidate signals — not written by a person. If a
human decides why TChecker is uncertain and types the category into C, the
experiment tests whether a human hint helps, not whether the bucket method
works. `tools/bucket_router.py` (in the TChecker package) removes the human from
that step: it consumes the frozen producers' candidate output and emits

```
{ candidate_id, established_facts, unresolved_property,
  uncertainty_bucket, recommended_route }
```

`uncertainty_bucket` is derived structurally (any emitted candidate is a
`relationship_unresolved` by the family's abstain-never-VULNERABLE posture);
`unresolved_property` is keyed on the candidate's subclass (width-bound vs
count-bound vs index-bound); the Condition-C focused question is rendered by a
FIXED template on `unresolved_property` (generic on purpose — a case-specific
question would smuggle human insight into the condition under test).

`build_auto_buckets.py` runs this over the real cached fact files for the three
candidate cases and writes machine-derived `auto_buckets/<id>.record.json` and
`sources_auto/<id>.{facts.txt,meta.json}`. **Validation: the auto-emitted bucket
agrees with the independently-verified bucket ground truth 3/3** (SB-01, SB-02,
SB-07). The human supplies only the fact file + function to locate the candidate
and the ground truth for the agreement check — never the bucket fed into C.

This exposed that the earlier hand-written C facts/questions were richer and
case-specific — i.e. they DID carry human insight. The final experiment must
generate B and C from `sources_auto/` (machine-derived), not the hand-written
`sources/`.

No-candidate buckets (`producer_evidence_missing`, `analysis_capability_missing`)
are NOT auto-classified yet: with no candidate there is nothing to route to the
LLM, and distinguishing "an absent fact" from "an unmodeled shape" needs the
producers to log why they emitted nothing. Those stay in the routing evaluation,
human-verified, and honestly out of scope for the automatic layer for now.

## Readiness gates for the FINAL A/B/C experiment (not yet met)

- [x] Automatic bucket layer emits candidate + facts + bucket + unresolved
      property + route from one scanner pass (`bucket_router.py`).
- [x] Automatic buckets agree with verified bucket ground truth (3/3 on the
      candidate cases).
- [ ] **Frozen scanner version** — soundness logic is still changing; no freeze
      yet. No scanner or bucket rule may change after the experimental prompts
      are generated.
- [x] **Open-candidate reason emission for every producer the corpus draws on**
      (runtime-capacity, cursor, interproc); all 3 pilot cases explicit, 3/3, no
      fallback. Abstention-reason emission for cursor/interproc still pending.
- [ ] **≥9 genuine routable candidates**, balanced among final safe /
      vulnerable / legitimately-unresolved outcomes, selected BEFORE any model
      calls by scanner state / bucket / verified ground truth / diversity —
      never by testing condition B (or A/C) first (that biases the experiment).
      Current: 3, all unresolved/safe.
- [ ] **B and C generated from `sources_auto/`** (machine-derived), with a
      token-matched B variant.
- [ ] **`relationship_answer` trichotomy pinned** (dry-run calibration fix).
- [ ] **Final isolated-call harness** (fixed model+version, randomized order,
      full archival) — every prompt reproducible from the frozen scanner
      artifact + candidate fingerprint.

## Files

- `sources/<id>.{code.txt,facts.txt,meta.json}` — per-case inputs.
- `generate_prompts.py` — builds `prompts/<id>_{A,B,C}.txt`; enforces byte-identical B/C facts.
- `prompts/system_instructions.txt` — shared framing, prepended identically to every call.
- `corpus/<id>.json` — ground truth + scanner_state + role (established before any call).
- `routing_eval.json` — the routing evaluation over all 8 cases.
- `rubric/scoring.py` — A/B/C scoring; primary = B vs C.
- `runs/` — archived valid model-call records.
- `excluded_pre_freeze/` — quarantined invalid outputs + manifest.
