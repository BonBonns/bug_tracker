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

## Files

- `sources/<id>.{code.txt,facts.txt,meta.json}` — per-case inputs.
- `generate_prompts.py` — builds `prompts/<id>_{A,B,C}.txt`; enforces byte-identical B/C facts.
- `prompts/system_instructions.txt` — shared framing, prepended identically to every call.
- `corpus/<id>.json` — ground truth + scanner_state + role (established before any call).
- `routing_eval.json` — the routing evaluation over all 8 cases.
- `rubric/scoring.py` — A/B/C scoring; primary = B vs C.
- `runs/` — archived valid model-call records.
- `excluded_pre_freeze/` — quarantined invalid outputs + manifest.
