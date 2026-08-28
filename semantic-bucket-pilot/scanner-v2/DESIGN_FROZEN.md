# Design frozen — Stage-1 execution runbook

The study design is **closed**. Further redesign now would risk an outcome-responsive
protocol. Unless Stage 1 reveals a **genuine packet or labeling defect**, nothing in
the frozen set changes. The frozen set is fingerprinted in `study/DESIGN_FROZEN.json`
(`freeze_design.py`); re-run and diff to detect drift.

Combined design fingerprint: `df181367ca436606f860c11f8b0329d66b9744250ec3b5b6a659f3409d9068a5`
(27 artifacts, Stage 1 not started).

## Two separate empirical findings

1. **Routing / evidence integration (done).** V2 consumed stack-capacity evidence v1
   ignored, reducing `additional_evidence_required` routing from **88.8% → 64.3%**
   within the evaluated corpus — broadly distributed, not driven by the identified
   conflict groups (`ROUTE_TRANSITION_MATRIX.md`).
2. **Single-bucket LLM experiment (ready to label).** Tests whether a focused
   length-relationship question (C) improves evidence-calibrated review versus a
   generic, length-matched instruction (B) when both receive identical established
   facts. `C − B`, three-class macro recall, family-clustered, one fixed reference
   target.

## Scope (hard limits)

The A/B/C study **cannot** support claims about multiple bucket types, automatic
bucket selection, path reasoning, identity ambiguity, or semantic review generally —
all 438 LLM-eligible cases are one bucket (`length_meaning`). Those are covered only
by finding 1 (the broader routing characterization) or future work (`STUDY_SCOPE.md`).

## Frozen execution sequence (do in order; do not reorder or skip)

1. **Independently label** the 438 neutral reference instances
   (`study/stage1_labeling_packet.jsonl`) into `study/stage1_labels.jsonl` per
   `STAGE1_LABELING.md`. Labelers are independent of the model being scored; the
   condition is hidden; rationale + evidence archived. Randomize packet order.
2. **Validate scanner facts**; set `established_facts_valid`; exclude invalid packets
   per the frozen rule (harness drops them; reported as upstream evidence errors).
3. **Resolve reviewer disagreements** with the frozen tie-break
   (`UNSUPPORTED_ASSUMPTION_RUBRIC.md` procedure; two reviewers + adjudicator).
4. **Freeze and hash** the completed `study/stage1_labels.jsonl`.
5. **Recompute post-exclusion** class + family counts and the **minimum inference
   gate** on the families remaining after exclusion (the harness already does this;
   `computed_after_invalid_exclusion=true`). Original counts are not reused.
6. **Authoritatively check B/C prompt lengths** with the fixed provider's token-count
   facility or input-token metadata if permitted; re-freeze `study/prompts_FROZEN.json`.
   If authoritative counts stay unavailable, retain the proxy, report it transparently
   with char/word counts, and do not call it exact tokenizer matching.
7. **Only then run randomized A/B/C** calls (`PROMPT_CONDITIONS.md`).
8. **Keep all condition outputs hidden** until the run is complete; then run the
   frozen `scoring_harness.py` once.

## What may still change (only these)

A genuine defect found during Stage 1 — a packet that misrepresents its source, a
labeling-schema gap, an invalid-fact rule that cannot be applied — may be corrected,
re-frozen, and re-fingerprinted, with the change recorded. Nothing else. Results,
class distributions, or model outputs must never motivate a design change.

## The model's boundary

The model whose A/B/C outputs this study scores does not assign the Stage-1 labels and
does not adjudicate them. Stage 1 is an independent-reviewer step.
