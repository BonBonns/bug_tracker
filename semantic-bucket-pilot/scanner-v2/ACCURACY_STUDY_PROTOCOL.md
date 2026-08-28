# Next study (OPEN) — does bucket-guided LLM review improve the security judgment?

Status: **not started.** This file records the design constraints for the accuracy
study so the routing result does not silently imply it. The routing study
(`ROUTE_TRANSITION_MATRIX.md`) is finished and answers a *different* question.

## The two questions are distinct

- **Routing (done).** Given v1's abstentions, does consuming locally available
  stack-capacity evidence move operations off `additional_evidence_required`?
  Answer: yes, 88.8% → 64.3% within the evaluated corpus, broadly distributed,
  not driven by the identified conflict groups. This says nothing about whether
  the resulting routes are *correct*.
- **Accuracy (open).** Given cases TChecker has correctly prepared for semantic
  review, does bucket-guided LLM review improve the final security judgment
  (vulnerable / safe / genuinely-unresolved) versus the alternatives?

The accuracy question is **not** answered by adding outcome labels to the 498
newly-eligible operations and reading off accuracy. It requires the design below.

## 1. Define the target population BEFORE sampling

Pick which claim is being made, and sample from that frame:

- **Complete v2 review pipeline** → target = *all* v2 LLM-eligible operations.
- **Effect of the stack-capacity capability specifically** → target = *only* the
  498 operations newly made eligible by the capability
  (`additional_evidence_required → semantic_relationship_review`).

Do not blur the two. The 68 `range_arithmetic_review` and 54 `deterministic_complete`
operations are separate routes with their own questions and are not part of the
LLM-review population.

## 2. Independent case families

Group related operations (same function/pattern across vuln/patched, macro
expansions, sibling offset writes) into **independent case families** and sample /
analyze at the family level. The routing study already shows heavy within-family
repetition (e.g. comba `at[]`, per-curve `hash[]`/`nonce[]`); treating those copies
as independent observations would inflate n and understate variance.

## 3. Select cases before running A/B/C

Draw the sample **without** first running the LLM (or any condition). Selecting or
filtering cases after seeing a condition's output biases the estimate. Freeze the
selected set; record it before any condition runs.

## 4. Independent, blinded outcome labels

Ground-truth outcomes verified **independently** of TChecker and **blinded to the
experimental condition** (which pipeline/route produced the case, and what it said).
The label is the true security outcome, not the scanner's or the LLM's assertion.

## 5. If you balance classes, do not report population prevalence

Deliberately enriching for vulnerable cases (to get enough positives) makes a
**case-control** sample, not a naturally representative one. Then:

- report **balanced / macro accuracy** (unweighted mean over safe / vulnerable /
  unresolved), **or**
- **reweight** estimates back to the original population prevalence.

Never report ordinary population-prevalence accuracy computed over an enriched
sample. Also fix and report the base rate: how many genuine vulnerable cases exist
in the target population at all (the disclosed-CVE positives are few).

## 6. Development set separate from the confirmatory set

Keep a **development** subset (for prompt design, bucket-guidance tuning, pipeline
debugging) strictly separate from a **held-out confirmatory** set used once for the
reported estimate. No tuning against the confirmatory set.

## Conditions (A/B/C) — to be specified when the study starts

The comparison is over cases TChecker has *correctly* prepared for review (so that
preparation quality is not the confound). Candidate arms — e.g. unguided LLM vs
bucket-/evidence-guided LLM vs a deterministic/human baseline — are to be pinned
down with the population choice above. The metric is improvement in the **final
security judgment**, not agreement with the route.

---

Until this is executed, the bounded claim stands: v2 improved evidence integration
and routing; whether that improves vulnerability-detection accuracy is untested.
