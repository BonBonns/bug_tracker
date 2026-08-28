# Stage 2 scoring plan — pre-registered BEFORE labels or model outputs exist

Frozen before any Stage-1 label or A/B/C output is visible, so no analysis decision
is made after seeing the class distribution or the results. The canonical
implementation is `scoring_harness.py`, frozen against synthetic labels
(`study/scoring_freeze/`); the real analysis runs the identical code.

## Conditions

Abstract arms (named concretely when the study starts):

- **A** = unguided LLM review (baseline prompt, no bucket/evidence guidance).
- **B** = bucket-/evidence-guided LLM review (the capability-effect condition).
- **C** = optional deterministic/human or alternate baseline.

Each condition emits, per instance, one of: `VULNERABLE`, `SAFE`, `ABSTAIN`. A
missing output or a parse failure is mapped to `ABSTAIN` (never silently dropped).

## The eight rules (answers)

1. **Primary comparison.** A single pre-registered comparison: **B − A** (does bucket
   guidance improve the judgment). C-vs-A and B-vs-C are secondary/exploratory.
2. **Point estimate & uncertainty.** Point estimate is **instance-weighted**;
   **uncertainty is family-clustered** (families are the resampling unit).
3. **Primary population.** **Independently-labeled `VULNERABLE` vs `SAFE`
   instances** in the **confirmatory** split only.
4. **Primary metric.** **Selective balanced accuracy** =
   `0.5·(sensitivity + specificity)` computed over *answered* VULNERABLE/SAFE
   instances, **reported jointly with coverage** — accuracy is never reported
   without its coverage. Balanced (macro over the two classes) so a rare
   `VULNERABLE` class is not swamped by `SAFE`; this is why prevalence enrichment is
   not needed and raw prevalence accuracy is not the primary.
5. **Abstention.** An `ABSTAIN` on a VULNERABLE/SAFE instance is **not** scored
   correct or incorrect; it lowers **coverage**. Primary metric is selective (over
   answered). A pre-registered **sensitivity analysis** re-scores abstentions as
   incorrect, to bound how much selectivity flatters a condition.
6. **Ground-truth `UNRESOLVED`.** **Excluded from binary accuracy.** Evaluated
   separately as an **appropriate-abstention** outcome: the fraction of truly
   `UNRESOLVED` instances on which a condition abstains (appropriate) vs commits to
   VULNERABLE/SAFE (over-confident). Reported per condition.
7. **Parse failures / missing outputs.** Counted as **`ABSTAIN`** (rule 5), never
   dropped. The parse-failure rate is reported separately as a data-quality metric.
8. **Multiple comparisons.** The **primary (B−A) is a single test** — no correction
   needed. Secondary comparisons (C−A, B−C) and per-class secondary metrics are
   corrected with **Holm–Bonferroni** across the pre-registered secondary family.

## Canonical uncertainty procedure

**Cluster (family) bootstrap**, fixed seed `20260101`, **10,000** resamples:
resample *families* (not instances) with replacement; within each resample recompute
each condition's selective balanced accuracy and the **paired** difference B−A on the
same resampled families; the 95% CI is the **percentile interval** (2.5, 97.5). The
effect is "significant" iff the 95% CI excludes 0. A **logistic mixed-effects model**
(random intercept per family) is a pre-registered **secondary** robustness check, not
the primary inference.

## Secondary metrics (per condition)

Coverage, abstention rate, parse-failure rate, sensitivity (recall on VULNERABLE),
specificity (recall on SAFE), selective accuracy (raw, unbalanced), and the
appropriate-abstention rate on `UNRESOLVED`.

## Reporting order (fixed)

1. Stage-1 class distribution (VULNERABLE / SAFE / UNRESOLVED) in dev and
   confirmatory — reported first, before any accuracy number.
2. Confirmatory power check (VULNERABLE/SAFE instance and family counts) **without
   changing the split**.
3. Per-condition secondary metrics with coverage.
4. Primary B−A selective balanced accuracy difference + family-clustered 95% CI.
5. Sensitivity analysis (abstention=incorrect) and secondary comparisons (Holm).
6. `UNRESOLVED` appropriate-abstention analysis.

If the confirmatory `VULNERABLE` family count is too small to power B−A at a
plausible effect size, the result is reported **descriptively** with the CI; the
split is **not** rearranged and copies are **not** split to buy n.

## Freeze

`scoring_harness.py` is frozen by sha256 (recorded in `study/scoring_freeze/
FROZEN.json`) after passing the synthetic self-test. Stage 2 runs the identical file
on the real `study/stage1_labels.jsonl` and the real A/B/C prediction files. No
scoring parameter is chosen after real labels or outputs are visible.
