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
4. **Primary metric — coverage-penalised, not selective.** **Full-population
   balanced accuracy** = `0.5·(sensitivity + specificity)` over **every**
   VULNERABLE/SAFE instance, with denominators = the *total* per class, so an
   `ABSTAIN` or parse failure counts as an **incorrect** answer. This cannot be
   gamed by abstaining on hard cases (an abstain on a hard `VULNERABLE` is a miss).
   *Rationale:* selective accuracy rewards strategic abstention — a condition that
   answers only 10 easy cases correctly and abstains on 90 scores 100% selective
   while being far less useful; reporting coverage beside it does not stop the
   paired test from crowning it. So selective is **demoted to secondary**.
   Balanced (macro over the two classes) so a rare `VULNERABLE` class is not swamped.
5. **Metric hierarchy.**
   - Primary: full-population balanced accuracy (abstain/parse = incorrect).
   - Secondary: **selective** balanced accuracy among *answered* cases.
   - Secondary: **coverage** and **abstention rate**.
   - Separate: **appropriate abstention** on ground-truth `UNRESOLVED`.
   (A coverage-noninferiority-then-selective design was considered and rejected: it
   requires choosing and defending a coverage margin before labels, which the
   coverage-penalised primary avoids.)
6. **Ground-truth `UNRESOLVED`.** **Excluded from binary accuracy.** Evaluated
   separately as an **appropriate-abstention** outcome: the fraction of truly
   `UNRESOLVED` instances on which a condition abstains (appropriate) vs commits to
   VULNERABLE/SAFE (over-confident). Reported per condition.
7. **Parse failures / missing outputs.** Counted as **`ABSTAIN`**, i.e. incorrect
   under the primary metric; never dropped. The parse-failure rate is reported
   separately as a data-quality metric.
8. **Multiple comparisons.** The **primary (B−A) is a single test** — no correction
   needed. Secondary comparisons (C−A, B−C) are corrected with **Holm–Bonferroni**
   across the pre-registered secondary family.

## Canonical uncertainty procedure + rare-class rule

**Cluster (family) bootstrap**, fixed seed `20260101`, **10,000** resamples:
resample *families* (not instances) with replacement; within each resample recompute
each condition's **primary** balanced accuracy and the **paired** difference B−A on
the same resampled families; the 95% CI is the **percentile interval** (2.5, 97.5).
The effect is "significant" iff the 95% CI excludes 0. A **logistic mixed-effects
model** (random intercept per family) is a pre-registered **secondary** robustness
check, not the primary inference.

**Rare-class degeneracy (pre-registered).** With a low `VULNERABLE` base rate a
resample can contain zero `VULNERABLE` (or zero `SAFE`) instances, leaving balanced
accuracy undefined. Two guards:

- **Power gate (primary).** The confirmatory CI is computed **only if** at least
  `MIN_POS_FAMILIES = 12` families carry a `VULNERABLE` instance **and** ≥ 12 carry a
  `SAFE` instance. Below that, results are reported **descriptively** (point estimate
  only, no CI) — the split is not rearranged and copies are not split to buy n.
- **Degenerate-resample handling.** Past the gate, any resample with 0 `VULNERABLE`
  or 0 `SAFE` instances is **discarded** (not redrawn); the CI is taken over the
  remaining valid resamples and the **discard fraction is reported**. If the discard
  fraction exceeds `MAX_DEGENERATE_FRAC = 0.05`, the CI is **flagged non-robust** and
  the descriptive result takes precedence.

## Secondary metrics (per condition)

Coverage, abstention rate, parse-failure rate, selective balanced accuracy
(answered only), selective sensitivity/specificity, and the appropriate-abstention
rate on `UNRESOLVED`.

## Reporting order (fixed)

1. Stage-1 class distribution (VULNERABLE / SAFE / UNRESOLVED) in dev and
   confirmatory — reported first, before any accuracy number.
2. Confirmatory power gate (VULNERABLE/SAFE **family** counts vs `MIN_POS_FAMILIES`)
   **without changing the split** — decides confirmatory vs descriptive.
3. Per-condition metrics: primary balanced accuracy, then secondary (selective,
   coverage, abstention, parse-failure).
4. Primary B−A **full-population** balanced accuracy difference + family-clustered
   95% CI (with the degenerate-resample fraction).
5. Secondary comparisons (C−A, B−C) with Holm.
6. `UNRESOLVED` appropriate-abstention analysis.

If the power gate fails (too few independently-`VULNERABLE` families), the result is
reported **descriptively** (point only, no CI); the split is **not** rearranged and
copies are **not** split to buy n.

## Freeze

`scoring_harness.py` is frozen by sha256 (recorded in `study/scoring_freeze/
FROZEN.json`) after passing the synthetic self-test. Stage 2 runs the identical file
on the real `study/stage1_labels.jsonl` and the real A/B/C prediction files. No
scoring parameter is chosen after real labels or outputs are visible.
