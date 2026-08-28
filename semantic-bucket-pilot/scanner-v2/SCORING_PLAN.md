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
3. **Primary population + fixed target.** **All independently-labeled instances** —
   `VULNERABLE`, `SAFE`, **and** `UNRESOLVED` — in the **confirmatory** split only.
   The scored ground-truth field is **`evidence_reference_conclusion`**: the
   conclusion supported by the **fixed neutral reference packet**
   (`REFERENCE_PACKET.md` — shared code + the established scanner facts shared by B
   and C; no bucket, no focused C question, no condition id). Because A/B/C receive
   *different* packets (A: code only; B/C: code + established facts), a
   condition-specific target would score them against different answers and make
   accuracy incomparable; one fixed reference target keeps them comparable and asks
   whether each *presentation* helps reach the conclusion the common evidence
   supports. **B−C is especially clean** — B and C hold byte-identical facts, so the
   difference isolates presentation. A model that guesses "vulnerable" without the
   reference evidence supporting it is marked **wrong** — the study tests calibrated
   reasoning from supplied evidence, not lucky guesses. `program_outcome` is reported
   separately (a scored × program cross-tab), never scored, so "unresolved" stays a
   property of the *available evidence*, not an inherent property of the program.
4. **Primary metric — three-class macro recall.** Ground truth ∈
   {`VULNERABLE`, `SAFE`, `UNRESOLVED`} (from `evidence_reference_conclusion`);
   prediction ∈ {`VULNERABLE`, `SAFE`, `ABSTAIN`(=predict UNRESOLVED)}; `PARSE_ERROR`
   is always incorrect. Score = **average recall across all three classes**. This penalises **both** failure
   modes: abstaining on resolved (`VULNERABLE`/`SAFE`) cases *and* committing on
   cases that should stay `UNRESOLVED`. A resolved-only, coverage-penalised metric
   (the previous primary) leaves the second hole open — a condition could guess on
   every unresolved case with no primary penalty — so the primary must include
   `UNRESOLVED`. Macro (unweighted mean of per-class recalls) so a rare class is not
   swamped.
5. **Metric hierarchy.**
   - Primary: three-class macro recall.
   - Secondary: **resolved-class full-coverage balanced accuracy** (`VULNERABLE`
     vs `SAFE` only, `ABSTAIN`/parse = incorrect) — the previous primary, renamed:
     it excludes `UNRESOLVED`, so it is *not* "full-population."
   - Secondary: **selective** balanced accuracy among *answered* resolved cases.
   - Secondary: **coverage** and **abstention rate**.
   - Secondary: **external unsupported-assumption rate** — fraction of a condition's
     committed answers that an **independent adjudicator**, applying the frozen
     rubric in `UNSUPPORTED_ASSUMPTION_RUBRIC.md` over the response and the
     ground-truth evidence, judges to rest on an assumption unsupported by the
     evidence. This is the error metric. The model's **self-report** is recorded
     separately as **descriptive only** and is NOT used as an error metric — a model
     making an unsupported assumption may simply fail to list it.
   - Separate: **appropriate abstention** on ground-truth `UNRESOLVED` (= the
     per-class recall on `UNRESOLVED`).
   (A coverage-noninferiority-then-selective design was considered and rejected: it
   requires choosing and defending a coverage margin before labels.)
6. **Ground-truth `UNRESOLVED`.** **Included in the primary** as its own class
   (recall = appropriate-abstention rate). Not a separate excluded bucket.
7. **Parse failures / missing outputs.** Mapped to `PARSE_ERROR`/`ABSTAIN` and
   scored **incorrect** under the primary; never dropped. The parse-failure rate is
   reported separately as a data-quality metric.
8. **Multiple comparisons.** The **primary (B−A) is a single test** — no correction
   needed. Secondary comparisons (C−A, B−C) are corrected with **Holm–Bonferroni**
   across the pre-registered secondary family.

## Canonical uncertainty procedure + rare-class rule

**Cluster (family) bootstrap**, fixed seed `20260101`, **10,000** resamples:
resample *families* (not instances) with replacement; within each resample recompute
each condition's **three-class macro recall** and the **paired** difference B−A on
the same resampled families; the 95% CI is the **percentile interval** (2.5, 97.5).
The effect is "significant" iff the 95% CI excludes 0. A **logistic mixed-effects
model** (random intercept per family) is a pre-registered **secondary** robustness
check, not the primary inference.

**Rare-class degeneracy (pre-registered).** With a low `VULNERABLE` (or
`UNRESOLVED`) base rate a resample can miss a class, leaving its recall — and the
macro average — undefined. Two guards:

- **Minimum inference gate.** The confirmatory CI is computed **only if each of the
  three classes** has ≥ `MIN_CLASS_FAMILIES = 12` families carrying it. Below that,
  results are reported **descriptively** (point only, no CI) — the split is not
  rearranged and copies are not split to buy n. **This is a minimum-count floor, not
  demonstrated statistical power.** The achievable effect size is characterised by
  `mde_simulation.py` (empirical power vs true B−A gap over the frozen family
  structure and assumed prevalences; reports the MDE at 80% power). If the real
  `UNRESOLVED` or `VULNERABLE` family count falls below 12 after labeling, the
  primary is reported descriptively.
  *Result (`study/mde_simulation.json`):* **Under the frozen simulation
  assumptions** (base per-class recall 0.60, family-clustered labels, improvements
  simulated as a uniform per-class recall lift), the estimated 80%-power detectable
  B−A macro-recall gap is **≈ 0.16–0.20** — ≈0.16 at moderate/rich prevalence
  (V≈0.15–0.25), ≈0.20 at a low vulnerable base rate (V≈0.08, ~19 vulnerable
  families). This is **not a universal MDE**: it depends on the assumed class
  prevalence, the baseline accuracy, the within-family dependence, and how the
  improvement is simulated. Effects below ~0.15 — and any effect if the vulnerable
  class is very rare — are underpowered and would be reported descriptively, not as
  a null.
- **Degenerate-resample handling.** Past the gate, any resample missing a class is
  **discarded** (not redrawn); the CI is taken over the remaining valid resamples and
  the **discard fraction is reported**. If it exceeds `MAX_DEGENERATE_FRAC = 0.05`,
  the CI is **flagged non-robust** and the descriptive result takes precedence.

## Secondary metrics (per condition)

Per-class recalls (`VULNERABLE`/`SAFE`/`UNRESOLVED`), resolved-class full-coverage
balanced accuracy, selective balanced accuracy (answered only), coverage, abstention
rate, parse-failure rate, **external** unsupported-assumption rate (error metric;
self-report kept descriptive only), and appropriate-abstention on `UNRESOLVED`.

## Reporting order (fixed)

0. **Synthetic freeze numbers are harness-regression outputs, not findings.** The
   B−A values in `study/scoring_freeze/` exist only to lock the code; they change
   with the synthetic seed and instance ids and **must never appear in the results
   section**. Only the real Stage-2 run over real labels produces findings.
1. Stage-1 class distribution of `evidence_reference_conclusion` (VULNERABLE / SAFE /
   UNRESOLVED) in dev and confirmatory, **plus the `program_outcome` cross-tab** —
   reported first, before any accuracy number.
2. Confirmatory **minimum inference gate** (families-per-class vs
   `MIN_CLASS_FAMILIES` for all three classes) **without changing the split** —
   decides confirmatory vs descriptive.
3. Per-condition metrics: primary three-class macro recall + per-class recalls,
   then secondary (resolved full-coverage, selective, coverage, abstention,
   parse-failure, unsupported-assumption).
4. Primary B−A **three-class macro recall** difference + family-clustered 95% CI
   (with the degenerate-resample fraction).
5. Secondary comparisons (C−A, B−C) with Holm.
6. `UNRESOLVED` recall (appropriate-abstention) analysis per condition.

If the gate fails (any class under `MIN_CLASS_FAMILIES` families), the result is
reported **descriptively** (point only, no CI); the split is **not** rearranged and
copies are **not** split to buy n.

## Freeze

`scoring_harness.py` is frozen by sha256 (recorded in `study/scoring_freeze/
FROZEN.json`) after passing the synthetic self-test, which includes an **anti-gaming
regression** covering both failure modes: a strategic-abstention condition and an
over-confident condition that never abstains on `UNRESOLVED` both score below a
calibrated condition on the primary. Stage 2 runs the identical file on the real
`study/stage1_labels.jsonl` and A/B/C prediction files. No scoring parameter is
chosen after real labels or outputs are visible.
