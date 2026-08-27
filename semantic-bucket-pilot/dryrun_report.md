# Dry-run report — 3-case A/B/C prompt mechanics

**Scope:** prompt-mechanics + rubric validation only, on the three genuine
frozen-scanner candidates (SB-01, SB-02, SB-07), each × conditions A/B/C = 9
isolated calls. **Not** an accuracy result for the thesis: 3 cases, all
scanner-category `relationship_unresolved`, verified answers skewed
(2 unresolved, 1 safe, 0 vulnerable-with-candidate). Calls made via the Agent
tool (fresh subagent, no inherited history, instructed no-tools) — preliminary /
debugging per policy, archived in `runs/`, not final thesis observations.

## Did the mechanics work? Yes.

- 9/9 calls returned schema-valid JSON parseable by the rubric.
- `rubric/scoring.py` scores against `verified_ground_truth`, keeps
  scanner-category separate from the verified answer, and computes the B-vs-C
  delta.
- `generate_prompts.py` produced byte-identical B/C established-facts fields
  (verified: C = B + a 166–257 byte category+question appendix per case).

## Scored results

| Case | verified | A | B | C |
|---|---|---|---|---|
| SB-07 | safe | safe ✓ | safe ✓ | safe ✓ |
| SB-01 | unresolved | **safe ✗** | unresolved ✓ | unresolved ✓ |
| SB-02 | unresolved | **safe ✗** | unresolved ✓ | unresolved ✓ (rel. "contradicted") |

Condition accuracy (conclusion / relationship / appropriate-abstention):
- **A:** 0.33 / 0.33 / 0.00 — over-claimed "safe" on both hard cases;
  contradicts_deterministic = 2/3.
- **B:** 1.00 / 1.00 / 1.00.
- **C:** 1.00 / 0.67 / 1.00.
- **PRIMARY B-vs-C:** conclusion delta **0.00**, relationship delta **−0.33**.

## The honest finding: on these 3 cases the bucket (C) shows NO benefit over generic-unknown (B)

The entire lift is **A → B (the established facts)**, not **B → C (the typed
bucket + focused question)**:

- On SB-01 and SB-02, condition A (code only) concluded "safe" by building an
  in-bounds arithmetic argument while flagging the load-bearing unproven premise
  (unsigned-underflow reachability / Huffman worst-case bound) merely as an
  "unsupported assumption" — then relying on it anyway. That is exactly the
  over-claim the pilot is meant to detect.
- Adding the **facts** (B) moved both to the correct "unresolved" abstention.
- Adding the **bucket + focused question** (C) did not improve on B; on SB-02 it
  scored worse on the relationship dimension (see calibration issue below).
- SB-07 is a **ceiling** case: A already solved it by tracing the cross-function
  equality, so no condition could show separation.

This is a real, if deflating, signal: **condition B saturated the achievable
accuracy on every case here, leaving no room for the bucket to demonstrate
value.** It is not evidence against the bucket hypothesis in general — 3
skewed cases cannot be — but it means these cases do not *test* it. Reported
as-is rather than presented as support the data does not provide.

## Two concrete problems to fix before the real experiment

1. **Inclusion criteria must select cases where B is INSUFFICIENT but C
   resolves.** A case only tests the bucket contribution if condition B (facts +
   generic "unresolved") does *not* already reach the verified answer. Add to
   the frozen criteria: *a candidate qualifies for the A/B/C accuracy set only
   if a pre-registered condition-B check leaves the answer wrong or unresolved,
   so the focused question has something to add.* (Applying this now would
   exclude all three dry-run cases from the accuracy set — SB-07 because A
   already solves it, SB-01/SB-02 because B already solves them.)

2. **`relationship_answer` semantics are under-specified for "does X hold?"
   questions.** SB-02's focused question ("does anything bound the write count to
   ≤ capacity?") drew "contradicted" from condition C, where the verified answer
   is "unresolved" — because "nothing shown bounds it" reads equally as "the
   safety relationship fails" (contradicted) or "safety cannot be established"
   (unresolved). Before scaling, define crisply: **established** = proven safe;
   **contradicted** = proven unsafe (a concrete violating input exists);
   **unresolved** = neither proven. "No bound is shown" is **unresolved**, not
   contradicted, unless an actual overflowing input is demonstrated. The focused
   question wording should be aligned to that trichotomy.

## Token counts (for the token-matched B variant in the real experiment)

Full-prompt sizes (system + condition body), from `staged/`:
- SB-01: A 4692 / B 5836 / C 6005 bytes
- SB-02: A 4233 / B 4982 / C 5148 bytes
- SB-07: A 5614 / B 6389 / C 6646 bytes

C exceeds B by ~166–257 bytes (the category + focused question). The real
experiment must add a token-matched B variant (same facts restated in untyped
prose) so any C effect is not attributable to length.

## Go / no-go

- **Mechanics: GO.** Prompt generation, isolation, schema, archival, quarantine,
  routing eval, and rubric all work end to end.
- **Accuracy pilot: NOT YET.** Do not run or report an A/B/C accuracy result
  until: (a) fresh cases meeting the *B-insufficient* criterion above are
  sourced (target ≥9: 3 safe / 3 vulnerable / 3 unresolved, multiple
  functions/repos), (b) the `relationship_answer` trichotomy is pinned down and
  the rubric updated, (c) a token-matched B variant exists, and (d) the final
  run uses fixed-model isolated calls with randomized condition order and full
  archival.
