# Mechanics dry-run results (DEVELOPMENT-ONLY — NOT an accuracy claim)

Ran the full A/B/C pipeline on the 5 development cases (15 blinded reviewer
tasks, one naive subagent each, seed 20260827). **These numbers validate the
machinery only. They are development-only and are excluded from every
confirmatory accuracy statistic.** n=5 in a single bucket cannot support any
accuracy or B-vs-C conclusion.

## Machinery: all green

| mechanic | result |
|----------|--------|
| prompt generation (A/B/C from frozen router) | OK — 5 cases × 3 conditions |
| byte-identical B/C evidence | OK — asserted at generation for all 5 (C differs only by the category/question block) |
| blinding + randomization | OK — 15 tasks shuffled, case/condition/GT sealed behind opaque blind_ids |
| running the reviewer | OK — 15/15 naive subagents returned a verdict |
| output parsing | OK — 15/15 JSON responses parsed |
| scoring + unblinding | OK — every response realigned to its case; all outcome types exercised (correct / committed_wrong / abstain) |
| archival | OK — prompts, manifest, sealed key, raw responses, scores all under `archive/` |

## Per-condition tallies (mechanics only — do NOT read as accuracy)

| condition | correct | committed_wrong | abstain |
|-----------|---------|-----------------|---------|
| A | 3 | 2 | 0 |
| B | 2 | 3 | 0 |
| C | 2 | 1 | 2 |

## Mechanics findings worth carrying into the confirmatory design

These are observations about the *harness*, surfaced by the dry run — not
results about the hypothesis.

1. **The code block omits referenced macros / `#define`s.** The prompt shows the
   enclosing function only. For macro-heavy code (mozjpeg `encode_one_block`:
   `BUFSIZE`, `PUT_BITS`, `CHECKBUF15`, `EMIT_*`), reviewers could not see the
   136-byte capacity or the emit widths, and said so explicitly. This is a real
   prompt-construction gap: the confirmatory generator should include the
   definitions the highlighted operation depends on (the destination's
   declaration/capacity macro and the write macros), or the code condition is
   under-specified for exactly the cases the scanner flags.

2. **`rsa_vuln` (CVE-2019-17006) was called `safe` in all three conditions.**
   The real bug is a subtle signed/unsigned `padLen` underflow; every reviewer
   reconstructed the "exact-fit" arithmetic and judged the guard sufficient.
   This says the case is genuinely hard, and that neither facts (B) nor the
   focused question (C) flipped it here — but with n=1 per condition it is an
   anecdote, not a finding.

3. **Condition C drew more abstentions (2 of 5) than A/B (0).** The focused
   question appears to push a reviewer toward `unknown` when it cannot be
   answered from the shown code. Whether that is desirable (honest abstention)
   or harmful (suppressing a correct commit) is precisely what a *powered*
   B-vs-C comparison must measure — impossible at n=5 in one bucket.

4. **All 5 cases are `relationship_unresolved`.** The dry run cannot exercise
   B-vs-C across bucket variety because the frozen llm-eligible corpus has none
   (see `../FEASIBILITY.md`). Motivates Step 2 (corpus expansion).

## Conclusion

The experimental machinery is sound and archival is complete. Before a
confirmatory run: (a) fix finding #1 in the prompt generator, (b) expand the
corpus (Step 2) until it holds ≥3 safe / 3 vulnerable / 3 unresolved
independently-verified cases across multiple repos, shapes, and eligible
buckets. Only then does the confirmatory A/B/C experiment begin — on fresh
cases, never these five.
