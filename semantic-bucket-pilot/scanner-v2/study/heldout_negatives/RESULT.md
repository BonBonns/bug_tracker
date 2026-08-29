# Specificity / soundness result — 101 non-vulnerable SecVulEval sites (unchanged scanner)

A **separate** frozen measurement from the now-consumed 258 vulnerable corpus. Run with the
**byte-identical unchanged scanner** (`544a606`, capabilities 1–4 + three frozen producers) on
the 101 preserved **non-vulnerable** mapped SecVulEval sites (function-level source packets,
101/101 sha-verified, zero overlap with the vulnerable pool). Raw archived first:
`raw_negatives.jsonl` (sha `5c624dc5…`).

**What this measures:** unsupported vulnerability promotions and abstention behavior on labeled
non-vulnerable write sites. **What it does NOT measure:** conventional accuracy/precision — the
scanner emitted **no** safe/vulnerable conclusions on these sites at all (see below), so no
accuracy figure can be formed. This completes the **soundness** picture only.

## Harness correction check (post hoc — see study/heldout_correction/)

This negative run used the same harness that mistakenly invoked V1 instead of the declared V2
runtime-capacity producer. The post-hoc V2 replay on the archived CPGs was applied to all 101
negative rows: the recognition set is invariant (3→3) and **0 negative dispositions changed** —
no non-vulnerable site is promoted or re-routed under V2. The 101-site soundness conclusion
below (0 unsupported vulnerability promotions, all recognized writes abstain) is **unchanged**
by the correction.

## Recognition funnel (101 non-vulnerable sites)

| stage                       | result   |
|-----------------------------|----------|
| source available            | 101/101  |
| build/parse OK              | 101/101  |
| labeled write mapped to CPG | 76/101   (25 stage-3 mapping attrition) |
| recognized at labeled site  | 3/76     |

Scanner misses (mapped, not recognized), by write_kind: pointer_deref 43, copy_sink 18,
index_write 12. Built-but-unmapped: pointer_deref 21, index_write 2, copy_sink 2.

## Soundness signal (the headline)

**At the labeled non-vulnerable site (of the 3 recognized):**
- unsupported **vulnerability** promotions (`proven_oversized`): **0**
- safe promotions (`deterministic_complete`): **0**
- abstained: **3** (all)

**Body-wide** — across *every* recognized write in the 101 non-vulnerable bodies (a promoted
overflow anywhere in a non-vulnerable body would be a candidate false positive):
- bodies with ≥1 `proven_oversized` record: **0**  ← **zero unsupported vulnerability promotions**
- bodies with ≥1 `deterministic_complete` record: **0**
- aggregate recognized-record dispositions: 11 abstained + 4 unresolved/none — **all abstentions**
- 15 raw recognized records → 14 unique physical operations (identity chain holds); **none**
  promoted to any verdict.

## Reading

On 101 non-vulnerable held-out sites the unchanged scanner made **zero unsupported vulnerability
promotions** and **zero safe promotions** — it abstained on every recognized write, at the
labeled site and body-wide. No `proven_oversized` was ever emitted on non-vulnerable code.

Combined with the vulnerable run (4 recognized sites, all abstained, **zero observed unsupported
safe promotions at labeled vulnerable sites**), the observed behavior is **sound in both
directions**: no false-overflow claims on non-vulnerable code, no false-safe claims at the
recognized vulnerable sites. But the scanner issues **essentially no verdicts** on held-out real
code — on both corpora it recognizes a small minority of writes and then abstains for lack of
packet-level capacity/contract evidence. This is a soundness observation, **not** an accuracy or
false-positive-rate result: with 0 verdicts emitted, there is no confusion matrix to compute.

## Status

This measurement uses the unchanged scanner and does not consume anything needed for future
development. The 258 vulnerable corpus remains consumed (a scanner change motivated by its misses
would make it development data). The soundness picture is now complete for both the vulnerable and
non-vulnerable held-out slices; any resumption of development should use a new, unseen corpus for
the next confirmatory generalization claim.
