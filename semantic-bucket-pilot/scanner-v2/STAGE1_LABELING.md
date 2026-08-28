# Stage 1 — blinded security labeling (sidecar, not a manifest mutation)

Stage 0 defines which cases exist (`study/instances.jsonl`, immutable). Stage 1
independently defines what happened. **Neither artifact rewrites the other.** Labels
are never written back into the frozen instance manifest; they live in a separate
sidecar and are frozen separately after review.

## Labeling invariants (retained, frozen)

1. **Ground truth belongs to each case instance** — one label per instance, not per
   family.
2. **Families are used only for the dev/confirmatory split and clustered inference**,
   never for labeling.
3. **Pre-patch and post-patch members of a family may legitimately have different
   labels** (e.g. vulnerable pre-patch, safe post-patch). Disagreement within a
   family is expected, not a defect.
4. **Family definitions cannot change after labels are observed.** The site-aware
   instance/family assignment is frozen at Stage 0; no re-clustering post-label.

## Artifacts

| file | role | mutable? |
|------|------|----------|
| `study/instances.jsonl` | Stage-0 case instances (immutable) | frozen, never edited |
| `study/stage1_labeling_packet.jsonl` | blinded evidence packet, one row per instance | frozen input to review |
| `study/stage1_labels.jsonl` | **sidecar** — one label row per instance | written during review, frozen after |

Labels join to the manifest by `instance_id`.

## Sidecar schema (`study/stage1_labels.jsonl`)

The primary evaluates an **evidence-relative decision**, not the code's real
vulnerability status, so every label record preserves three distinct answers:

    instance_id                   # joins to study/instances.jsonl (opaque)
    packet_supported_conclusion   # safe | vulnerable | unresolved   <-- SCORED by the primary
    program_outcome               # safe | vulnerable | not_established  (reported SEPARATELY)
    relationship_answer           # established | contradicted | unresolved
    evidence_basis                # capacity / write_length / guard / reachability /
                                  #   cross_revision_diff  (one or more)
    reviewer_id                   # who assigned it
    reviewer_confidence           # high | medium | low
    review_status                 # primary | adjudicated | verified

- **`packet_supported_conclusion` is what the primary three-class macro recall
  scores.** A model that correctly guesses "vulnerable" *without sufficient packet
  evidence* is marked **wrong** for this evidence-relative task (and may draw an
  unsupported-assumption finding). This is intentional: the study evaluates
  calibrated reasoning from supplied evidence, not lucky guesses.
- **`program_outcome` is reported separately** (a scored × program cross-tab),
  **never scored**. This keeps "unresolved" a property of the *available evidence*,
  not a claim that the program's status is inherently undecidable.
- `relationship_answer` records whether the length/capacity relationship was
  established, contradicted, or left unresolved by the packet.

The file does not exist yet — Stage 1 has not run. It is created during review and
frozen (sha256 recorded) once labeling is complete.

## The blinded packet (`study/stage1_labeling_packet.jsonl`)

Mechanically constructed from **source only** by `build_labeling_packet.py` — no
model judgment, no prose summary. Per instance it carries:

- neutral `packet_instance_id` + `packet_family_id` (opaque hashes) and
  `sibling_instance_ids` so paired revisions can be compared;
- the **operation**: file, function, destination, write statement, line;
- **destination capacity evidence**: declared element type/count, capacity
  expression, and the declaration's source line;
- **write-length expression**;
- **enclosing guards**: the `if/for/while/switch` headers that brace-enclose the
  write (mechanical);
- **reachability evidence**: whether the function is `static`, and the list of call
  sites (file/line/text);
- the **enclosing function source**, recovered from the **CPG function line range**
  (parser-backed) for all 438/438 instances (`context_kind: cpg_function`); a regex
  span and a flagged ±25-line window remain as fallbacks in code but are unused.

**Excluded and asserted absent** (neutrality check fails the build if any appear):
V1/V2 routes, bucket names, `unresolved_property` / `uncertainty_bucket` /
`established_property`, `llm_eligible`, A/B/C outputs, `pre_patch`/`post_patch`/
`revision_side`, `stack_fixed_array`, and any generated summary.

**Accurate neutrality claim:** the packet contains **no explicit revision-side,
routing, bucket, model-condition, or outcome signal**. It does **not** claim the
outcome is unguessable: within a family the two revisions are shown as neutral
siblings, and a reviewer comparing paired source may see that one revision added a
guard or changed a length — that is legitimate review reasoning, not a leaked label.
What is prevented is the packet *asserting* which revision is the fix or what the
scanner concluded. Function context is CPG-backed (parser line ranges), so all 438
instances carry full enclosing-function source; the `window_fallback` path remains
in code for robustness but is currently unused (0/438).

## Review procedure

1. **Validate the packet on the development families** (106 dev instances) — confirm
   the evidence is sufficient and neutral before labeling at scale. (Build already
   asserts neutrality and reports 106/106 dev instances with full context.)
2. **Label every instance** on its own evidence. Reviewers may read source and patch
   context but must stay **blind to routing, buckets, and A/B/C outputs**, and must
   **not** assume a pre-patch-revision operation is `VULNERABLE` — the fix may touch a
   different operation.
3. Store labels in `study/stage1_labels.jsonl` (schema above).
4. **Freeze** the sidecar (record its sha256) once review is complete.
5. Report the **actual security-class distribution** in the already-frozen dev and
   confirmatory splits — do not rearrange families to manufacture `VULNERABLE` cases.
6. Check confirmatory power **without changing the split**.
7. Debug the A/B/C pipeline **only** on the 106 development instances.
8. Run the frozen A/B/C conditions **once** on the 332 confirmatory instances; score
   per instance with family-clustered uncertainty.

## Reviewer arrangement (disclosed honestly)

Preferred: **two independent security reviewers**, disagreements adjudicated by a
third pass; record `review_status` accordingly.

Fallback if two independent reviewers are impractical: a first review performed
**blind to routing and conditions**, then an **independent reviewer verifies every
`VULNERABLE` and `UNRESOLVED` label plus a random sample of `SAFE` labels**. Whichever
arrangement is used must be stated in the write-up, with reviewer identities and the
verified fraction.

**The model whose A/B/C responses this study scores must not assign these labels.**
That is why Stage 1 is a human/independent step and this repository ships only the
blinded packet and the empty sidecar schema — no labels.

## Scoring is already frozen (before labels exist)

All Stage-2 analysis decisions are pre-registered in `SCORING_PLAN.md` and
implemented in `scoring_harness.py`, which was **frozen against synthetic labels**
(`study/scoring_freeze/`: synthetic labels + A/B/C outputs, `expected_report.json`,
and `FROZEN.json` with sha256 of the harness, the plan, and the synthetic inputs).
The freeze run is deterministic and reproduces byte-identically, and it confirms the
harness recovers a built-in B>A effect (primary CI excludes 0). Stage 2 runs the
**identical** harness on the real `stage1_labels.jsonl` and real A/B/C prediction
files — no scoring parameter is chosen after real labels or outputs are visible.
