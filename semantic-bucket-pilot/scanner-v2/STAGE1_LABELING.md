# Stage 1 — blinded security labeling (sidecar, not a manifest mutation)

Stage 0 defines which cases exist (`study/instances.jsonl`, immutable). Stage 1
independently defines what happened. **Neither artifact rewrites the other.** Labels
are never written back into the frozen instance manifest; they live in a separate
sidecar and are frozen separately after review.

## Artifacts

| file | role | mutable? |
|------|------|----------|
| `study/instances.jsonl` | Stage-0 case instances (immutable) | frozen, never edited |
| `study/stage1_labeling_packet.jsonl` | blinded evidence packet, one row per instance | frozen input to review |
| `study/stage1_labels.jsonl` | **sidecar** — one label row per instance | written during review, frozen after |

Labels join to the manifest by `instance_id`.

## Sidecar schema (`study/stage1_labels.jsonl`)

One row per case instance:

    instance_id          # joins to study/instances.jsonl (opaque; no revision encoding)
    stage1_label         # VULNERABLE | SAFE | UNRESOLVED
    evidence_basis       # which evidence drove it: capacity / write_length / guard /
                         #   reachability / cross_revision_diff  (one or more)
    reviewer_id          # who assigned it
    reviewer_confidence  # high | medium | low
    review_status        # primary | adjudicated | verified

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
- the **enclosing function source** (430/438) or a flagged ±25-line
  `window_fallback` (8/438, where a macro/K&R definition could not be isolated —
  the reviewer widens from the file if needed).

**Excluded and asserted absent** (neutrality check fails the build if any appear):
V1/V2 routes, bucket names, `unresolved_property` / `uncertainty_bucket` /
`established_property`, `llm_eligible`, A/B/C outputs, `pre_patch`/`post_patch`/
`revision_side`, `stack_fixed_array`, and any generated summary. Within a family the
two revisions are shown as neutral siblings; the packet never says which is the fix.

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
