# The frozen neutral reference packet

A/B/C do **not** contain identical evidence: **A** sees code only; **B** and **C**
additionally receive the established scanner facts. B and C share **byte-identical**
facts and differ only in presentation — **B** presents them with generic review,
**C** through the bucket-guided interface (typed category **and** focused question).
So a per-instance "packet-supported conclusion" would be ambiguous: it would silently
correspond to one condition's packet, and scoring A/B/C against different targets
would make their accuracies incomparable.

**Fix: one fixed reference target.** The primary scores every condition against a
single `evidence_reference_conclusion` per instance, derived by the Stage-1
reviewers from a **neutral reference packet** that is the common evidence floor.

## What the neutral reference packet contains

The reference packet is the blinded labeling packet already built and frozen,
`study/stage1_labeling_packet.jsonl` (`build_labeling_packet.py`). Per instance it
contains, mechanically from source:

- the **code context** shared by all conditions (enclosing function source, the
  operation, destination declaration);
- the **established scanner facts shared by B and C** (destination capacity, write-
  length expression, enclosing guards, reachability evidence).

## What it deliberately excludes

- **no uncertainty bucket** (B-specific presentation);
- **no focused C question** (C-specific presentation);
- **no condition identifier** (A/B/C);
- no routes, bucket names, scanner conclusions, or model output (neutrality check in
  `build_labeling_packet.py`, independently re-scanned: 0 forbidden tokens).

So the reference packet is exactly `code ∪ established-facts-shared-by-B-and-C`,
stripped of anything only one condition receives. Labeling
`evidence_reference_conclusion` against it asks: *what conclusion does the frozen
common evidence support?*

## How the conditions are scored against it

- **Accuracy target: fixed across A/B/C.** All three are scored on
  `evidence_reference_conclusion`. The question each condition answers is whether its
  *presentation* helps the model reach the conclusion the common evidence supports.
- **C−B is the primary and is especially clean:** B and C contain byte-identical
  established facts, so the difference isolates presentation with the evidence held
  constant. **But C adds both** the typed category **and** the focused question, so
  `C − B` tests the **combined routing-and-questioning interface**, not the bucket
  label alone. No B−C difference may be attributed specifically to the label;
  separating label from question would need a fourth arm.
- **A** has strictly less evidence (code only); `B − A` measures the value of the
  established facts under generic review, and `C − A` the combined effect. Neither
  isolates presentation.

## Established facts are independently validated

A scanner-emitted fact is not ground truth merely because it appears in the packet.
Stage 1 records `established_facts_valid ∈ {valid, invalid, unresolved}`. If a
load-bearing fact is **invalid**, the reference conclusion is **not** built by
treating it as true — the packet is marked invalid, **excluded from the A/B/C
analysis**, and reported separately as an upstream evidence error. If validity is
**unresolved**, the reference conclusion is normally `unresolved` unless it follows
without that fact.

## Condition-relative exception: unsupported-assumption adjudication

The **accuracy target** is fixed, but the **unsupported-assumption** metric is
**condition-relative** (`UNSUPPORTED_ASSUMPTION_RUBRIC.md`): an assumption may be
*supported* in B/C by an established fact yet *unsupported* in A, which never received
that fact. So that metric is adjudicated against the evidence **actually supplied to
that condition**, not against the reference packet.

## Freeze

The reference packet is `study/stage1_labeling_packet.jsonl`; its sha256 is recorded
in `study/reference_packet_FROZEN.json`. It is frozen before Stage 1 and is not
revised after labels or model outputs are seen.
