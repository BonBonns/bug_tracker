# The frozen neutral reference packet

A/B/C do **not** contain identical evidence: **A** sees code only, while **B** and
**C** additionally receive the established scanner facts (B and C share byte-identical
facts; they differ only in presentation — B's uncertainty bucket vs C's focused
question). So a per-instance "packet-supported conclusion" would be ambiguous: it
would silently correspond to one condition's packet, and scoring A/B/C against
different targets would make their accuracies incomparable.

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
- **B-vs-C is especially clean:** B and C contain byte-identical established facts, so
  a B−C difference isolates presentation (bucket vs focused question) with the
  evidence held constant.
- **A** has strictly less evidence (code only); an A−B/A−C gap conflates added
  evidence with presentation, and is read accordingly.

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
