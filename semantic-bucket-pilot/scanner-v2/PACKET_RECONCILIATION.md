# Packet reconciliation — 498 operations vs 438 case instances

Stage 0 froze **498 operation records**; the labeling packet has **438 case
instances**. This documents the **60**-record difference exactly.

## Accounting (closes)

| | count |
|--|------:|
| operation records (study_manifest.jsonl) | 498 |
| case instances (instances.jsonl) | 438 |
| **collapsed records** | **60** |
| instances holding >1 operation | 60 |
| extra records merged into them (Σ size−1) | 60 |

Every operation maps to exactly one instance (checked: 0 duplicates, op sets equal).
Instance size histogram (ops per instance): {1: 378, 2: 60}.

## What the 60 collapses are

Under the frozen instance rule (`build_family_manifest.py`), operations collapse to
one instance only when they are the **same source revision at the same site** —
tested by the **enclosing-function source hash** — within one family and one
revision side. In this corpus every collapse is an **E2/E4 duplicate scan of an
identical revision**:

| collapse type | count |
|---------------|------:|
| same revision side, different scan (E2/E4 duplicate) | 60 |
| same side, same scan (other) | 0 |
| **crosses pre-patch / post-patch** | **0** |

Scan pairs among the collapses: {'E2+E4': 60}.

## Confirmations

- **No collapse crosses pre-patch/post-patch** (asserted 0). Pre- and post-patch
  operations always remain separate instances, so no outcome-relevant merge occurs.
- The collapse key is the **enclosing-function source hash**, computed from source
  text — **no label or outcome information** is used (labels do not exist at Stage 0).
- The 60 merged records are redundant duplicate-scan observations of the
  same code; dropping them from the labeling count removes duplication, not cases.

So 498 → 438 is fully explained: 60 same-revision duplicate-scan records
collapse; 438 independent case instances remain for labeling.
