# Capability-effect accuracy study — Stage 0 (manifest, families, split)

Target population: the **498 operations** the stack-capacity capability newly made
LLM-eligible (v1 `additional_evidence_required` → v2 `semantic_relationship_review`).
This is the *capability-effect* population, per `ACCURACY_STUDY_PROTOCOL.md` §1.

**No LLM condition was run and no outcome label was assigned.** Stage 0 fixes the
sample so the confirmatory experiment cannot be tuned into existence later.

## Two levels — instance (labeled) vs family (clustered)

The unit that gets a ground-truth label and A/B/C responses is **not** the same as
the unit used for statistical clustering. Conflating them was wrong: a vulnerable and
a patched revision can share the same write statement while surrounding guards,
callers, or arithmetic differ — the RSA case is exactly that (textually similar sink,
different security meaning across revisions).

- **Case instance** — one operation in one source revision (vuln **or** patched).
  Ground truth and A/B/C responses belong here. Exact duplicates of the *same
  revision + site* across the E2/E4 scans collapse to one instance (verified by
  enclosing-function source hash). **Vulnerable and patched revisions are always
  separate instances**, even when textually identical.
- **Case family** — correlated instances of the same logical site across
  vulnerable/patched revisions and duplicate scans. Used **only** for the dev/
  confirmatory split and for statistical clustering. A family is **never split after
  labels are seen**; label disagreement between vuln and patched members is expected,
  not a defect.

## Counts

| level | count | notes |
|-------|------:|-------|
| operations | 498 | frozen fingerprints; = the transition-matrix semantic set (asserted) |
| **case instances (labeled units)** | **438** | 219 vulnerable + 219 patched |
| **case families (clusters)** | **214** | over-merge check asserted 0 |

Instances-per-family: **209 families → 2 instances** (one vuln, one patched; E2/E4
collapsed as identical revisions), **5 families → 4 instances** (E2 and E4 are
different revisions of that site, so they stay separate on one or both sides).
209·2 + 5·4 = 438.

The 498 operations are **not** 498 independent observations, and 214 is **not** the
sample size either — it is the number of correlation clusters. The labeled units are
the **438 instances**; the clustering unit is the **214 families**.

## Family clustering key

`content_key = (file, function[normalized], dest, element_type, element_count,
capacity_expr, width_expr)` + the **site-ordinal** of that write among same-content
writes within each (scan, side), scan-guarded where E2/E4 write-counts differ. This
collapses copies but never merges distinct call sites (asserted). Sensitivity bounds
from the earlier keyings: content-only 177 (over-merges), content+line 235 (splits
line-shifted pairs); the ordinal key's 214 sits between.

## Vuln↔patched pairing is verified, not assumed

"No over-merge" does not prove the vulnerable site was matched to the *correct*
patched site — an added or removed write shifts every later ordinal. Each family's
pairing is checked with a source anchor:

| pairing verdict | families | basis |
|-----------------|---------:|-------|
| unambiguous_single_write | 159 | only one same-content write per side → the pair is forced |
| stmt_anchor_matched | 55 | multi-write site; ordinal-aligned vuln/patched **write statements match by source text** in every scan |
| **unverified → excluded** | **0** | would be excluded from confirmatory rather than guessed |

All 55 multi-write families (the only ones exposed to ordinal shift) were confirmed;
none required exclusion. Every family has both a vulnerable and a patched side
present (checked). Any future family that cannot be verified is marked
`excluded_unverified` and kept out of the confirmatory set.

## Family-level outcome rule (corrected)

1. **Ground truth is per case instance**, not per family.
2. **Run and score A/B/C per instance.** Aggregate to uncertainty with
   **family-clustered** confidence intervals (clustered bootstrap or a mixed-effects
   model), so correlated instances do not inflate significance.
3. **A family is never split after labels are seen.** Vuln/patched label disagreement
   within a family is expected.
4. Whole families stay entirely within dev or confirmatory (no leakage).

## Frozen development / confirmatory split (`study/split.json`)

Split **by family**, deterministically
(`sha256("capeffect-498-v2|"+family_id) mod 10000 < 3000 → dev`):

| | families (clusters) | instances (labeled units) |
|--|--------------------:|--------------------------:|
| development | 52 | 106 |
| **confirmatory (held out)** | **162** | **332** (166 vuln + 166 patched) |
| excluded (unverified pairing) | 0 | 0 |

Verified: no family and no instance shared between dev and confirmatory. Dev is for
prompt/parsing/scoring debugging only; confirmatory is run once.
`study/FROZEN.json` records the sha256 of the op manifest, instances, families, and
split — the sample is immutable.

## Independent sample size and power

- **Clusters** in the confirmatory set: **162 families**.
- **Labeled units**: **332 instances** (166 vulnerable-revision + 166
  patched-revision) — but these cluster within the 162 families, so the effective n
  for significance is nearer the cluster count than 332.
- The binding constraint is still unknown until blinded labeling: **how many
  instances are genuinely vulnerable** (a patched-side instance is usually safe; a
  vuln-side instance is only vulnerable if this specific operation carries the bug).
  Many of these are safe capacity-bound crypto copies, so the genuinely-vulnerable
  count is likely well below 166.
- Therefore, after labeling: report the class base rate first; report **balanced /
  macro accuracy and per-class results**, or reweight to prevalence, never raw
  accuracy over a class-enriched sample; and if the genuinely-vulnerable cluster
  count is too small to power a paired A/B/C test, report descriptively rather than
  splitting copies to manufacture n.

## Not done here (by design)

No LLM condition (A/B/C), no outcome label, no prompt. Stage 0 delivers only the
frozen two-level sample and its independence + pairing audit. Next stage establishes
ground truth per instance, independently and blinded to condition and to V1/V2
routing, using the development set only for debugging.
