# Capability-effect accuracy study — Stage 0 (manifest, families, split)

Target population: the **498 operations** the stack-capacity capability newly made
LLM-eligible (v1 `additional_evidence_required` → v2 `semantic_relationship_review`).
This is the *capability-effect* population, per `ACCURACY_STUDY_PROTOCOL.md` §1 —
not all v2 LLM-eligible operations.

**No LLM condition was run and no outcome label was assigned.** This stage fixes the
sample so the confirmatory experiment cannot be tuned into existence later.

## Manifest (`study/study_manifest.jsonl`)

498 immutable rows, one per operation. Each carries an immutable `op_id` (the frozen
`build_frozen_corpus._fingerprint` over `source_label|file|function|line|dest`),
source location (file, function, line, dest), the stack-capacity evidence
(element type, count, capacity expr, width, unresolved property), and the v1→v2
route pair. No model output, no label.

Audited: all 498 `op_id`s distinct, and the set is **identical** to the
`semantic_relationship_review` transitions in `transition_matrix_v1_v2.json`
(asserted, symmetric-difference 0).

## Independent case families (`study/families.json`)

The unit of independence is the underlying source operation, not the record. Copies
of one operation — across vuln/patched, across the E2/E4 scans that both include
freebl, and across macro/line duplication — must share one family.

**Primary family key = content-key + site-ordinal within each (scan, side):**
`(file, function[normalized], dest, element_type, element_count, capacity_expr,
width_expr)` plus the ordinal of that write among same-content writes in the same
scan/side (ordered by line). The k-th write matches the k-th across scans/sides, so:

- copies collapse (a patch that shifts line numbers does **not** split a vuln/patched
  pair — matched by ordinal, not absolute line);
- **distinct call sites never merge** — over-merge check (any family holding >1 line
  within a single scan/side) is **0, asserted in code**;
- **scan guard:** 5 content-groups have different write-counts across E2 vs E4 (the
  scans captured different coverage). For those, cross-scan ordinal alignment is not
  1:1, so the key is not merged across scans (vuln/patched, always consistent, still
  merge). Those families are flagged `write_count_consistent_across_sides=false`.

### Result — 214 independent families

| | families |
|--|---------:|
| **primary (content + scan-guarded ordinal)** | **214** |
| sensitivity: content-only (over-merges distinct sites) | 177 (lower bound) |
| sensitivity: content + line (splits line-shifted pairs) | 235 (upper bound) |

Size distribution (primary): **179 families of size 2** (one vuln/patched pair) and
**35 of size 4** (E2/E4 × vuln/patched). 179·2 + 35·4 = 498. No singletons, no giant
families — the content-only key's 16- and 14-member blobs (`CTS_DecryptUpdate`,
`sftk_InitCBCMac`) were distinct call sites it wrongly merged; the ordinal key
separates them.

The independent sample size is therefore **214**, not 498 — a **2.3× reduction**;
treating the 498 operations as independent would have overstated n by that factor.

## Family-level outcome rule

1. **Ground truth is per family.** Members are copies of one operation, so a family
   has one true outcome ∈ {safe, vulnerable, genuinely-unresolved}. At labeling time
   (blinded), if any family's members receive *different* labels, that family is
   split before analysis — the 5 scan-guard-flagged families are the pre-identified
   candidates for this check.
2. **A condition is scored once per family.** Primary: run the condition on the
   family's `representative_op_id` (lowest scan/side then line). If a condition is
   instead run on every member, the family verdict is the **majority** of member
   judgments; an exact tie collapses to `abstain`. Per-family result ∈
   {correct, incorrect, abstain} versus the family ground truth.
3. **Analysis is at the family level, clustered by family** — never per operation —
   so within-family copies cannot inflate n or significance.

## Frozen development / confirmatory split (`study/split.json`)

Split **by family, never by operation**, deterministically:
`bucket = sha256("capeffect-498-v1|" + family_id) mod 10000 < 3000 → dev`.

| | families | operations |
|--|---------:|-----------:|
| development | 60 | 146 |
| **confirmatory (held out)** | **154** | 352 |

Verified: 0 families and 0 operations shared between dev and confirmatory. The
development set is for prompt / parsing / scoring debugging only (§7); the
confirmatory set is run once (§8).

Freeze record `study/FROZEN.json` stores the sha256 of the manifest, families, and
split files, plus the split parameters — the sample is now immutable.

## Independent sample size and power

The real independent n is **214 families** (154 in the confirmatory set). That is the
**ceiling**, not the effective power. The binding constraint is unknown until blinded
labeling: **how many families are genuinely vulnerable.** These are predominantly
crypto buffer copies whose capacity is bound and whose length relationship is merely
unresolved (many are safe self-referential copies such as `memcpy(iv, …, sizeof(iv))`),
so the vulnerable class is likely small. Consequences to carry into Stage 1+:

- Report the class base rate (safe / vulnerable / unresolved) among the 214 families
  **before** interpreting any accuracy number.
- Because a balanced design over a rare vulnerable class is what powers the test,
  report **balanced / macro accuracy and per-class results**, or reweight to
  prevalence — never raw accuracy over an enriched sample (§5).
- If the confirmatory vulnerable-family count is too small for a paired A/B/C test to
  detect a plausible effect, say so and treat the result as descriptive; do not
  manufacture power by splitting copies back apart.

## Not done here (by design)

No LLM condition (A/B/C) was run; no outcome label was assigned; no prompt was
written. Stage 0 delivers only the frozen sample and its independent-n audit. The
next stage establishes ground truth independently and blinded to condition and to
V1/V2 routing (`ACCURACY_STUDY_PROTOCOL.md` §4, §6), using the development set only
for debugging.
