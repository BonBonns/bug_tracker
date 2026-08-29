# Held-out corpus funnel (FROZEN)

Reconciles the pooled held-out denominator. Derived entirely from the frozen manifests
(`study/{postcutoff,bigvul,arvo,secvuleval_full}/FROZEN_heldout.json`,
`study/pooled/FROZEN_heldout_pooled.json`); no rule re-run, no yield inspected.

## Why 258 pooled, not 280

The full SecVulEval run produced **280 mapped** sites — but 280 is a MAPPED count that
includes non-vulnerable sites, whereas the pool takes **mapped AND vulnerable** only (the
pre-registered rule, PREREGISTER_SECVULEVAL_FULL.md). Pooling did not reduce a source below
itself; it added the vulnerable subclass of each source. Breakdown:

| Source          | mapped | vulnerable | non-vulnerable | pooled (vuln, post-dedup) |
|-----------------|-------:|-----------:|---------------:|--------------------------:|
| PostCutoff-CVE  |     21 |         21 |              0 |                        21 |
| Big-Vul (MSR20) |     11 |         11 |              0 |                        11 |
| ARVO            |     51 |         51 |              0 |                        51 |
| SecVulEval-full |    280 |        179 |            101 |                       175 |
| **Pool**        |        |            |                |                   **258** |

- PostCutoff / Big-Vul / ARVO are vulnerability-fix corpora: every mapped site is
  vulnerable (0 non-vulnerable), so their mapped == vulnerable == pooled.
- SecVulEval-full: 280 mapped = **179 vulnerable + 101 non-vulnerable**. Only the 179
  vulnerable are pool-eligible.

## Cross-source duplicates removed (at pooling)

Pre-registered dedup keys: CVE; (project, fix commit); identical diff_sha256; Magma
projects excluded at inclusion. Drops:
- PostCutoff: 0
- Big-Vul: 0
- ARVO: 0
- SecVulEval-full: **4** (dup_cve — CVE overlap with Big-Vul/PostCutoff). 179 − 4 = 175.

## Exclusions AFTER mapping (per source, not pooled)

- SecVulEval-full: **101 non-vulnerable mapped** sites are EXCLUDED from the pool by the
  vulnerable-only rule. They remain recorded in `study/secvuleval_full/FROZEN_heldout.json`
  (mapping_status=mapped, is_vulnerable=false) but do not enter the pool.
- Ambiguous / no_write_found sites are excluded at mapping in every source and are NOT in
  these mapped counts (e.g. SecVulEval-full: 684 ambiguous / 829 no_write_found excluded
  before the 280 mapped; ARVO 348/65; Big-Vul 22/29; PostCutoff 34/57).

## Final 258 composition (all vulnerable)

    postcutoff       21
    bigvul           11
    arvo             51
    secvuleval_full 175
    ----------------------
    total           258   (21 + 11 + 51 + 175)

Every pooled site is vulnerable (`is_vulnerable == true` for all 258; confirmed).

## 42-family composition (distinct proof-obligation families)

    from PostCutoff              9
    new via Big-Vul             +2
    new via ARVO                +8
    new via SecVulEval-full    +23
    ---------------------------
    distinct pooled families    42   (>= 12-family power gate)

## What the held-out set measures — stated plainly

The pooled held-out corpus is **VULNERABLE-ONLY** (258 vulnerable sites, 0 non-vulnerable).
The confirmatory held-out evaluation therefore measures **vulnerable-site
recognition / recall** — whether the scanner recognizes and correctly routes a known
vulnerable write site. It does **NOT** measure overall accuracy or false-positive behavior,
because it contains no negative (non-vulnerable) sites.

If false-positive / specificity measurement is wanted later, a negative set is already
available and frozen: the **101 non-vulnerable mapped SecVulEval sites** (in the SecVulEval
slice manifest, excluded from the pool). Using them would be a separate, separately
pre-registered evaluation; they are NOT part of the current pooled corpus and remain
uninspected.
