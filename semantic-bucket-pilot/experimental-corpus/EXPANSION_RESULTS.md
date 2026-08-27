# Expansion results: the scarcity is a method property, not a tooling gap

Joern 4.0.608 installed successfully, reproduces frozen-compatible facts, and
scanned five **pre-registered** (SELECTION.md), diverse, disclosed NSS
memory-safety CVEs through the unchanged frozen v1 scanner. The result settles
the feasibility question the corpus expansion was meant to answer.

## What the frozen scanner did with 5 fresh disclosed CVE sites

| family | disclosed CVE site | module | CVE-site LLM-routable? | vuln≠patched differential? |
|--------|--------------------|--------|------------------------|----------------------------|
| E1 Bug 1869493 AES Keywrap | `sftk_CryptInit` | softoken | **no (miss)** | no |
| E2 Bug 1835425 RSA input overflow | `rsa_FormatOneBlock` | freebl | yes (3 writes) | no (stable uncertainty) |
| E3 Bug 1396616 UTF-8 overrun | `nssUTF8_Length` | base | **no (miss)** | no |
| E4 Bug 2026311 PSS overflow | `RSA_EMSAEncodePSS` | freebl | **no (miss)** | no |
| E5 Bug 2028954 AVA buffer sizing | `CERT_DecodeAVAValue` | certdb | **no (miss)** | no |

- **CVE-site scanner misses: 4 / 5.**
- **CVE-site LLM-routable: 1 / 5** (`rsa_FormatOneBlock`).
- **CVE-site vuln≠patched routable differential: 0 / 5.**
- Incidental routable candidates surfaced by the whole-module scans: **116**
  (two buckets: `relationship_unresolved`, `external_contract_unknown`) — real
  code, but not the disclosed bugs, and overwhelmingly `vuln == patched`.

## Why (verified against source)

Disclosed memory-safety fixes are predominantly **guard / length-check
additions**, and the guard usually lives in a *caller* or in bounds arithmetic
the scanner does not evaluate — while the *write* the scanner recognizes is
unchanged across the fix. So:

- 4/5 sites are shapes the scanner does not recognize as capacity-relationship
  buffer writes at all (keywrap length calc, UTF-8 counting, PSS/EMSA sizing,
  AVA output sizing) → **misses**.
- The 1/5 it does recognize (`rsa_FormatOneBlock`) it flags **identically in
  both revisions**: E2's real bug is an unsigned `modulusLen` underflow in the
  caller `rsa_FormatBlock` (`data->len > modulusLen - (3+RSA_BLOCK_MIN_PAD_LEN)`
  underflows); vuln is genuinely vulnerable, patched adds the missing
  `modulusLen < 3+RSA_BLOCK_MIN_PAD_LEN` guard — but the *write* in
  `rsa_FormatOneBlock` is the same, so the scanner stays `relationship_unresolved`
  on both. Same bucket, different truth.

## Consequence for the confirmatory A/B/C experiment

The genuine, verified-**vulnerable**, LLM-**routable** pool across ALL data
(original corpus + this expansion) is essentially two independent functions:

- `rsa_FormatOneBlock` — vulnerable in CVE-2019-17006 (padLen signedness) and,
  at a later revision, in Bug 1835425 (modulusLen underflow). Two distinct bugs,
  **same function** — the guidance forbids counting variations of one function
  as independent cases.
- the mozjpeg `encode_one_block`/`flush_bits` buffer (BUFSIZE).

That is below the ≥3 independent vulnerable cases (multiple shapes, not
variations of one function) a powered accuracy comparison requires — and,
critically, this is **not** a tooling limitation: Joern worked, the pipeline
reproduces the frozen facts, and five diverse fresh CVEs were scanned. The
shortage is a genuine property: **the frozen scanner's LLM-routable uncertainty
rarely coincides with the actual disclosed vulnerability.**

## Decision (matches the pre-authorized fallback, now on firmer ground)

Do not fabricate a balanced corpus. The defensible results are:

1. **The A/B/C harness is validated** (mechanics dry run + frozen prompt
   generator v2), but the frozen scanner does not supply enough independently
   grounded, LLM-routable vulnerable case families for a powered accuracy claim.
2. **The scarcity itself is a primary empirical finding**: over 5 fresh
   disclosed CVEs, the scanner routes the true bug site to LLM review in 1/5
   cases and to nothing (miss) in 4/5 — it more often needs deterministic
   recognition/repair or additional evidence than semantic LLM review.
3. **The routing evaluation over all records becomes the primary empirical
   result** (built next), characterizing where the frozen scanner actually
   sends real operations.

The A/B/C machinery remains ready: if a future corpus (more repos, shapes, or a
scanner that recognizes more sites) supplies ≥3/3/3 independently-verified
routable families, the frozen generator v2 + dry-run harness run it unchanged.
