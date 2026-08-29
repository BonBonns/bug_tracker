# Held-out confirmatory result (one-time run)

**Scope (stated plainly):** the pooled corpus is **258 vulnerable sites, 0 non-vulnerable**, so
this measures **vulnerable-site recognition / coverage**, NOT precision, false-positive rate, or
overall accuracy. The 101 non-vulnerable SecVulEval sites remain a separate future specificity
experiment. SecVulEval results are **recognition from frozen FUNCTION-LEVEL source packets**
(reconstructed `func_body`, sha-verified), not full-repository scanner recall — missing headers,
declarations, macros, callers, and build config can lose evidence.

Provenance: scanner implementation `544a606`, evaluation harness `dbcc4c80`, Joern/c2cpg 4.0.608.
Runner hash `24f1ad35…` verified identical at launch, in the harness commit, in the manifest, and
after completion. **Not perfectly blind** — see `PROTOCOL_DEVIATION.md` (8 sites pre-exposed).
See `RUN_MANIFEST.json` for all pinned hashes and the timing disclosure. Raw archived first:
`raw_sites.jsonl` (sha `ba413dea…`), then the frozen summarizer run exactly once.

## Harness correction (see study/heldout_correction/CORRECTION.md)

A post-hoc audit found the runner loaded the **heap-only V1** runtime-capacity producer
(`oob_runtime_capacity_verdict`) instead of the intended **V2 stack-capacity integration**
(`oob_runtime_capacity_v2`, declared in the manifest). Because V2 only *enriches* V1's already-
recognized operations (it forms no new ones), the **recognition count is unchanged: 4/118 vuln,
7/143 combined stand**. One of the 7 recognized dispositions is corrected — `evutil_parse_sockaddr_port`
upgrades from `required_evidence_absent` to `relationship_unresolved` (capacity `buf[128]`
established, length symbolic). Still **0 deterministic verdicts** under either producer. The
harness is fixed; the scanner (V2 byte-identical to the frozen commit) was never changed.

## Two measurements

### PRIMARY / FULL — all 258 pooled sites, 42 families

Funnel (function-level packets): source available **175**, build/parse OK **175**, labeled write
mapped into CPG **118**, physical site recognized **4**, capacity/contract evidence established
**0**.

- **(A) End-to-end coverage = 4 / 258 = 1.55 %.** Pipeline-unrecovered = 140 (83 metadata-only
  PostCutoff/BigVul/ARVO sites + 57 SecVulEval labeled writes that did not map into the CPG).
- **(B) Conditional scanner recall = 4 / 118 = 3.39 %** (denominator = labeled sites mapped into
  a CPG).
- **Macro family recall:** strict (mean over all 42 families of recognized/all) = **5.26 %**;
  conditional (over families with mapped sites, recognized/mapped) = **9.31 %**.
- **Family coverage (≥1 site recognized — coverage, not recall):** 4/42 of all families; 4/27 of
  families that reached the scanner.
- **Identity reconciliation:** raw recognized records **47** ≥ identity-bearing **47** ≥ unique
  physical operations **40** (identity_unverifiable **0**). Chain holds. (These 40 distinct
  recognized operations span all writes in the bodies; only 4 coincide with a labeled vuln site.)

All **4** recognized labeled sites resolved to **relationship = missing** — the producer
recognized the write operation but the required capacity/contract evidence was **absent** in the
function packet, so it **abstained** (`required_evidence_absent`). **Zero observed unsupported
safe promotions at labeled vulnerable sites**: none of the 4 recognized vulnerable writes was
promoted to `deterministic_complete` (nor to `proven_oversized`). This is a statement about these
4 recognized labeled sites only — NOT a general "no false safes" claim.

**Framing of the two numbers (neither is vulnerability-detection accuracy):**
- **4/258 (1.55 %) is end-to-end artifact/pipeline coverage** — how many labeled vulnerable
  operations the whole pipeline reaches and recognizes, dominated by source-packaging and
  CPG-mapping attrition.
- **4/118 (3.39 %) is conditional scanner recognition** — recognition rate after source
  reconstruction and CPG mapping succeed.
- Neither measures whether the scanner correctly decides vulnerable-vs-safe.

| recognized labeled site        | write_kind    | family            | producer(s)                                   |
|--------------------------------|---------------|-------------------|-----------------------------------------------|
| `evutil_parse_sockaddr_port`   | copy_sink     | fam_27ca4337511d  | runtime_capacity                              |
| `msg_parse_fetch`              | pointer_deref | fam_42418a7cbf67* | cursor_write                                  |
| `blosc_c`                      | copy_sink     | fam_0d230c8e7c0a  | interprocedural + runtime_capacity            |
| `enc_untrusted_recvfrom`       | copy_sink     | fam_b41a25fd581c  | interprocedural + runtime_capacity            |

`*` `msg_parse_fetch` is in an exposed family, which is why the sensitivity analysis shows 3
recognized instead of 4.

**Scanner misses (mapped but not recognized), by labeled write_kind:** pointer_deref 75,
copy_sink 26, index_write 13 (114 total). **Built-but-unmapped (stage-3 pipeline attrition):** 57
(pointer_deref 32, copy_sink 14, index_write 11) — labeled writes such as pointer declarations
and macro-expanded lines with no matching CPG node in the function packet.

### SECONDARY / SENSITIVITY — exclude the 8 exposed sites and their 6 whole families

This is a sensitivity check, **not** a replacement denominator. Excluding the 6 exposed families
(dominated by the generic `pointer_deref|unknown|deref` family) removes 150 sites → 108 sites, 36
families.

- (A) End-to-end coverage = **3 / 108 = 2.78 %**; (B) conditional recall = **3 / 39 = 7.69 %**.
- Macro family recall: strict **6.11 %**, conditional **11.90 %**. Family coverage 3/36 (all),
  3/21 (reached scanner). Identity chain: raw 16 ≥ id-bearing 16 ≥ unique 12.

The low-coverage regime is unchanged when the exposed material is removed (conditional recall
moves 3.4 % → 7.7 % only because the excluded families were the hardest, generic pointer-deref
sites). The conclusion does not depend on the exposed sites.

## Protocol deviation disclosure

The run is not blind. Eight SecVulEval sites (first 8 in pooled order) were exposed during runner
validation; two were hand-inspected. **All eight exposed cases were misses** (0 recognized
records); one (`psi_write`) additionally **failed CPG mapping** (stage-3 attrition). No
capability, producer, normalizer, exporter, or identity module changed (empty `git diff
544a606 HEAD` over all scanner files; manifest hashes match). Full detail in
`PROTOCOL_DEVIATION.md`.

Note: the summarizer's console header prints "5 sites pre-exposed" — a stale string; the
executed analysis correctly excluded **8 sites / 6 families** (see the SECONDARY block and
`PROTOCOL_DEVIATION.md`, which are authoritative). The frozen summarizer was not re-edited or
re-run after the result was seen.

## Negative generalization result

This is a **meaningful negative generalization result**: the frozen scanner barely reaches the
labeled vulnerable operations outside its development distributions. Capabilities 1–4 passed
their synthetic and development gates but **did not generalize broadly** to these function-level
held-out vulnerability sites. Crucially, **the main failure precedes semantic reasoning** — it is
missing source packaging (83), failed target mapping (57), unsupported write representations (114
of 118 mapped writes fell outside the modeled forms), and missing capacity/contract evidence
(0/4 recognized). The 40 unique recognized operations vs 4 labeled matches is telling: the
scanner recognized writes *inside* these functions, just usually **not the vulnerable one**.

This is **low coverage under the frozen scanner's deliberately narrow modeled domain** — not
"low coverage by design" as a virtue. No conclusion here concerns precision, false-positive rate,
or vulnerability-detection accuracy.

## Consequence: this corpus is now consumed

These 258 sites have been used as a confirmatory generalization measurement. Their misses may be
analyzed, but **any scanner change motivated by them turns these 258 sites into development
data** — a NEW, unseen corpus would be required for another confirmatory generalization claim.
Before any such development, the best remaining frozen measurement is the separately preserved
**101 non-vulnerable mapped SecVulEval sites** (a specificity / soundness experiment run with the
UNCHANGED scanner), which is being run next.

## One-line reading

On a frozen, vulnerable-only held-out corpus, the sound narrow scanner **recognizes 4 of 118
CPG-mapped vulnerable write sites (3.4 %), reaches only 4 of 258 end-to-end (1.6 %), and made
zero observed unsupported safe promotions at those 4 sites** — low coverage under a deliberately
narrow modeled domain, with the dominant losses upstream of any semantic reasoning. A coverage
measurement, not accuracy or false-positive rate.
