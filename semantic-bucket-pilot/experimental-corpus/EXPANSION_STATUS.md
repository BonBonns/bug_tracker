# Step 2 (corpus expansion) — status and blocker

Step 1 (mechanics dry run) is complete and validated. Step 2 is enlarging the
routable pool by scanning more disclosed CVEs through the **unchanged** frozen
v1 scanner. Current status:

## Environmental blocker: no Joern in this session

Generating fact files for **new** disclosed CVEs requires the joern-c2cpg
frontend (v4.0.608, per the toolchain). It is **not installed** in this
environment (`JOERN_HOME` unset, no `c2cpg.sh` on disk), and the moz-canon gate
skips for the same reason. So new CVE scans cannot be produced here without
first installing Joern (a large JVM toolchain, feasibility uncertain behind the
proxy) or generating the fact files in a Joern-capable environment.

## What cached data can and cannot add (no Joern needed)

| cached input | routable (llm-eligible) candidates | provenance | note |
|--------------|-----------------------------------|-----------|------|
| `cve-2017-ugly-split` (NSS bug 1418780, h_page.c) | **0** | disclosed CVE pair | scanner ABSTAINS (required_evidence_absent → additional_evidence_required). A scarcity result, not a routable case. |
| `nss-ssl-scan` | 6 | rev `1de60067…` (pinned) | TLS 1.3 AEAD, ECDH — new shapes/areas, but a single revision, NOT a vuln/patched CVE pair |
| `nss-crypto-scan` | 13 | **UNVERSIONED** | HMAC, PSS, exptmod, a 2nd `unknown_allocator_contract`; single revision, no CVE pairing, unknown exact revision |
| `mozjpeg-scan`, `mozjpeg-decoder-scan` | 0 | — | no routable candidates |

So the 7th cached **disclosed-CVE pair** adds nothing routable — itself an
informative result (the scanner needs evidence-repair there, not LLM review,
exactly as anticipated). The ~19 additional candidates that DO exist come from
**non-paired module scans**: real NSS code with verifiable outcomes and genuine
bucket/shape diversity, but not disclosed vuln/patched differentials, and one of
the two sources is of unknown revision.

## Decision needed before proceeding

The prior instruction was to expand via *disclosed CVEs*. The environment blocks
new CVE scans, and the only cached disclosed-CVE pair left is non-routable.
Expanding from here means one of:

1. **Install Joern here** and scan fresh disclosed CVEs (large download,
   uncertain behind the proxy) — stays closest to the disclosed-CVE design.
2. **Generate fact files in a Joern-capable environment** and bring them back —
   same design, different machine.
3. **Mine the cached NSS module scans** (nss-ssl pinned; nss-crypto unversioned)
   as independently-verified single-revision cases — available now, adds bucket
   diversity, but weaker grounding (no patch differential; one unknown revision).
4. **Accept the scarcity as the result** — the frozen scanner more often needs
   deterministic repair or additional evidence than LLM review; report that and
   keep A/B/C as a validated-but-unpowered pilot.

Routing evaluation over the full record set remains a separate, viable
experiment regardless of this choice.
