# Frozen frontend toolchain identity (capabilities 2-4 + held-out run)

The C/C++ facts the capability models consume (parsing, node identities, calls, parameters,
reference resolution) are frontend-version-dependent. This record freezes the ONE frontend
version all capability development and the held-out confirmatory run must use. A capability
validated under any other frontend is not accepted.

## Pinned frontend (matches the frozen corpus)

- Tool: joern-cli (contains c2cpg), tag **v4.0.608** — the exact version the frozen corpus
  and every prior gate used (`bootstrap.sh` JOERN_VERSION=4.0.608; `manifest.json`
  toolchain.frontend_version=4.0.608; fact-file `metadata[0].version` == 4.0.608;
  `ENVIRONMENT.md`, `RUNBOOK.md`, `JOERN_PROVENANCE.md`, `MANIFEST.md`).
- Archive: `joern-cli-linux-x86_64.zip`
- URL: `https://github.com/joernio/joern/releases/download/v4.0.608/joern-cli-linux-x86_64.zip`
- Size: 1821051748 bytes
- Archive SHA-256: `97989843f7d6be1449296936644b04803e80723e607648c33edf87ded6202ded`
  (downloaded here and VERIFIED equal to the value recorded in JOERN_PROVENANCE.md).
- Installed at `/tmp/joern-cli`; `joern` prints `Version: 4.0.608`; JVM OpenJDK 21.
- Facts schema produced: `portable-program-facts/0.3`.

## Why 4.0.462 was rejected

An earlier step in this session installed joern 4.0.462 (the version whose release still
served a `joern-cli.zip` asset) and validated capability 1's synthetic controls under it.
That is INSUFFICIENT: capability-1 controls passing does not prove frontend compatibility,
because different joern versions can change parsing, node identities, calls, parameters,
and reference resolution — the exact facts the capability models read. 4.0.462 has been
removed; it is NOT the frozen frontend and must never silently replace 4.0.608.

## Two-level validation (both PASS) — the authority for accepting 4.0.608

4.0.608 was installed in a SEPARATE directory (`/tmp/joern-4.0.608`) and validated before
being accepted as the frozen frontend. (4.0.462 had already been removed in the prior step;
it was the accidental install, never a validated baseline, so nothing validated was lost.)

### Level 1 — frontend / normalization compatibility

- Reproduced `cpp.json` at the exact pinned revision (NSS `994c45e80^` = `aeb343057...`),
  file `lib/util/secasn1d.c`, with the in-tree exporter `export_c_cpp_facts_v03.sc` and
  normalizer `normalize_c_cpp_facts_v03.py`, using the separate 4.0.608 install.
- Whole-file SHA-256: `731b7687...` vs archived `758f8792...` — DIFFERENT. Expected: the
  archived facts embed a different absolute scan path (`metadata.root`, per-fact `file`),
  used a wider scan scope, and were normalized by the exporter/normalizer at frozen
  scanner_commit `b704aab2` (absent from this tree). The archived RAW `cpp.json` is not
  vendored (only its sha256 is recorded in `manifest.json`), so a direct fact-table diff
  against the archive is impossible.
- Difference characterized as path/metadata + scope, NOT semantic:
  * DETERMINISM: two independent re-scans at the same scope produce a BYTE-IDENTICAL raw
    `cpp.json` (`731b7687...`) and identical canonical fact tables — the frontend +
    normalizer are deterministic, so the archive-hash difference is not nondeterminism.
  * The only scan-path-dependent content is `metadata.root` and per-fact `file`; changing
    the scan directory changes those bytes (and the whole-file hash) with no semantic change.
  * Cross-scope changes (file-only vs lib/util) are exactly cross-file REFERENCE RESOLUTION
    (macros like `SEC_ASN1_*`, `PORT_Memset`/`PORT_Memcpy` callees) — expected scope
    behavior, and the reason the semantic projection is compared at a scope that resolves
    those references (below).

### Level 2 — producer / semantic compatibility

The expected abstentions were produced by the producer code at scanner_commit `b704aab2`,
which is not in this tree; later producer/schema fields may differ, so byte-identical
current records are NOT required. Instead the FROZEN SEMANTIC PROJECTION
(`frozen-corpus/all_records.jsonl`, the 4 records for `cve-2016-1950/vuln`) is the ground
truth. Running the current producers on the 4.0.608 facts (scope that resolves cross-file
references), restricted to the CVE source file, the projection
`(producer, function, analysis_status, reason_code, llm_eligible)` is an EXACT MATCH:

    cursor  sec_asn1d_concat_group    abstained destination_identity_ambiguous  llm=False   (x2)
    runtime sec_asn1d_add_to_subitems abstained unknown_allocator_contract      llm=True
    runtime sec_asn1d_concat_substrings abstained required_evidence_absent       llm=False

Semantic reproduction target — all hold:
- cursor abstentions: 2  ✓
- runtime abstentions: 2  ✓
- interprocedural: 0  ✓
- exactly one LLM-routable candidate, at `sec_asn1d_add_to_subitems`  ✓
- reason `unknown_allocator_contract`  ✓

### Decision

Archive hash PASS + Level 1 (deterministic; difference is path/metadata/scope, not
semantic) PASS + Level 2 (exact semantic-projection match) PASS. 4.0.608 is therefore
accepted as the frozen frontend and replaces the accidental 4.0.462; capability work
resumes under it. `/tmp/joern-cli` (used by `scan_c_frozen.sh`) is the accepted 4.0.608.

## Real-source reproduction (not synthetic) — PASS

Regenerated facts for the real disclosed CVE cve-2016-1950 (NSS bug 1245528) and ran the
three frozen producers, comparing against the archived producer output in
`frozen-corpus/all_records.jsonl`.

- Source: `github.com/mozilla/nss` @ `994c45e80^` (= `aeb343057119d647dbd6c0d7fcdd0d60e4a6e682`,
  the vuln revision), file `lib/util/secasn1d.c`.
- Pipeline: `scan_c_frozen.sh` (c2cpg 4.0.608 -> export_c_cpp_facts_v03.sc ->
  normalize_c_cpp_facts_v03.py), facts stamped `version 4.0.608`, schema 0.3.
- Archived cve-2016-1950/vuln record set (4 records) reproduced EXACTLY (same producer,
  function, line-adjacent, analysis_status=abstained, reason_code):
  * cursor  `sec_asn1d_concat_group` x2  -> `destination_identity_ambiguous`
  * runtime `sec_asn1d_add_to_subitems`  -> `unknown_allocator_contract` (llm_eligible)
  * runtime `sec_asn1d_concat_substrings`-> `required_evidence_absent`
  * interproc: empty
  Per-producer abstained counts match the manifest (cursor 2, runtime 2, interproc 0).
- One extra runtime abstention (`sec_asn1d_zalloc`, unknown_allocator_contract) appears
  ONLY when secasn1d.c is scanned in isolation; at realistic scope (the full `lib/util`
  directory) it produces no record, exactly as in the frozen corpus. So it is a
  single-file scoping artifact, NOT a frontend incompatibility.
- capability-1 control harness re-run under 4.0.608: ALL PASS.

## Byte-identical facts: not claimed, and why

The archived `cpp.json` sha256 (`758f8792...` for cve-2016-1950/vuln) was produced over the
FULL nss checkout at frozen scanner_commit `b704aab26e3b7872d21350816ac9d60aaf0e4d3f`,
which is not present in this working tree. Byte-identical normalized facts therefore cannot
be guaranteed and are NOT claimed. Frontend compatibility is instead established at the
authoritative level the capabilities depend on: identical PRODUCER OUTPUT (reason codes,
analysis_status, llm-eligibility) on real disclosed source, plus identical facts schema
(0.3) and stamped frontend version (4.0.608).

## Binding decision

- Capabilities 2, 3, 4 and the held-out confirmatory run MUST use joern-cli v4.0.608 with
  the archive SHA-256 above. Any capability result produced under a different frontend is
  invalid and must be re-run.
- If v4.0.608 ever cannot be obtained, a substitute frontend is treated as a NEW frontend
  and requires its own full compatibility evaluation (this same real-source reproduction,
  passing) before use — it cannot silently replace the frozen version.
