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

## Two-level validation — the authority for accepting 4.0.608

4.0.608 was installed in a SEPARATE directory (`/tmp/joern-4.0.608`) and validated before
being accepted as the frozen frontend. (4.0.462 had already been removed in the prior step;
it was the accidental install, never a validated baseline, so nothing validated was lost.)

The frozen scanner_commit `b704aab2` IS retrievable from the remote (fetched, then
`git worktree add /tmp/tchecker-b704aab2 b704aab2`). This let the historical scripts be
used directly rather than assumed absent. What is NOT recoverable is (a) the archived RAW
`cpp.json` (not vendored; only its sha256 is in `manifest.json`) and (b) the exact original
scan scope + absolute path used to build it (the manifest records only the source file, not
the scan root or the full set of co-compiled files).

### Level 1 — frontend / normalization

- Reproduced `cpp.json` at the exact pinned revision (NSS `994c45e80^` = `aeb343057...`),
  file `lib/util/secasn1d.c`, with the exporter `export_c_cpp_facts_v03.sc` and normalizer
  `normalize_c_cpp_facts_v03.py`, using the separate 4.0.608 install.
- Exporter and normalizer at `b704aab2` were retrieved via worktree and are BYTE-IDENTICAL
  to the current tree (`diff` clean) — the normalizer snapshot is NOT a source of difference.
- Whole-file SHA-256 `731b7687...` != archived `758f8792...`.
- Honest status of this level: **determinism at the reconstructed scope PASSED** — two
  independent re-scans at the same scope produce a BYTE-IDENTICAL raw `cpp.json`
  (`731b7687...`) and identical canonical fact tables. **Exact archived fact reproduction
  was NOT available**, because the archived raw facts and the original scan scope were not
  available together. This validation does NOT claim the archived hash difference is only
  path/metadata: changing scope alters cross-file REFERENCE RESOLUTION, which is a SEMANTIC
  change to the facts, not mere path/metadata reordering. The archived difference is
  therefore left as attributable to (scope + scan-path), of which only the scan-path part
  (embedded in `metadata.root` and per-fact `file`) is provably non-semantic; the scope
  part is not asserted to be non-semantic. Compatibility rests on Level 2, not on this hash.

### Level 2 — producer / semantic projection (the compatibility evidence)

Both options the review allowed were exercised: the producer code AT `b704aab2` was run
directly (not only current producers), and the current producers were additionally
confirmed BYTE-IDENTICAL to `b704aab2` for all three modules
(`oob_cursor_write_verdict`, `oob_runtime_capacity_verdict`, `oob_interprocedural_verdict`),
so there is no producer drift for these.

Exact projection rule (documented so filtering cannot hide records):
> P(cpp) = { (producer, function, reason_code, llm_eligible) :
>           analysis_status == "abstained" AND basename(record.file) == "secasn1d.c" }
> i.e. the abstained records located in the CVE's own source file — the file in which ALL
> four archived `cve-2016-1950/vuln` records live.

Full disclosure of the UNFILTERED record set (b704aab2 producers, 4.0.608 facts, `lib/util`
scope) so the filter hides nothing: 46 abstained records across 8 co-compiled files —
derenc.c 8, dersubr.c 16, nssb64e.c 6, **secasn1d.c 4**, secoid.c 1, utilpars.c 9,
secport.c 1, portreg.c 1. The 42 non-secasn1d.c records are abstentions in sibling
lib/util files (co-compiled to resolve secasn1d.c's own dependencies); they are outside the
projection unit, and the filter removes ONLY those — it removes NO secasn1d.c record. Within
secasn1d.c there are exactly 4, matching the archived projection EXACTLY:

    cursor  sec_asn1d_concat_group    abstained destination_identity_ambiguous  llm=False   (x2)
    runtime sec_asn1d_add_to_subitems abstained unknown_allocator_contract      llm=True
    runtime sec_asn1d_concat_substrings abstained required_evidence_absent       llm=False

Scope sensitivity of the projection is disclosed (same historical producers):
- `lib/util` scope (secasn1d.c's arena dependency resolved): secasn1d.c projection = the 4
  archived records, exactly.
- file-only scope (arena dependency unresolved): secasn1d.c projection = 5 — the same 4
  PLUS `sec_asn1d_zalloc / unknown_allocator_contract`, because `sec_asn1d_zalloc`'s arena
  allocator (defined in a sibling lib/util file) is unresolved when secasn1d.c is compiled
  alone. This is expected scope-driven reference resolution, confirmed with the historical
  producers (so not producer drift), and is why the projection is taken at the
  dependency-resolving scope.

Semantic reproduction target — all hold at the dependency-resolving scope:
- cursor abstentions in secasn1d.c: 2  ✓
- runtime abstentions in secasn1d.c: 2  ✓
- interprocedural: 0  ✓
- exactly one LLM-routable candidate, at `sec_asn1d_add_to_subitems`  ✓
- reason `unknown_allocator_contract`  ✓

### Decision (defensible conclusion)

Joern 4.0.608's identity (archive sha256) and deterministic operation were verified, and its
current facts reproduce the frozen security-relevant PRODUCER PROJECTION exactly (validated
with the historical `b704aab2` producer code, which is byte-identical to the current
producers, and with the exporter/normalizer confirmed byte-identical to `b704aab2`). Exact
byte-level reproduction of the historical NORMALIZED FACTS was NOT possible, because the
archived raw facts and the original scan scope were not available together, and scope is
semantic. On this basis 4.0.608 is accepted as the frozen frontend, replacing the accidental
4.0.462; `/tmp/joern-cli` (used by `scan_c_frozen.sh`) is the accepted 4.0.608. Acceptance of
the toolchain does NOT by itself validate any capability — see each capability's own gate.

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
- The `sec_asn1d_zalloc` scope sensitivity is documented above under Level 2 (file-only
  scope adds it; the dependency-resolving `lib/util` scope does not), confirmed with the
  historical producers.
- capability-1 control harness re-run under 4.0.608: ALL PASS.

## Byte-identical facts: not claimed, and why

The archived `cpp.json` sha256 (`758f8792...` for cve-2016-1950/vuln) is recorded in
`manifest.json`, but the archived RAW facts themselves are NOT vendored (rebuild-recipe
policy), and the exact original scan scope + path are not recorded. The frozen
scanner_commit `b704aab2` and its exporter/normalizer/producers ARE retrievable (worktree)
and are byte-identical to the current tree, so the pipeline is not the obstacle — the
missing archived raw facts and unknown original scope are. Byte-identical normalized facts
therefore cannot be reproduced and are NOT claimed. Frontend compatibility is established at
the authoritative level the capabilities depend on: the frozen PRODUCER PROJECTION (reason
codes, analysis_status, llm-eligibility) on real disclosed source, reproduced exactly with
the historical `b704aab2` producer code, plus identical facts schema (0.3) and stamped
frontend version (4.0.608).

## Binding decision

- Capabilities 2, 3, 4 and the held-out confirmatory run MUST use joern-cli v4.0.608 with
  the archive SHA-256 above. Any capability result produced under a different frontend is
  invalid and must be re-run.
- If v4.0.608 ever cannot be obtained, a substitute frontend is treated as a NEW frontend
  and requires its own full compatibility evaluation (this same real-source reproduction,
  passing) before use — it cannot silently replace the frozen version.
