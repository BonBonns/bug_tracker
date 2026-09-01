# NAPI-STATUS-R01: real-package results

Per the pre-registered protocol in `NAPI_STATUS_R01.md`. **Claims boundary applies to
every line below:** these are API-handling classifications with node-id evidence --
never vulnerability, severity, exploitability, or impact claims.

## Candidate triage (frozen-order walk, tarball hashes verified)

Rows 0-9 of `overnight_100/overnight_sample_100.tsv` fetched and verified against
their pinned `tarball_sha256`; the token triage (`napi_create_buffer` in C/C++
sources; triage selects packages, never verdicts) produced, in frozen order:

- row 7: `@gjsify/napi@0.44.0` -- first candidate -> **development package**
- row 9: `@farcaster/rocksdb@5.5.0` -- next candidate -> **blind package**

(rows 0-6 and 8: verified, no token; walk stopped at the second candidate, per
protocol.)

## Development package: `@gjsify/napi@0.44.0` (disclosed before reading)

Pipeline: pinned tarball verified (sha256
`52a217e29e00c4302fc01504c9effa0d5ab70c3ae09de9a5c9f94a195cfef6bf`) -> c2cpg
v4.0.608 -> export_c_cpp_facts_v03.sc -> napi_status_verdict.py.

Result: `classification: {}` -- **zero supported creation call sites**. Root cause,
confirmed in the package's own sources: `@gjsify/napi` is an N-API *implementation*
library -- it **defines** `napi_create_buffer` / `napi_create_buffer_copy`
(`src/cc/arraybuffer.cc:163/:177`) and declares them (`src/napi-headers/node_api.h`),
but contains no call site of either. The triage token came from those
definitions/declarations. The analyzer keys on CALL facts only, so a pure-provider
package correctly contributes nothing: no false candidate, no false abstention.

Development outcome: no representation bug surfaced; the implementation was NOT
modified after this read. All 32 gate checks re-verified green.

## Freeze (recorded BEFORE blind selection was acted on)

```
45bf86bd05169ed66f3e5f48028296a3adf7d939bb0112d5eca8a1ad2ead5918  napi_status_verdict.py
265002baa38ede3a31d1a0a5301f590d9d4c7a5492f5a2f622ec173a72ade0ce  check_napi_status.py
3546835f9203c77e7e7db9b54cbfcf645865a51417229830738a1391b4396813  study/napi_status/fixture_source.c
```

## Blind package: `@farcaster/rocksdb@5.5.0` (single post-freeze run, reported as-is)

Pipeline: pinned tarball verified (sha256
`cdc0e3e6cd625330831c0bb325a660cb3d4c535d042ac60bb5828d90e12908a9`) -> c2cpg v4.0.608
-> export_c_cpp_facts_v03.sc -> the FROZEN napi_status_verdict.py (hash re-verified
`45bf86bd...918` immediately before the run).

Parse scope disclosure: the full-tree parse OOM-crashed c2cpg twice (6g, then 12g
heap; ~1000 vendored C++ files). The parse was scoped with c2cpg's own `--exclude` to
omit `package/deps/` (the vendored rocksdb C++ library) and `package/prebuilds/`
(compiled binaries). Token triage over the verified sources shows
`napi_create_buffer` appears in exactly one source file, `package/binding.cc`, and
nowhere under `deps/` -- so the exclusion cannot add or remove any supported call
site; its only possible effect is turning a provable wrapper into an abstention
(the conservative direction). The analyzer itself was NOT modified.

Result (verbatim):

```
classification: {'SUPPORTED_CREATION_CALL_FOUND': 1, 'NO_OUTPUT_USE': 1}
```

The one supported site: `napi_create_buffer_copy` at `package/binding.cc:344`,
method `Convert` -- `napi_create_buffer_copy(env, s->size(), s->data(), NULL,
result)`. Verdict `NO_OUTPUT_USE` (reason `USES_EXIST_BUT_NONE_REACHABLE_FROM_CALL`):
the napi_status result is discarded, but no reference to either output is
CFG-reachable after the call inside `Convert` -- the function ends immediately; the
`result` output escapes through the forwarded caller-supplied pointer parameter, and
`NULL` is passed for `result_data` (N-API's documented opt-out of that output). An
API-handling classification only; no impact statement is made or implied.

Findings-count summary: 0 STATUS_GUARD_MISSING, 0 abstentions, 1 NO_OUTPUT_USE, out
of 1 supported creation call site.

### Outcome classification (per review; the three permitted categories)

`@farcaster/rocksdb@5.5.0` is reported as **ANALYZED with zero guard-missing
findings** -- not an infrastructure failure: the two full-tree c2cpg OOMs were an
infrastructure HAZARD, but the disclosed scoped parse recovered usable facts, the
supported site was recognized, and the frozen analyzer ran once. Task #34's earlier
`CPP_CPG_FAILED` for this package is consistent with that hazard being real. The
caveats stand: this is LIMITED blind semantic evidence (one site, whose honest
classification under R02 is a caller-analysis abstention, see below), and it is NOT
real positive-path evidence -- positive-path behavior remains established on compiled
fixtures only (R02's w01/w02/w03 controls).

### Pre-registered fallback rule (for any future package run in this protocol)

If a selected package fails before producing usable facts (CPG generation or fact
export fails; a scoped parse per the disclosed rule above also failing), it is
recorded as an INFRASTRUCTURE FAILURE -- never as a scanner negative and never as
blind semantic evidence -- and the replacement is selected mechanically: among the
remaining frozen-sample packages, excluding all previously reviewed packages (rows
0-9 above, and any prior study's reviewed set), produce facts for each candidate with
the same pinned toolchain and select the one with the HIGHEST count of
`napi_create_buffer`/`napi_create_buffer_copy` call rows in its own `calls.tsv`
(structural count, no source reading before selection). Ties break by frozen-sample
row order. Only an analyzed result counts as the blind portability test.

### R02 correction of this site (see NAPI_STATUS_R02.md)

The `NO_OUTPUT_USE` above is R01's frozen verdict and stands AS the R01 record; it
is also exactly the boundary the review identified: the required `napi_value*
result` output escapes through a caller-provided pointer, so intraprocedural
analysis cannot prove it unused (`result_data == NULL` is the documented opt-out of
the OPTIONAL raw-data pointer -- a different thing entirely). Under
`napi_status_verdict_r02.py` this real site -- its facts now frozen at
`raw_blind_rocksdb/` -- classifies as
**`OUTPUT_ESCAPES_CALLER_ANALYSIS_REQUIRED`** (callers unresolvable from these
facts: `Convert` is an overloaded member, so call sites carry no single callee id),
pinned by `check_napi_status_r02.py` as a permanent regression.

## Integration status (NAPI-STATUS-INTEGRATION-R01, per review)

Wired additively in `napi_status_integration.py` (gate: `check_napi_status_
integration.py`, 25/25): exact candidate allowlist -- `STATUS_GUARD_MISSING` AND its
caller-side `STATUS_DISCARDED_OUTPUT_USED_IN_CALLER` are BOTH candidates (the
vocabulary-mismatch correction; an unrecognized sub_reason fails closed loudly) --
provenance enrichment via the EFFECTIVE caller function, reachability via
reachability_tier's own classifier on that same function, raw-N-API applicability
(exact API, required outputs resolved, provenance resolved, allowed tier, NO
exception-configuration premise), an EMPTY exact-match adjudication registry
section, diagnostic-only staged enablement, and aggregator revision
`aggregate_record_r02` (delegates the six frozen properties to
`six_property_aggregator.aggregate_record` unchanged). The property is
DIAGNOSTIC-ONLY (`NAPI_STATUS_ENABLED = False`) until a real package exercises its
positive path.

## 97-bundle preserved-facts replay (review item 9): attempted, infrastructure result

`replay_napi_status_97.py` implements the replay over the preserved evidence bundles
(preserved cpp_raw for the scanner, preserved cpp_facts/js_facts for reachability,
optional pinned-tarball refetch for provenance, diagnostic-only enablement, r02
aggregation). Its `--selftest` proves the mechanics end to end on a synthetic bundle
built from the frozen R02 fixture facts (7 sites, full classification, 0 reportable).
The REAL run in this checkout: **INFRASTRUCTURE_FAILURE / PRESERVED_BUNDLES_ABSENT**
(`replay_97/replay_report.json`) -- `evidence_bundles_100/` is a gitignored scratch
output that exists only on the machine that ran the overnight corpus pass. Per the
pre-registered rule this is an infrastructure result, not a scanner negative and not
semantic evidence. The driver is ready to run where the preserved bundles exist.

## Mechanical candidate map (token triage, all 100 frozen-sample packages)

All 100 pinned tarballs fetched and hash-verified; per-package count of C/C++ files
containing the `napi_create_buffer` token (triage data for the pre-registered
fallback selection; a token-free package provably contains no direct supported call
site -- barring token-pasting macros, disclosed assumption):

| row | package | token files |
|---|---|---|
| 7 | @gjsify/napi@0.44.0 (dev pkg -- provider library) | 2 |
| 9 | @farcaster/rocksdb@5.5.0 (blind pkg) | 1 |
| 12 | @8crafter/leveldb-zlib@1.6.0 | 1 |
| 31 | @cocktailpeanut/node-pty-prebuilt-multiarch@0.11.16 | 1 |
| 37 | @depup/node-addon-api@8.9.2-depup.0 | 1 |
| 48 | @fugood/whisper.node@1.1.3 | 1 |
| 55 | @h1x4dev/node-addon-api@2.0.0 | 1 |
| 87 | napi-ldap@1.0.4 | 1 |
| 96 | smart-whisper@0.8.1 | 3 |
| 99 | @zowe/db2-for-zowe-cli@6.1.17 | 1 |

The other 90 packages: verified, zero token files. (Note: two of the ten are
node-addon-api forks -- likely provider libraries like the dev package, i.e.
definitions rather than call sites; the facts, not this table, decide.)

### Refinements surfaced by the blind run (addressed in R02 except where noted)

1. A literal `NULL` out-argument was resolved as a trackable "variable" (CDT binds
   `NULL` to a synthetic same-named local). ADDRESSED IN R02: optional roles record
   an explicit `opted_out`; NULL in a required role abstains.
2. Outputs escaping via forwarded pointer parameters place the real uses in CALLERS.
   ADDRESSED IN R02: escape detection, one-level caller analysis, derived
   proven-wrapper sites, and the `OUTPUT_ESCAPES_CALLER_ANALYSIS_REQUIRED`
   abstention (this site's corrected classification).
3. `input_size_origin` labels a call-expression size argument (`s->size()`) as
   `unresolved`; a `call_result` label would be more informative. NOT addressed in
   R02 (diagnostic field only; no verdict depends on it) -- candidate R03 polish.
