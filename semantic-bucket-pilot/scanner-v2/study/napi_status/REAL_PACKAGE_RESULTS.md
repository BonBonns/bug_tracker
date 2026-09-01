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

## Blind package: `@farcaster/rocksdb@5.5.0`

(to be filled by the single post-freeze run; reported as-is)
