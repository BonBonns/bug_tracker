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

### Refinements surfaced by the blind run (NOT applied post-freeze; candidate R02 work)

1. A literal `NULL` out-argument is currently resolved as a trackable "variable"
   (CDT binds `NULL` to a synthetic same-named local). Correct verdict here, but the
   cleaner classification is an explicit opted-out output role.
2. Outputs escaping via forwarded pointer parameters place the real uses in CALLERS;
   this revision is deliberately intraprocedural (NO_OUTPUT_USE is the honest
   in-scope answer). Caller-side analysis of proven-propagating creation wrappers is
   the natural next revision.
3. `input_size_origin` labels a call-expression size argument (`s->size()`) as
   `unresolved`; a `call_result` label would be more informative. Diagnostic field
   only; no verdict depends on it.
