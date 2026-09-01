# Bounded failure-injection result — @8crafter/leveldb-zlib NextWorker::HandleOKCallback

Run ONLY after the two `napi_create_buffer_copy` `STATUS_GUARD_MISSING` findings cleared
every gate — provenance, reachability (three-proof `TIER_CALLBACK_OR_WORKER_VIRTUAL_PROVEN`),
applicability, and adjudication (see `COMBINED_LEVELDB_RESULT.json`), which was the
pre-stated precondition.

## What was tested

The exact control-flow shape of the real site (`bindings.cpp:1440 → use at 1453`):
the required output `returnKey` is declared, `napi_create_buffer_copy` is called with its
`napi_status` **discarded** (no assignment, no check), and `returnKey` is then passed to
`napi_set_element` regardless of success. A local stub for `napi_create_buffer_copy`
follows the real N-API contract: on injected failure it returns a non-ok status and does
**not** write `*result` (the output is left unavailable). `returnKey` is seeded with a
disclosed sentinel to model indeterminate prior stack content (the real code leaves it
uninitialized) so the behavior is deterministic. Harness:
`failure_injection_leveldb.cpp` (self-contained; no real N-API/node/leveldb).

## Observed runtime behavior (`failure_injection_output.txt`)

```
SUCCESS path: napi_set_element received 0x1000            (the real created handle)
FAILURE path: napi_set_element received 0xdeadbeefdeadbeef (the unavailable/indeterminate output)
```

- **Success:** the created buffer handle flows to the use site.
- **Injected failure:** the output is **used on the failure path without a success
  check**, carrying an unavailable/indeterminate value rather than a created handle.

This confirms, at runtime, exactly what the static finding states: the return code is
discarded and the required output is consumed regardless of whether the creation
succeeded.

## Claims boundary (unchanged, load-bearing)

This is a **runtime observation of return-code handling only**. It is NOT an exploit, and
NO security impact, severity, exploitability, or attacker-control claim is made or
established. The two sites remain **confirmed API return-code handling discrepancies**,
now with a confirmed runtime control-flow consequence (an unavailable output is used on
the failure path) — not confirmed vulnerabilities. Whether any real-world harm follows is
a separate, unestablished question outside this reliability analysis.
