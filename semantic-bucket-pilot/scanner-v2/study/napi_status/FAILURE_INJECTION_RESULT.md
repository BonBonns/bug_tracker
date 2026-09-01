# Model failure-path result — @8crafter/leveldb-zlib NextWorker::HandleOKCallback

**Correction applied (per review): this section's original claim was overstated.**
Seeding the stub's output with a disclosed sentinel and using a hand-written stub for
`napi_create_buffer_copy` proves the CONTROL-FLOW MODEL's behavior on failure — it does
**not** run the real pinned addon, and it observes a known sentinel rather than an actual
indeterminate stack value. The correct classification is:

```
MODEL_FAILURE_PATH_CONFIRMED
```

— not "actual package runtime consequence confirmed." See "Real pinned-addon test" below
for the separate, harder proof that classification calls for.

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

This is a **model observation of return-code handling only**. It is NOT an exploit, and
NO security impact, severity, exploitability, or attacker-control claim is made or
established. The result is `MODEL_FAILURE_PATH_CONFIRMED`: the hand-written stub, under
a disclosed seeded sentinel, shows the modeled control-flow shape uses an unavailable
output on the failure path — a useful, deterministic sanity check of the static finding's
shape, but not yet a runtime observation of the actual pinned addon.

## Real pinned-addon test (attempted; see outcome below)

To reach an actual "runtime consequence confirmed in the real addon" classification, the
review specifies: build the pinned `@8crafter/leveldb-zlib@1.6.0` native addon; use
test-only interposition at the N-API boundary to force ONLY the two relevant
`napi_create_buffer_copy` call sites to fail without writing their output; invoke the
real exported `iterator_next` from JavaScript; observe whether the real code proceeds to
`napi_set_element`; keep the run bounded and record exit status / emitted N-API error /
assertion / sanitizer output; infer no security impact from the outcome. See
`REAL_ADDON_TEST_RESULT.md` for what was attempted and the honest outcome in this
environment.
