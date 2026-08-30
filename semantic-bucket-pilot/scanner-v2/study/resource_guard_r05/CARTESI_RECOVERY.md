# R05 Cartesi recovery: development case, NOT a blind test

Per this project's own established discipline (RESOURCE_GUARD_R03.md section 6): Cartesi
motivated and validated this correction (its own R02/R03 result, and the fact that its real,
currently-published source could not be resolved even after the header-staging fix, is what
led to R05 existing at all), so it CANNOT also serve as R05's blind holdout. This file records
its recovery as a development/regression case, exactly as R03 did for the same package.

## Real input

`@cartesi/machine@1.0.0-alpha.1`'s real, currently-published tarball (`native/addon.cc`),
run through real c2cpg with node-addon-api headers staged (`--include`) and the exception
macro defined (`--define NAPI_DISABLE_CPP_EXCEPTIONS`) -- the same real facts built and
verified during the header-staging fix (`HDR_FIX_STATUS.md`), re-used here unchanged (not
re-run). Build-configuration evidence: `study/resource_guard_r04/build_configs/
bc_cartesi_disabled.json` (real, previously independently verified `NAPI_DISABLE_CPP_
EXCEPTIONS` in the real `binding.gyp`) -- unchanged from R02/R03/R04's own use of this file.

## Real result

```
classification: {ACQUISITION_NAME_MATCH_CANDIDATE: 78, ACQUISITION_SIGNATURE_UNRECOGNIZED: 78,
                  R05_RECOVERY_CANDIDATE: 78, R05_RECOVERY_RESULT_TYPE_UNRECOGNIZED: 75,
                  R05_ACQUISITION_CALL_RECOVERED: 3, VALUE_ACQUISITION_GUARD_MISSING: 3}
findings: 3
```

Three real, distinct `VALUE_ACQUISITION_GUARD_MISSING` findings, each with
`evidence_source: "r05_structural_recovery"`:

| Method | Object | Recovered result_type | Real acquisition line |
|---|---|---|---|
| `Machine::ReadMemory` | `data` | `Napi.Buffer` | 523 |
| `Machine::ReadVirtualMemory` | `data` | `Napi.Buffer` | 551 |
| `Machine::ReadConsoleOutput` | `data` | `Napi.Buffer` | 599 |

**`Machine::ReadMemory` is the SAME real site R02/R03 originally found** (same
`acquisition_call_id`, `30064771980`, as the direct manual Joern-REPL query confirmed while
building R05) -- now reached via a completely different evidence path (the LOCAL's own
resolved type, not the call's own methodFullName, which stays `<unresolvedNamespace>` even
with headers staged). **`Machine::ReadVirtualMemory` and `Machine::ReadConsoleOutput` are
genuinely NEW findings** -- neither was reported by R02/R03/R04, which only ever examined
`ReadMemory` specifically as their hand-selected blind-test target; this is the first time
the WHOLE real file has been scanned for this pattern.

Real accounting check, not just trusted: of 78 real `"New"`-named candidate calls in this
file, 75 are rejected at the result-type-form gate (real `Napi::TypeError::New`,
`Napi::RangeError::New`, `Napi::Object::New`, `Napi::String::New`, `Napi::Number::New`,
`Napi::BigInt::New`, `Napi::Boolean::New`, `Napi::External<cm_machine>::New`,
`Napi::Function::New` calls throughout the same real file -- all correctly rejected, none
misclassified as Buffer). Exactly 3 calls have a `Napi.Buffer`/`Buffer`-typed local, and all
3 pass every remaining gate and are recovered -- 0 lost to arity or argument-role rejection in
this real file, and 0 lost to a real `IsEmpty()` guard actually being present (there is none,
matching R02/R03's own already-documented finding that this file has no such guard anywhere).

## Direct source verification of the two new sites (real, not taken on the algorithm's word)

Read directly from the real, currently-published tarball (`native/addon.cc:540-554` and
`:582-602`), matching R02's own discipline of never reporting a finding without reading the
real source:

```cpp
// line 540
Napi::Value Machine::ReadVirtualMemory(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    uint64_t address = 0;
    uint64_t length = 0;
    if (!get_u64(env, info[0], "address", &address) || !get_u64(env, info[1], "length", &length)) {
        return env.Undefined();
    }
    if (length > SIZE_MAX) {
        Napi::RangeError::New(env, "length is too large").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    Napi::Buffer<uint8_t> data = Napi::Buffer<uint8_t>::New(env, static_cast<size_t>(length));
    CHECK_CM(env, cm_read_virtual_memory(machine_, address, data.Data(), length));
    return data;
}
```

```cpp
// line 582 (excerpt)
Napi::Value Machine::ReadConsoleOutput(const Napi::CallbackInfo &info) {
    ...
    Napi::Buffer<uint8_t> data = Napi::Buffer<uint8_t>::New(env, static_cast<size_t>(max_length));
    CHECK_CM(env, cm_read_console_output(machine_, data.Data(), max_length, &read_length));
    ...
}
```

Both confirmed, by direct read: the exact same shape as `ReadMemory` -- `length`/`max_length`
supplied via `get_u64` on a JS-caller argument (bounded only by `SIZE_MAX`, same as R02's
original finding), no `IsEmpty()`/`IsExceptionPending()` check anywhere in either function, a
real downstream use (`data.Data()` passed into `cm_read_virtual_memory`/
`cm_read_console_output`) before any validity check, and the same real
`NAPI_DISABLE_CPP_EXCEPTIONS` build-configuration assumption applies (same `binding.gyp`, same
file). Both real, genuinely unguarded, not an artifact of the recovery mechanism.

**One real, additional confirmation of R05_DESIGN.md's own disclosed scope boundary, seen
directly in this same file:** `ReadConsoleOutput` (line 592) also contains
`return Napi::Buffer<uint8_t>::New(env, 0);` -- a DIRECT RETURN with no intermediate local.
This call is real, also unresolved by c2cpg, and correctly NOT recovered (it is not among the
3 findings) -- exactly the "return with no intermediate local, not covered by this pass"
boundary R05_DESIGN.md stated up front, now observed in real code rather than only asserted.

## Claims boundary -- same discipline as R02/R03's own Cartesi write-up

Exactly the claims boundary RESOURCE_GUARD_R03.md's section 5 already states for
`Machine::ReadMemory` applies here, unchanged, to all three findings: a real, unguarded
CANDIDATE under this contract's static property -- not a confirmed real vulnerability, not
automatically CWE-787, not proof of exploitable memory corruption.
