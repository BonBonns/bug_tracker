# R06/FIX01I integration -- promoting SOURCE_BOUNDARY_UNRESOLVED via real JS linkage

Branch `claude/r06-fix01i-integration`, a merge of `claude/r06-precision-fix` (R06) and
`claude/crosslang-linker-fix` (FIX01I) -- both kept COMPLETELY UNTOUCHED (no commits on
either branch modify them; verified by hash before and after this integration's own work).
All new logic lives in `promote_via_js_linkage.py`, a new file on this branch only.

## Goal

R06 (`claude/r06-precision-fix`) deliberately reports `SOURCE_BOUNDARY_UNRESOLVED` (or an
untraced `None`) for every reached parameter, with no exception -- see that branch's own
commit for why an earlier, more permissive rule was an overclaim. This integration adds the
ONE thing that legitimately CAN promote such a finding: real, structural proof that a real
JS-supplied argument reaches the traced native value.

## What's real vs. what's disclosed synthetic

Three real mechanisms, all new code, all verified against real data:

1. **`extract_instancemethod_bindings()`** -- real, structural recognition of the
   `Napi::ObjectWrap<Class>::DefineClass(env, "X", { InstanceMethod<&Class::Method>("y"),
   ... })` registration idiom, which `link_napi_facts.py`'s own `extract_napi_bindings()`
   does NOT recognize (that function only matches the DIFFERENT `exports.Set(String::New,
   Function::New)` idiom). Verified real against Cartesi's own real `cpp_facts.json`: all
   60 real `InstanceMethod` registrations found, including the 3 real methods R06 already
   flags (`readMemory`/`readVirtualMemory`/`readConsoleOutput`), each resolving to the
   correct real C++ function id via an exact, single-candidate `Class.Method` full-name
   match (never a guess).

2. **`find_callback_info_index_source_for_acquisition()`** -- a real, additional dataflow
   shape neither R06's own `backward_attacker_trace` nor FIX01I's own call-linking models:
   does the traced value originate from `info[N]` (a real `Napi::CallbackInfo` index access)
   via an OUT-PARAMETER helper call (`get_u64(env, info[N], "name", &var)`-shaped)? Found by
   direct investigation of Cartesi's own real, cached raw facts (`/tmp/cartesi_raw`): its real
   `length` value comes from exactly `get_u64(env, info[1], "length", &length)`, which is WHY
   R06's own identifier/assignment-RHS walk alone traces it to `None` -- `length`'s only real
   `<operator>.assignment` in that method is `length = 0` (a harmless default LITERAL,
   correctly not followed further by that walk). Verified real: the structural search
   correctly finds the real `get_u64` call for all 3 of Cartesi's real findings.

3. **`link_calls_extended()` + `promote_findings()`** -- combines both, plus a real,
   index-convention-correct check that a linked JS call ACTUALLY supplies a real argument at
   the position `info[N]` needs (`info[N]` is 0-based; a real JS call's own `arguments` list
   is 1-based with index 0 reserved for the receiver -- confirmed via direct inspection of
   Cartesi's own real `require(...)` calls, `index 0 = "this"`, `index 1 = ` the real first
   argument. Getting this wrong was a REAL bug caught during this integration's own
   development, not a hypothetical: an early version matched `info[N]` against JS argument
   index `N` directly, which spuriously "passed" only because the test fixture happened to
   supply enough arguments either way -- fixed to require index `N + 1`, with a dedicated
   negative regression (a JS call supplying only `info[N]`'s own first N real arguments, not
   the N+1'th) proving the fix matters.

**One disclosed synthetic piece**: Cartesi's own real, currently-published
`@cartesi/machine@1.0.0-alpha.1` ships `dist/index.cjs` as its real JS entry point -- a
WASM/bundled build. Direct inspection of its real, captured JS facts
(`/tmp/smoke_test_cartesi/work/js_raw`, 243 real calls total) found **zero** real calls
naming `readMemory`, `readVirtualMemory`, `readConsoleOutput`, or any other
InstanceMethod-registered name anywhere in the package. This is a real, honest finding, not
a gap in this integration's own mechanism: `study/r06_fix01i_integration/controls/
cartesi_shape_positive/build_js_control.py` builds ONE synthetic JS call
(`machine.readMemory(address, length)`) standing in for the real call Cartesi's own package
does not currently expose in an inspectable form, so the FULL promotion chain can be proven
correct end-to-end. The C++ side of that control is Cartesi's OWN real facts, unmodified --
only the JS call site is synthetic, and it is never presented as a real Cartesi finding.

## Required promotion boundary (explicit instruction, verified)

A cross-language link proves JavaScript CAN reach a native method; it does NOT by itself
prove the SPECIFIC allocation size comes from a JS argument. Promotion to
`JS_ARGUMENT_CONTROLLED` requires all three, none of which alone is sufficient:

1. The C++ method is registered/exposed to JavaScript (`extract_napi_bindings`/
   `extract_instancemethod_bindings`).
2. FIX01I resolves the relevant JS/native method identity (a real entry in `linked_calls`).
3. The internal native trace terminates at a specific `CallbackInfo[index]`/`args[index]`
   value that feeds the allocation size (`find_callback_info_index_source_for_acquisition`).

Explicitly verified NOT promoted, each for the SPECIFIC required reason (`tests/
test_promote_via_js_linkage.py`, 12/12 PASS):

| Case | Registration? | Structural `info[N]` source? | Real JS linkage? | Promoted? |
|---|---|---|---|---|
| node-libcurl (`Easy::ReadFunction`) -- a native callback parameter, not JS-reachable | N/A -- no `Napi::CallbackInfo` param at all | No (correctly) | N/A | **No** |
| Adversarial: JS-reachable method, size internally computed (`length = width * height`, no `info[N]` anywhere) -- even with a PRETEND real FIX01I link present | N/A (test bypasses this) | **No** (correctly) | N/A (pretend real link supplied, still refused) | **No** |
| Cartesi, real data (`ReadMemory` etc.) -- registration real, structural source real, but no real JS call site exists in the published package | **Yes**, real (3/3) | **Yes**, real (3/3) | **No** -- 0 real linked calls | **No** |
| Cartesi, disclosed synthetic JS call missing 1 argument -- `info[1]` would read an undefined JS value | Yes, real | Yes, real | Yes, synthetic (1 call, 1 real arg -- one short) | **No** |

And the one case where all three conditions genuinely hold:

| Case | Registration? | Structural `info[N]` source? | Real JS linkage? | Promoted? |
|---|---|---|---|---|
| Cartesi, disclosed synthetic JS call (2 real args) | Yes, real | Yes, real | Yes, synthetic (1 call, 2 real args) | **Yes** -- `ReadMemory` promoted, verdict `JS_ARGUMENT_CONTROLLED`, evidence cites `info[1]` -> JS argument index 2 |

node-crc16 is unaffected by this integration (0 findings under R06 already -- `SIZE_
ATTACKER_INDEPENDENT` rejects its one recovered candidate before any trace/promotion logic
runs at all -- a literal size is never even a promotion candidate).

jpeg-turbo is unaffected too, for an honest, real, DIFFERENT reason than initially expected:
it is a **`nan`-based** addon (confirmed via its own real `header_staging` evidence --
`"dep": "nan"`, not `node-addon-api`), so its real acquisition calls never match the
curated `Napi::Buffer::New` contract's own structural requirements at all (`R05_RECOVERY_
RESULT_TYPE_UNRECOGNIZED` for all 28 real candidates, 0 findings) -- it never reaches R06's
own applicability gate, so no `BUILD_CONFIGURATION_UNRESOLVED`/`CONTRACT_NOT_APPLICABLE`
finding is literally reported for it. This is a real, disclosed scope boundary of the
curated node-addon-api contracts (nan is a different, older native-addon API this project's
contracts were never built for), not a gap in this integration -- reported here precisely
rather than forced to match an initial expectation the real data does not support.

## node-libcurl's finding now carries BOTH pieces of real evidence, independently

A `claude/r06-precision-fix` refinement (merged into this branch) attaches
`source_boundary_evidence` and the per-target build-config resolution metadata to EVERY
applicability-gate finding, not only the final "disabled, established" one. node-libcurl's
own real `CONTRACT_NOT_APPLICABLE` finding now carries, on the SAME record:
`source_boundary_evidence.source_boundary == "SOURCE_BOUNDARY_UNRESOLVED"` (its `size`
parameter is `size_t`, not `Napi::CallbackInfo`) AND the real exceptions-enabled evidence
(`resolution_scope: "per_target"`, `resolved_target_name: "<(module_name)"`, the target's
own real `enable_evidence`) -- an abstention and a source-boundary determination are
independent real facts, and a reader can now see both regardless of which one this run
reports as the primary verdict. `package_wide_diagnostic` is also present and shown to
genuinely differ from the authoritative per-target result (package-wide `"unresolved"` vs.
per-target `"enabled"`) -- confirming per-target resolution, not the package-wide value, is
what was actually applied (`tests/test_target_scoping_e2e.py`, 16/16 PASS).

## Honest conclusion

The promotion mechanism is real, correctly index-convention-aware, and verified against real
node-libcurl and real Cartesi data for the rejection/registration-without-linkage cases, and
against a disclosed synthetic JS call (built on Cartesi's own real C++ facts) for the full
positive/negative promotion chain. **Cartesi's own real, currently-published npm package does
NOT itself supply real evidence sufficient to promote its 3 findings** -- this is reported
here precisely, not glossed over, matching this project's own established discipline (see
`resource_guard_verdict_r06.py`'s own docstring account of why an earlier promotion rule
built on an unverified claim about Cartesi was itself an overclaim). If a future JS
regeneration pass (per the still-frozen, unmerged `claude/crosslang-linker-fix` plan) ever
captures Cartesi's real native-consumer JS code (rather than only its WASM/browser dist
bundle), this same mechanism can be re-run against real facts and may promote for real.
