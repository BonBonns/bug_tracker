# Nan Buffer-allocation capability -- design

Two new, standalone contracts for the two `Nan::` Buffer-allocation entry points the
prevalence study (`study/nan_prevalence_study/PREVALENCE_STUDY.md`) found to be the corpus's
largest uncovered contract family (38 packages / 104 call sites -- larger than R05/R06's
existing `Napi::Buffer<T>::New` coverage of 29 packages / 72 sites):

1. **`NAN_NEWBUFFER_UNBOUNDED_ALLOCATION`** -- `Nan::NewBuffer(...)`'s allocation length is
   JS-argument-controlled, with no structurally-detected application-level upper-bound check.
2. **`NAN_COPYBUFFER_SOURCE_CAPACITY`** -- `Nan::CopyBuffer(...)`'s copy length is
   JS-argument-controlled AND a real, local allocation site for the source pointer was found
   whose own size is structurally independent of that length (a genuine capacity/length
   mismatch -- never inferred merely because the source's origin could not be resolved).

Built entirely on `claude/nan-capability`, a new isolated branch. Imports NOTHING from
`resource_guard_verdict_r04/r05/r06.py`, `resource_contracts_r04/r05.py`, or
`promote_via_js_linkage.py`. In particular, this capability does **not** reuse R04-R06's
exceptions-enabled/disabled build-configuration applicability gate -- Section 3 below is the
real, source-verified reason why that gate does not apply here at all.

## 1. Version resolution (real, per-package)

Every development/control package's own declared `nan` dependency range, resolved the SAME
way the corpus's own header-staging mechanism (`run_pipeline_one.py`'s
`resolve_npm_dep_version`) already resolves it -- highest real registry version satisfying the
declared semver range, matching what `npm install` would fetch today:

| Package | Declared `nan` range | Resolved version |
|---|---|---|
| `node-snap7` (dev case) | `^2.23.0` | `2.28.0` |
| `node-snap7-micro-client` | `~2.14.0` | `2.14.2` |
| `murmurhash-native` (control) | `^2.14.1` | `2.28.0` |
| `msgpack` (control) | `^2.14.0` | `2.28.0` |
| `@confluentinc/kafka-javascript` (control) | `^2.22.0` | `2.28.0` |
| `scrypt` (control) | `^2.0.8` | `2.28.0` |
| `libpq` (control) | `~2.26.2` | `2.26.2` |
| `phplike` (control) | `^2.0.9` | `2.28.0` |

Three distinct real versions in play: 2.14.2, 2.26.2, 2.28.0. Fetched and read all three
directly (not assumed identical from the newest alone): `NewBuffer`/`CopyBuffer`'s own real
signatures, the `MaybeLocal<v8::Object>` return type, the `assert(... <= imp::kMaxLength ...)`
bound check, and `kMaxLength = 0x3fffffff` are **byte-for-byte identical** across all three --
stable since at least nan 2.14.x (2020-era) through the current 2.28.0. This capability's
semantics claims (Section 3) hold for every real development/control package without a
per-version branch.

## 2. Real facts established via an actual c2cpg/jssrc2cpg run (not assumed)

A purpose-built synthetic fixture (`study/nan_capability/controls/comprehensive_fixture/pkg/`)
was run through the REAL toolchain -- real nan-header staging
(`run_pipeline_one.py`'s own `stage_native_dep_headers`, `nan@2.28.0` resolved and fetched),
real `c2cpg.sh`, real `jssrc2cpg.sh`, real `export_c_cpp_facts_v03.sc` /
`export_neutral.sc` -- and the real output raw facts inspected directly, not guessed. Every
one of the following was a real, load-bearing discovery, not an assumption carried over from
R05/R06's own Napi-specific facts:

- **c2cpg does NOT macro-expand `NAN_METHOD`/`NAN_METHOD_ARGS_TYPE`.** A real
  `NAN_METHOD(Name)`-declared method's own `info` parameter shows up in `parameters.tsv` with
  `typeFullName` exactly `Nan.NAN_METHOD_ARGS_TYPE` (Joern's dot-qualified rendering) --
  **not** `v8::FunctionCallbackInfo<v8::Value>`, which is what the macro would expand to. This
  is the real marker `JS_CALLBACK_ORIGIN_TYPES` matches on -- a different literal string from
  R06's own `Napi::CallbackInfo`/`Napi.CallbackInfo`, confirmed empirically, not assumed by
  analogy.
- **`Nan::NewBuffer`/`Nan::CopyBuffer` resolve to the SAME unresolved-call shape** R05 already
  found for `Napi::Buffer::New`: `<unresolvedNamespace>.NewBuffer:<unresolvedSignature>(N)`,
  with `N` the real argument count. Confirmed for all three real overloads: `(data, size, cb,
  hint)` -> arity 4, size at argument index 2; `(size)` -> arity 1, size at index 1; `(data,
  size)` -> arity 2, size at index 2. `Nan::CopyBuffer(data, size)` -> arity 2, size at index
  2, source at index 1. Nan has **no `env` argument** on any of these (unlike every real
  `Napi::` static factory) -- `size_arg_index` is genuinely arity-dependent here, not a fixed
  constant the way R04/R05's Napi contracts have it.
- **A chained method call's receiver IS represented as argument index 0.** Real corpus code
  (node-snap7's own `Nan::To<int32_t>(info[3]).FromJust()`) is a receiver chain, not an
  out-parameter call -- confirmed via raw facts: the `.FromJust()` call's own `arguments.tsv`
  row at index 0 is the `Nan::To<int32_t>(info[3])` call itself (kind `CALL`). This is a
  **different, simpler, and (on real corpus evidence) more common** dataflow shape than
  R06/FIX01I's own out-parameter-specific `get_u64(env, info[N], "name", &var)` idiom --
  `find_js_index_source_for_value`'s "direct-chain" check (does the walk ever visit a CALL that
  is itself `<operator>.indirectIndexAccess` on a CallbackInfo-typed identifier) is the PRIMARY
  path for Nan; the out-parameter shape is kept as a secondary, structurally-parallel check for
  completeness, but is **not confirmed on any real Nan corpus site read for this capability** --
  disclosed, not fabricated as observed-real.
- **`Nan::SetPrototypeMethod(tpl, "name", Class::Method)` and `Nan::SetMethod(target, "name",
  Fn)` share IDENTICAL structural shape**, both empirically verified: a real
  `<unresolvedNamespace>.Set(PrototypeMethod|Method):<unresolvedSignature>(3)` call whose 3rd
  argument is a real `METHOD_REF` node carrying the **bare, unqualified function name** as its
  own `code` field. This is simpler and more reliable than R06/FIX01I's own
  `InstanceMethod<&Class::Method>` idiom, which needed a text regex over the call's own `code`
  because Joern does not expose a template argument as a structured node -- Nan's real
  registration idiom needs no such fallback.
- **A real, complete end-to-end JS-native link was independently reproduced**: a real
  `pkg/index.js` (mirroring node-snap7's own actual `S7Client.prototype.DBRead = function
  (dbNumber, start, size, cb) { return this.ReadArea(...) }` wrapper idiom exactly) was run
  through real `jssrc2cpg`, and the resulting real JS `calls.tsv`/`arguments.tsv` confirmed the
  SAME 1-based argument-index convention (index 0 = the call's own receiver, `this`) FIX01I's
  own tooling established for a different corpus -- independently re-verified here, not
  assumed to transfer. `info[N]` (0-based) still corresponds to JS schema index `N + 1`.
- **A real, confirmed c2cpg parser artifact**: unresolved C++ template angle brackets
  (`v8::Local<v8::Object> ret`) are mis-lexed as `<operator>.greaterThan`/`<operator>.lessThan`
  CALLS. Directly observed on the fixture's own `GuardedLike` method: a REAL comparison
  (`size > 65536`, operands `IDENTIFIER "size"` / `LITERAL "65536"`) sits alongside a SPURIOUS
  one from the very next line's template syntax (operands `CALL "v8::Local<v8::Object"` /
  `IDENTIFIER "<unknown> ret"`). `find_upper_bound_check` only accepts a comparison whose own
  operand is an IDENTIFIER matching a name the size-trace walk actually visited -- a structural
  filter that rejects the artifact by construction, not a blocklist.
- **`<operator>.new` wraps `<operator>.alloc` as its own index-1 argument**; `<operator>.alloc`'s
  own index-2 argument is the real allocation-size operand (index-1 is the allocated TYPE,
  e.g. `char`). Confirmed on both `CopyGoodLike` (`new char[size]` -> alloc size IDENTIFIER
  `"size"`) and `CopyMismatchLike` (`new char[128]` -> alloc size LITERAL `"128"`).

## 3. Nan's real allocation/failure semantics (why R04-R06's exception gate does not apply)

Read `nan.h` directly for all three real resolved versions (2.14.2, 2.26.2, 2.28.0 -- Section
1), not assumed from the `Napi::Buffer<T>::New` analogy:

```cpp
inline MaybeLocal<v8::Object> NewBuffer(char *data, size_t length, ..., void *hint) {
  assert(length <= imp::kMaxLength && "too large buffer");   // kMaxLength = 0x3fffffff
  return node::Buffer::New(v8::Isolate::GetCurrent(), data, length, callback, hint);
}
```

- Returns `v8::MaybeLocal<v8::Object>` -- a raw V8 API type, not a `napi_status`-backed result.
  Every real corpus call site read across this whole effort (the prevalence study and this
  capability's own development/control packages) calls `.ToLocalChecked()` unconditionally.
- The `assert(length <= imp::kMaxLength ...)` bound is a **plain C `assert()`** -- compiled to
  a no-op in a release (`NDEBUG`) build, the normal npm-install configuration. It does **not**
  actually enforce the ~1 GiB bound at runtime in a real installed addon.
- `.ToLocalChecked()` on an **empty** `MaybeLocal` (the real failure case) invokes V8's own
  fatal-error path, which **terminates the process** -- a hard abort, not a catchable
  exception and not a `napi_status` a caller can branch on.

R04-R06's whole applicability axis ("exceptions enabled" -> `CONTRACT_NOT_APPLICABLE`,
"exceptions disabled" -> the contract's premise holds) is built specifically around
`Napi::Buffer<T>::New`'s `NAPI_THROW_IF_FAILED` semantics (throw a catchable exception, or
leave a pending exception when exceptions are disabled). **Neither branch of that axis
describes Nan's real behavior** -- there is no Nan-side "exceptions disabled" state at all; the
failure path is unconditionally a fatal abort regardless of any node-gyp exception-handling
flag. Porting that gate to Nan would be a structural non sequitur, not merely an unnecessary
dependency -- this is why the capability does not carry any applicability gate at all in this
first pass (see Section 6, "not yet built").

## 4. Reachable security consequence (why a positive finding is a "static candidate", never a
   vulnerability claim)

Per the explicit instruction not to call an unguarded allocation a vulnerability without
establishing a reachable consequence, every `NAN_NEWBUFFER_UNBOUNDED_ALLOCATION` finding states
two real, disclosed, structurally-grounded consequences (verbatim in the finding's own
`evidence_note`, `NON_VULN_DISCLAIMER` in `resource_guard_verdict_nan.py`) without asserting a
CWE or exploitability:

1. **Fatal abort (DoS)**: an oversized or failed allocation makes `node::Buffer::New`/`Copy`
   return empty; `.ToLocalChecked()` then triggers V8's fatal-error path and terminates the
   process -- confirmed from Section 3's own source read, not a guess.
2. **Unbounded memory / integer-overflow risk**: with no detected application-level cap, a
   successful allocation of attacker-influenced size risks excessive memory consumption; where
   the size is the PRODUCT of two JS-controlled factors (node-snap7's own real `ReadArea`
   shape: `amount * byteCount`), integer overflow could yield a small allocated size while a
   later native call still writes the full, uncapped amount -- a real, disclosed, but **not
   independently verified in this pass** downstream-write-mismatch risk (this capability does
   not trace the downstream native write call to confirm it actually happens).

`NAN_COPYBUFFER_SOURCE_CAPACITY` findings are explicitly framed as an out-of-bounds-**read
shape** (`Nan::CopyBuffer` reads `size` bytes starting at `data`) -- real and disclosed, but
not a confirmed OOB read: the finding establishes a structural capacity/length mismatch, not
that the mismatch is reachable with a length that actually exceeds the real allocated
capacity.

## 5. Real, end-to-end validation

### 5.1 Comprehensive synthetic fixture (9 cases, 25/25 assertions passing)

`study/nan_capability/controls/comprehensive_fixture/` -- real raw facts from an actual
c2cpg/jssrc2cpg run (`build_fixture.sh` reproduces them), covering every contract-boundary
decision this capability makes: JS-argument-controlled positive (2 shapes: 4-arg and 2-arg
`NewBuffer` overloads), an explicit-bound-check negative, a literal-size negative, a
never-registered negative, a registered-but-never-called negative, and all three CopyBuffer
outcomes (capacity matches, capacity mismatch, capacity unresolved). See
`tests/test_resource_guard_verdict_nan.py` -- 25/25 real assertions passing.

### 5.2 Real corpus runs

`node-snap7` (the designated development case, per instruction -- not a blind test) run
through the real pipeline, its three real client-side sites (`ReadArea`, `Upload`,
`FullUpload`) and one real server-side site treated as SEPARATE, independently-evaluated call
sites (not folded together), plus the six real, independently-verified negative-control
packages the prevalence study identified (`murmurhash-native`, `msgpack`,
`@confluentinc/kafka-javascript`, `scrypt`, `libpq`, `phplike`) run the same way. Real results
in `study/nan_capability/corpus_runs/<package>/run_result.json` and Section 7 below.

## 6. Two real bugs found and fixed by running against diverse real corpus code (not by
   inspection or assumption)

Both caught the same way every real defect in this whole project's lineage has been caught:
by running the actual tool against real, independent packages and treating a surprising
result as a signal to re-verify, not a false alarm to explain away.

**Bug 1 -- registration bare-name collision (found on `node-snap7`).** The first version of
`extract_registrations` matched a `SetPrototypeMethod`/`SetMethod` call's function-reference
argument against candidate functions by BARE NAME across the whole translation unit. Real
node-snap7 facts showed 5 real, distinct method nodes named `ReadArea` (header declaration,
out-of-line definition, and other real c2cpg-parsed duplication of the same real class) --
`extract_registrations` correctly refused to guess among them (`"5 candidate functions for
'ReadArea' (need exactly 1)"`), which meant `ReadArea`/`Upload`/`FullUpload` all fell through
to `NOT_JS_REGISTERED` even though they ARE really registered. Fixed with class-scoped
disambiguation: the registration call's own ENCLOSING method supplies a real class prefix
(`_class_prefix`, the same `Class.Method:Sig(...)` splitting convention R04/R05 already use
for contract matching), narrowing candidates to the SAME class; a second real tiebreak (prefer
the one candidate with `line_end != line_start`, i.e. a real function body, when exactly one
such candidate remains) resolves the header-declaration-vs-definition case. After the fix,
registrations went from 3 to 61 real entries on node-snap7, and `ReadArea` correctly resolved.

**Bug 2 -- opaque-call argument over-chasing (found on `libpq`).** The backward walk's
call-argument-chasing (`find_js_index_source_for_value`'s `else` branch) originally chased
EVERY argument of every visited call, unconditionally. Real libpq facts showed this is
unsound: `Nan::NewBuffer(buffer, length, ...)` where `length = PQgetCopyData(self->pq,
&buffer, async)` -- the walk chased `async` (a WHOLLY UNRELATED boolean argument of
`PQgetCopyData`, not what determines `length`, which is libpq's own internal byte count) all
the way back through `async = info[0]->IsTrue() ? 1 : 0` to a real `info[0]` access, and
reported `length` as JS-argument-controlled. True for `async`; false, and the thing that
actually matters, for `length`. Fixed by restricting non-receiver (non-index-0) argument
chasing to an explicit, narrow, disclosed allowlist of Nan/V8 helpers CONFIRMED (by reading
`nan.h`) to derive their return value from that argument (`KNOWN_VALUE_DERIVING_CALLS = {"To"}`
at present) -- receiver-index-0 chasing (`X.Method()`, e.g. `.FromJust()`) and real C++
OPERATOR calls (`<operator>.multiplication` etc., which use 1-based operand indexing with no
receiver at all, and where every operand genuinely determines the result) both remain
unconditional, since both are structurally sound patterns confirmed on real corpus code.
Fixing this correctly turned `libpq`'s `GetCopyData` from a false positive trace into the
correct `SOURCE_BOUNDARY_UNRESOLVED`, without regressing node-snap7's own real `ReadArea`
positive (re-verified end-to-end after the fix -- same real `js_call_id`, same
`callback_info_index`/`js_argument_index`) or any of the 25 fixture assertions.

Both bugs are real, disclosed, honest under-approximations corrected in the direction of
LESS promotion, never more -- consistent with the whole project's abstain-when-uncertain
discipline. Neither would have been found by inspecting the synthetic fixture alone; both
required running against real, structurally diverse corpus code.

## 7. Real corpus results

See `study/nan_capability/corpus_runs/<package>/run_result.json` and `nan_verdict.json` for
the full, real evidence records (post both fixes in Section 6). Summary:

| Package | Role | Positives | Notable abstentions |
|---|---|---|---|
| `node-snap7` | development case | 1: `ReadArea` (`ReadArea`/`Upload`/`FullUpload` all confirmed real info[N]+registration; only `ReadArea` also has a confirmed real JS call site in the package's own bundled wrapper -- `Upload`/`FullUpload` correctly abstain `JS_CALL_UNRESOLVED`, not promoted on registration alone) | `HandleReadWriteEvent` (server-side, network-controlled, matches `R05_INTERIM_NEAR_MISS_AUDIT.md`'s existing finding) correctly `SOURCE_BOUNDARY_UNRESOLVED` for both contracts |
| `node-snap7-micro-client` | same source, separate npm identity | 1: `ReadArea`, same shape | same pattern as node-snap7 (no server component, so no CopyBuffer candidates at all) |
| `murmurhash-native` | negative control | 0 | `HashSize` (compile-time constant) correctly unresolved, not literal-tagged (see Section 8) |
| `msgpack` | negative control | 0 | `sb->size` (library-computed) correctly unresolved |
| `@confluentinc/kafka-javascript` | negative control | 0 | 2 literal-0 fallback sites correctly `SIZE_LITERAL_NOT_APPLICABLE`; 2 correctly unresolved |
| `scrypt` | negative control | 0 | 2 literal-96/other sites correctly `SIZE_LITERAL_NOT_APPLICABLE`; 1 `NOT_JS_REGISTERED` |
| `libpq` | negative control | 0 | `GetCopyData` correctly `SOURCE_BOUNDARY_UNRESOLVED` post Section 6 Bug 2 fix (was a false positive pre-fix) |
| `phplike` | negative control | 0 | `nodeSocketReceive`'s out-parameter `resLength` correctly unresolved |

**Zero false positives across all 6 independently-verified negative-control packages.** The
one real, structurally distinct positive (`node-snap7`'s `ReadArea`) is reported as a STATIC
CANDIDATE per Section 4's disclaimer, not a vulnerability or CWE claim.

## 8. Explicitly not built in this pass

- **`SIZE_LITERAL_NOT_APPLICABLE` vs. `SOURCE_BOUNDARY_UNRESOLVED` categorization is
  slightly coarser than ideal, disclosed rather than fixed.** `SIZE_LITERAL_NOT_APPLICABLE`
  only fires when the acquisition call's OWN size argument is itself a literal at the call
  site. A value that is an IDENTIFIER whose own assignment chain terminates at a literal one
  or more hops back (e.g. `murmurhash-native`'s real `HashSize` compile-time-template-constant
  case, or node-snap7's own `int size = 65536; ...NewBuffer(bufferData, size, ...)`) instead
  falls out of the backward walk with no result at all, and is reported as
  `SOURCE_BOUNDARY_UNRESOLVED`. Both are correctly NEVER promoted -- this is a categorization
  precision gap, not a correctness gap -- but a future pass could walk the literal-termination
  case explicitly and re-tag it, giving a clearer signal for why each site abstained.
- **No applicability/failure-mode gate.** Section 3 established WHY R04-R06's gate does not
  transfer; designing Nan's own real gate (should a finding be suppressed when, say, a build
  disables `node::Buffer`'s own internal limit checks some other way?) is real, separate
  design work, not attempted here. Every finding in this pass is unconditionally a candidate
  once the structural evidence chain holds -- no applicability abstention bucket exists yet.
- **No blind-test package.** Per instruction, the capability is frozen (`NAN_CAPABILITY_FREEZE.md`)
  before any blind-test package is selected or read -- that selection is explicitly deferred to
  the next phase.
- **Downstream-use tracing** for the integer-overflow consequence named in Section 4 (does the
  traced native call that WRITES into the allocated buffer actually use the same uncapped
  `amount`/`byteCount` pair, independently of the allocation's own `size`?) -- named as a real,
  disclosed limitation, not evaluated here.
