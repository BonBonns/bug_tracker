# Buffer-allocation contract-family prevalence study

Corpus-wide census of which Buffer-allocation entry points the 494-package eligible corpus
actually uses, run to decide the next capability to build after `R05_INTERIM_NEAR_MISS_AUDIT.md`
found that R05/R06 model only `Napi::Buffer<T>::New` while at least one real package
(`node-snap7`) uses `Nan::NewBuffer`/`Nan::CopyBuffer` instead. Conducted on a new, isolated
branch (`claude/nan-prevalence-study`, off `claude/r05-near-miss-audit`) for tooling access
only. **No scanner, contract, exporter, or normalizer file was modified.** The live R05 scan
(`claude/aggregate-kinds-producer-test-03zs7n`, PID 6956) was not touched, raced, or slowed --
this study re-downloads each package's own pinned tarball independently, on its own process.

## 1. Method and disclosed limitation

`scan_contract_families.py` re-fetched all 494 packages' own pinned `tarball_url`s from
`eligible_packages.tsv` (the same corpus population, same pins, R05 already scanned), extracted
each into a throwaway temp dir, regex-matched every `.c/.cc/.cpp/.cxx/.h/.hh/.hpp/.hxx` file
against six call-shape patterns, and deleted the extraction before moving to the next package.
**494/494 packages fetched and scanned successfully -- 0 download/extract failures.**

**This is a textual census, not a CPG-verified one -- stated up front, not discovered later.**
R05 itself resolves call identity through Joern's real type system; a regex over raw source
can false-positive on a comment/string/disabled `#if 0` block (not stripped here, disclosed,
not silently ignored) and false-negative on an unusual line break or macro alias. One concrete,
confirmed defect this exact risk caused and required a fix for: this script's first run counted
`node-addon-api`'s own vendored `napi-inl.h` -- the **definition** site of `Buffer<T>::New`, not
a consumer call -- as a hit. Fixed by excluding a disclosed, precise set of known
library-interface header basenames (`napi.h`, `napi-inl.h`, `nan.h`, and nan's real v2.x header
set) rather than a general comment/string stripper; re-verified clean on node-addon-api
afterward (zero hits). This census is therefore a **prevalence signal for deciding which
capability to build next**, not a claim of exact real call-site counts -- every site this
document cites as evidence is separately confirmed by direct source reading, listed in Section 3.

Six families, matching the exact "New"/"Copy"-shaped Buffer-allocation scope the request asked
this census to cover (not a general native-call census):

| Family | Pattern |
|---|---|
| `NAPI_BUFFER_NEW` | `Napi::Buffer<T>::New(...)` -- R05's own existing family |
| `NAN_NEWBUFFER` | `Nan::NewBuffer(...)` |
| `NAN_COPYBUFFER` | `Nan::CopyBuffer(...)` |
| `RAW_NAPI_BUFFER` | `napi_create_buffer` / `napi_create_buffer_copy` / `napi_create_external_buffer` |
| `V8_NODE_BUFFER` | `node::Buffer::New(...)` / `v8::ArrayBuffer::New(...)` |
| `BARE_BUFFER_NEW` | unqualified `Buffer::New(...)`/`Buffer::Copy(...)` (catches `using namespace Napi;`-style call sites the qualified regexes miss -- namespace is **not** resolved from text, so this family is the noisiest and is flagged as such below) |

## 2. Prevalence table (the decision-relevant result)

| Family | Eligible packages | Real call sites (textual) |
|---|---:|---:|
| **`NAN` (NewBuffer ∪ CopyBuffer)** | **38** | **104** (65 NewBuffer + 39 CopyBuffer) |
| `NAPI_BUFFER_NEW` (existing R05 coverage) | 29 | 72 |
| `RAW_NAPI_BUFFER` (raw N-API C calls, 0 overlap with `NAPI_BUFFER_NEW`) | 26 | 89 |
| `BARE_BUFFER_NEW` (unqualified -- unverified, see below) | 20 | 34 |
| `V8_NODE_BUFFER` (raw V8/Node internals) | 14 | 39 |

**Nan is the largest single family in the corpus -- larger than the family R05/R06 already
model.** This confirms the user's stated hypothesis with real counts, not just the one
`node-snap7` example the audit found. `RAW_NAPI_BUFFER` has zero package overlap with
`NAPI_BUFFER_NEW` (packages calling the raw C N-API directly never also use the C++
`Napi::Buffer<T>::New` wrapper in this corpus) -- a third, structurally distinct contract family
in its own right, noted for a future study but out of scope for the immediate Nan decision.
`BARE_BUFFER_NEW`'s 20 packages are real npm packages (`ffi-napi` family, `zlib`, `native-reg`,
`mongodb-client-encryption`, ...) but the unqualified pattern cannot distinguish a real Node
`Buffer::New`/`Buffer::Copy` call from an unrelated class's own same-named method -- exactly the
"23,951 rejected candidates are overwhelmingly unrelated constructors" risk already established
for R05's literal `"New"` gate. Not selected as the next capability on this signal alone.

Real methodological note: `node-snap7` (1.0.9) and `node-snap7-micro-client` (0.1.0) are
near-identical forks (same file layout, same buffer-allocation code, confirmed by direct read)
but the corpus's own `unique_source_trees.tsv` dedup does **not** collapse them (distinct
`source_tree_hash`, `n_associated_identities: 1` each) -- so by the same definition the rest of
R05/R06 already uses for the corpus, they are counted as two real, separate eligible packages
here too. No additional dedup correction applied.

## 3. Manually verified origin classification (real source reads, not the heuristic)

A first-pass heuristic (`classify_origins.py`) tagged every hit from its captured 25-line
context window (`JS_ARGUMENT_CANDIDATE` if an `info[`/`args[` accessor appears nearby,
`EXTERNAL_NETWORK_CANDIDATE` for socket/protocol vocabulary, else `NATIVE_INTERNAL_CANDIDATE` or
`UNRESOLVED`). **This heuristic is disclosed as proximity-based triage, not a dataflow proof --
and real reads below confirm it has a high false-positive rate**, the same lesson Phase B
already learned for `Napi::Buffer::New` ("do not treat JS reachability as proof the size traces
to a JS argument"). Of the 8 packages the heuristic flagged as `NAN_NEWBUFFER` +
`JS_ARGUMENT_CANDIDATE`, every one was fetched and read directly:

| Package | Site | Real classification (verified by direct read) |
|---|---|---|
| `node-snap7` / `node-snap7-micro-client` | `node_snap7_client.cpp:1278` `S7Client::ReadArea` | **CONFIRMED JS_ARGUMENT_CONTROLLED.** `size = amount * byteCount`, both from `Nan::To<int32_t>(info[3])`/`info[4]`; `new char[size]` with **no bounds/sign check** before the allocation -- only `IsInt32()` type checks. Genuinely matches Phase B's 3-condition promotion boundary (registered `NAN_METHOD`, JS args, size terminates at `info[N]`). |
| `node-snap7` / `node-snap7-micro-client` | `node_snap7_client.cpp:1742` `S7Client::Upload` | **CONFIRMED JS_ARGUMENT_CONTROLLED**, same shape: `new char[Nan::To<int32_t>(info[2]).FromJust()]`, no bound check. |
| `node-snap7` / `node-snap7-micro-client` | `node_snap7_client.cpp:1775` `S7Client::FullUpload` | **CONFIRMED JS_ARGUMENT_CONTROLLED**, same shape as `Upload`. |
| `node-snap7` / `node-snap7-micro-client` | `node_snap7_client.cpp:1846` `S7Client::DBGet` | Heuristic false positive -- `size = 65536` is a fixed literal; `info[` in the window belongs to an unrelated callback-function check. **NATIVE_INTERNAL (literal).** |
| `node-snap7` / `node-snap7-micro-client` | `node_snap7_client.cpp:2101` `S7Client::ReadSZL` | Heuristic false positive -- `size = sizeof(TS7SZL)`, a compile-time struct size. **NATIVE_INTERNAL (literal).** |
| `murmurhash-native` | `nodemurmurhash.cc:253` | Heuristic false positive -- `Nan::NewBuffer(HashSize)`, `HashSize` is a template compile-time constant; the `info[outputTypeIndex]` in the window belongs to an unrelated output-mode branch. **NATIVE_INTERNAL (literal).** |
| `msgpack` | `msgpack.cc:290` `pack()` | `Nan::NewBuffer(sb->data, sb->size, ...)` -- `sb->size` is tracked internally by the vendored `msgpack_sbuffer` C library as it packs, not a raw `info[N]` value. Matches the boundary's explicit "linked function whose allocation size is internally computed" exclusion. **NATIVE_INTERNAL (library-computed), not JS-argument.** |
| `@confluentinc/kafka-javascript` | `producer.cc:501/533` | Heuristic false positive -- `Nan::NewBuffer(new char[0], 0)` is a fixed 0-length fallback for a null message buffer; `info[2]`/`info[3]` in the window feed an *existing* Buffer's own data/length via `node::Buffer::Length/Data`, not this call. **NATIVE_INTERNAL (literal).** |
| `scrypt` | `scrypt_kdf_sync.cc:22` | Heuristic false positive -- `Nan::NewBuffer(96)`, 96 is scrypt's fixed KDF output length. **NATIVE_INTERNAL (literal).** |
| `libpq` | `connection.cc:710` `GetCopyData` | `length = PQgetCopyData(self->pq, &buffer, async)` -- length is libpq's own return value from a Postgres `COPY` protocol response; `info[0]` only supplies the `async` boolean, not the size. **EXTERNAL_NETWORK_CONTROLLED_OUT_OF_CURRENT_JS_SCOPE**, same shape/category as `node-snap7`'s server-side case in the audit. |
| `phplike` | `phplikeSocket.cc:58` `nodeSocketReceive` | `resLength` is an **out-parameter** set by `phplikeSocketReceive(sockfd, length, &resLength)`; the JS-controlled `info[1]` supplies the *requested* length, but the buffer's real size is the native call's own out-parameter. Matches the boundary's explicit "unresolved out-parameter trace" exclusion. **UNRESOLVED (out-parameter), not a direct JS-argument feed.** |

**Real result: of 8 heuristically flagged packages, only `node-snap7`
(and its near-duplicate `node-snap7-micro-client`) is a confirmed real JS-argument-controlled,
apparently-unguarded case -- and it has three such sites, not the one already documented in the
audit.** The other six are confirmed real negatives across every excluded shape the Phase B
boundary already names (literal, compile-time constant, library-computed, out-parameter). This
is honest, useful evidence either way: it strengthens `node-snap7` as a development case (richer
test surface than previously known) and it demonstrates, with real code rather than assumption,
that a future Nan capability needs the same narrow dataflow discipline Phase B already built for
Napi -- proximity to `info[` is not sufficient on its own.

## 4. Nan's real allocation/failure semantics (verified against `nan@2.28.0`'s own source)

Fetched the real, current `nan` npm package and read `nan.h` directly (not assumed from name
similarity to `Napi::Buffer<T>::New`, per the explicit instruction not to treat them as
automatically equivalent):

```cpp
inline MaybeLocal<v8::Object> NewBuffer(char *data, size_t length, ..., void *hint) {
  assert(length <= imp::kMaxLength && "too large buffer");   // kMaxLength = 0x3fffffff
  return node::Buffer::New(v8::Isolate::GetCurrent(), data, length, callback, hint);
}
```

Confirmed structural differences from `Napi::Buffer<T>::New`, both real and load-bearing for any
future guard/applicability model -- **not the same contract, confirmed by reading the source,
not assumed**:

- `Nan::NewBuffer`/`Nan::CopyBuffer` return `v8::MaybeLocal<v8::Object>`, a **raw V8 API type**,
  not a `napi_status`-backed result. Every real corpus call site reviewed above calls
  `.ToLocalChecked()` unconditionally.
- The `assert(length <= imp::kMaxLength ...)` bound check is a **plain C `assert()`** --
  compiled to a no-op in an `NDEBUG` (release) build, which is the normal npm-install
  configuration. It does **not** actually enforce the ~1 GiB (`0x3fffffff`) bound at runtime in
  a real installed addon.
- `.ToLocalChecked()` on an **empty** `MaybeLocal` (the real failure case -- V8 allocation
  failure, or `node::Buffer::New` internally rejecting an out-of-range length) invokes V8's own
  fatal-error path, which **terminates the process**. This is a hard crash/DoS failure mode, not
  a catchable JS exception and not a `napi_status` a caller can branch on.
- Consequently, R06's own "exceptions enabled/disabled" build-target applicability axis --
  built specifically around `Napi::Buffer<T>::New`'s `NAPI_THROW_IF_FAILED` semantics (throw a
  catchable exception, or leave a pending exception when exceptions are disabled) -- **does not
  apply to Nan at all**. There is no Nan-side equivalent of "exceptions disabled"; the failure
  path is unconditionally a fatal abort regardless of any node-gyp exception-handling flag.

**This is the concrete evidence behind the instruction not to reuse R05's guard model as-is: a
Nan capability needs its own applicability/failure-mode gate, not a port of the Napi one.**
Designing that gate is out of scope for this study (a prevalence census), and is flagged as the
first real design task for the next phase.

## 5. `node-snap7` as development case (not a blind test)

Per instruction, `node-snap7` is the **designated development case** for building and testing
the Nan capability -- not eligible as its blind test. Section 3 shows it now has two structurally
different, both real, both already-classified cases in one package, which makes it a genuinely
good development fixture (not just a coverage-gap example):

- **Server-side** (`node_snap7_server.cpp:813`, already in `R05_INTERIM_NEAR_MISS_AUDIT.md`):
  `size = byteCount * rw_event_baton_g.Tag.Size`, sourced from the vendored `snap7` C library's
  own S7-protocol event mechanism -- `EXTERNAL_NETWORK_CONTROLLED_OUT_OF_CURRENT_JS_SCOPE`, a
  case the future capability must correctly **decline** to promote.
- **Client-side** (`node_snap7_client.cpp:1278/1742/1775`, newly confirmed by this study): three
  real `NAN_METHOD`s where the allocation size traces directly to `info[N]` with no bound check
  -- cases the future capability must correctly **promote**, mirroring exactly the positive case
  Phase B built for Napi/Cartesi.

One package, one real positive test surface and one real negative test surface, both already
source-verified -- exactly what a development case needs.

## 6. Blind-test candidates for the future capability

**Honest, disclosed limitation: no confirmed real *positive* JS-argument-controlled Nan case
was found in this study outside of `node-snap7` itself.** The six other heuristically flagged
packages (Section 3) all resolved to real negatives. This does not mean none exist elsewhere in
the corpus -- only the 8 heuristically flagged `NAN_NEWBUFFER` packages were read in full; the
other 30 Nan-family packages (`NAN_COPYBUFFER`-only hits, and the `UNRESOLVED`/
`NATIVE_INTERNAL_CANDIDATE`-tagged `NAN_NEWBUFFER` sites) were not individually read in this
pass. Finding and verifying a genuine positive blind-test package (distinct from `node-snap7`)
is deferred to the next phase, not fabricated here.

What this study *does* provide for that phase, real and already verified:

- **Confirmed negative-control candidates** (useful for the future capability's own test suite,
  the same role `node-crc16` plays for R05): `murmurhash-native`, `scrypt`, `kafka-javascript`
  (literal/constant sizes), `msgpack` (library-computed size), `libpq`, `phplike`
  (network/out-parameter sizes) -- six real packages, six different disqualifying shapes, all
  already source-verified above.
- **A real second package with the exact same S7 codebase but a different npm identity**
  (`node-snap7-micro-client`) -- available as a low-cost sanity check that a frozen capability's
  verdict is stable across two independently-tarballed copies of nearly the same source, though
  not a substitute for a genuinely distinct blind test.

## 7. Recommendation

1. **Build the Nan capability next.** Real prevalence supports it directly: 38 packages / 104
   call sites, the single largest uncovered family in the corpus, larger than R05's own existing
   `Napi::Buffer<T>::New` coverage (29 packages / 72 sites).
2. **Scope it to `Nan::NewBuffer`/`Nan::CopyBuffer` only**, matching the current narrow
   `Napi::Buffer<T>::New`-only scope of R05/R06 -- do not fold in `RAW_NAPI_BUFFER` or
   `V8_NODE_BUFFER` in the same pass; they are real, separate families (Section 2) that deserve
   their own prevalence-driven decision later, not an opportunistic bundle-in now.
3. **Design a Nan-specific applicability/failure-mode gate before reusing any guard logic** --
   Section 4's real semantics (fatal-abort-on-empty, no enforced release-build bound) rule out a
   direct port of R06's exceptions-enabled/disabled axis.
4. **Use `node-snap7` as the development case**, with both its confirmed positive sites
   (`ReadArea`/`Upload`/`FullUpload`) and confirmed negative site (server-side S7 event data) as
   the fixtures to build the promotion boundary against.
5. **Freeze the capability, then blind-test it** on a real package not yet read for this purpose
   -- Section 6's negative controls are available immediately; a genuine positive blind-test
   package still needs to be found and verified in that next phase, not assumed from this study.

This study's own scope ends here -- it is a prevalence census and semantics investigation, not
an implementation. No Nan capability, contract, or guard logic was added to the scanner in this
pass, consistent with holding scanner changes until a reviewed batch of evidence is frozen.

## 8. Claims boundary

- The 38-vs-29-package prevalence comparison is real, corpus-wide, and 494/494-complete (0
  download failures) -- but textual, not CPG-verified (Section 1).
- The 11 manually verified classifications in Section 3 are real, source-confirmed reads of the
  exact pinned tarballs the corpus already uses -- not samples of samples, not heuristic output
  presented as fact.
- The Nan semantics in Section 4 are read directly from `nan@2.28.0`'s real, current source, not
  inferred from documentation or assumed from the Napi analogy.
- `node-snap7`'s three newly-confirmed client-side sites are additional real evidence beyond
  what `R05_INTERIM_NEAR_MISS_AUDIT.md` already established for the same package -- they
  strengthen, and do not contradict, that document's existing `CONTRACT_COVERAGE_GAP` finding.
- No real, verified positive blind-test candidate (other than `node-snap7`) exists yet -- stated
  as a limitation, not implied to be solved.
