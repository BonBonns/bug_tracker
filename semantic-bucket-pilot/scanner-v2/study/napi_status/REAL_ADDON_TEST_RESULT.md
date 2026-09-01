# Real pinned-addon runtime test — @8crafter/leveldb-zlib@1.6.0 (v3, offset-verified)

Supersedes the v2 `--wrap` result (`real_addon_test/v2_unconditional_arm_superseded/`),
which armed interposition unconditionally at every call reaching the wrapper. Per
review, that is not itself a proof that the armed calls were the two real target call
sites — it happened to be correct here, but wasn't verified. This revision fixes that:
it discovers and freezes the exact call-site identity of the two `napi_create_buffer_copy`
sites and their two corresponding `napi_set_element` sites from an unmodified "mapping"
run, and arms interposition only at those frozen offsets. The prebuilt result
(section 4) is unchanged from v2 and is repeated here for a complete record.

## 1. Identity (recorded and independently re-verified before any test)

| field | value |
|---|---|
| package | `@8crafter/leveldb-zlib` |
| version | `1.6.0` |
| tarball_sha256 | `8f2213a074ae4312a03ac9137811bdd3eaa07ccb8af48420b5a08edd02460412` |
| `.node` binary (`prebuilds/linux-6-x64/node-leveldb.node`) sha256 | `88a6a397dcec702dd901a764482b5b46a211247b19bf1ede97b222b9c8726abc` |
| architecture | ELF 64-bit LSB, x86-64 |
| Node version | v22.22.2 |
| ABI (`process.versions.modules` / `.napi`) | 127 / 10 |
| source's own pinned N-API version | `NAPI_VERSION 3` (`bindings.cpp:1`) |
| compiler / linker | gcc 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1) / GNU ld (GNU Binutils for Ubuntu) 2.42 |
| Node headers | `~/.cmake-js/node-x64/v22.22.2/include/node` (via cmake-js 7.4.0, the package's own build tool) |
| build flags | `-DBUILDING_NODE_EXTENSION -O3 -DNDEBUG -DLEVELDB_PLATFORM_POSIX -DNAPI_VERSION=3` plus the test-only `-Wl,--wrap=napi_create_buffer_copy -Wl,--wrap=napi_set_element` |
| rebuilt `.node` sha256 (`build_wrap/Release/node-leveldb.node`) | `a4e5a7a274f68a8cacb649f58cfe9ada34dbd157375cb4baccee28d617e2afdc` |

## 2. Unmodified addon: loads, real `iterator_next` baseline

The unmodified, verified prebuilt loads under Node v22.22.2 and completes the real
public JS API path (`db.open() → db.put("k1","v1") → db.getIterator() → it.next()`)
normally: **exit 0**, real buffer values returned.

## 3. Dynamic symbol inspection (`readelf -Ws`)

Both `napi_create_buffer_copy` and `napi_set_element` are **UND** (dynamically
imported) in the shipped prebuilt, in both `.symtab` and `.dynsym` — resolved at
load time against the host `node` process (`real_addon_test/readelf_dynsym_v2.txt`).

## 4. Prebuilt `LD_PRELOAD` attempt → `PREBUILT_INTERPOSITION_UNAVAILABLE`

Unchanged from v2. Run against the real prebuilt, both unarmed and armed
(`NAPI_SHIM_ARM_BUFFER_COPY=1`): zero `[shim]` lines in stderr in either condition
(`real_addon_test/ld_preload_v2_{unarmed,armed}_stderr.log`), independently confirmed
via `LD_DEBUG=bindings` (`real_addon_test/ld_preload_v2_binding_evidence.txt`) showing
both symbols binding directly to `node`, never to the preloaded library.

**Status: `PREBUILT_INTERPOSITION_UNAVAILABLE`.** `LD_PRELOAD` cannot intercept these
two symbols against this specific prebuilt-addon/node-binary combination. This is a
property of the **shipped prebuilt only** — no failure was ever injected into it, so
the shipped prebuilt's own runtime behavior under an injected failure remains
**unestablished**, not confirmed either way.

## 5. Source-build fallback: offset-verified `--wrap` interposition

Built from the pinned tarball's own source (`cmake-js`/CMake, the package's own real
build tooling) with a **test-only** addition (`src/wrap_interpose_v3_TESTONLY.cpp`,
`-Wl,--wrap=napi_create_buffer_copy -Wl,--wrap=napi_set_element` appended to
`CMakeLists.txt`) — never committed to the package's own tree; the added source file
and the `CMakeLists.txt` change were removed, and the original prebuilt binary
restored (verified by hash) immediately after testing
(`real_addon_test/source_build_wrap_v3/`).

### 5.1 Two modes, not one unconditional arm

`wrap_interpose_v3.cpp` (`source_build_wrap_v3/wrap_interpose_v3.cpp`) never assumes
"the first two calls are the right ones." It has two modes, selected by
`NAPI_WRAP_MODE`:

- **`map`** (discovery): every call to both wrapped symbols delegates to the real
  implementation, unmodified, while recording — per call — a monotonic sequence
  number, the calling thread id (`gettid()`), the raw return address
  (`__builtin_return_address(0)`), that address's addon-relative offset (via `dladdr`
  against the shared object it resolves into), and whether an output pointer was
  supplied.
- **`arm`**: reads two frozen offset lists (`NAPI_FROZEN_CREATE_OFFSETS`,
  `NAPI_FROZEN_SETEL_OFFSETS`) captured from a prior `map` run. Interposition
  activates **only** at those exact offsets: a `napi_create_buffer_copy` call there
  returns a non-OK status without writing `*result`; a `napi_set_element` call there
  records that the real call site was reached, records the raw `value` pointer
  **without dereferencing it**, and returns a safe failure without invoking the real
  implementation. A call at any other offset delegates normally, in both modes.

### 5.2 Symbol verification (mechanical, before trusting the test)

```
nm -D build_wrap/Release/node-leveldb.node | grep -E "__wrap_napi|__real_napi|napi_create_buffer_copy|napi_set_element"
0000000000028200 T __wrap_napi_create_buffer_copy
00000000000283b0 T __wrap_napi_set_element
                 U napi_create_buffer_copy
                 U napi_set_element

readelf -Ws build_wrap/Release/node-leveldb.node | rg '__wrap_|__real_|napi_create_buffer_copy|napi_set_element'
     5: ... UND napi_set_element
    93: ... UND napi_create_buffer_copy
   274: 00000000000283b0 441 FUNC GLOBAL DEFAULT 14 __wrap_napi_set_element
   323: 0000000000028200 426 FUNC GLOBAL DEFAULT 14 __wrap_napi_create_buffer_copy
   497: ... UND napi_set_element
   612: 0000000000028200 426 FUNC GLOBAL DEFAULT 14 __wrap_napi_create_buffer_copy
   651: 00000000000283b0 441 FUNC GLOBAL DEFAULT 14 __wrap_napi_set_element
   993: ... UND napi_create_buffer_copy
```

Both `__wrap_*` symbols are defined; both real symbols remain `UND` (still
runtime-resolved — `wrap_interpose_v3.cpp` calls through to them in `map` mode and
whenever an offset doesn't match the frozen list), confirming the wrap is wired as
intended (`source_build_wrap_v3/nm_D_v3.txt`, `readelf_Ws_v3.txt`).

### 5.3 Mapping run: discover and freeze the offsets

One bounded run (`timeout 20`, `ulimit -v 2GiB`, `ulimit -c 0`), `NAPI_WRAP_MODE=map`,
through the real `iterator_next` path (source-built binary swapped into the prebuilt's
own load path for this one test, then the original prebuilt restored and
hash-verified afterward). Exit 0, real buffer values returned
(`source_build_wrap_v3/v3_map_std{out,err}.log`):

```
[wrapv3][map] create_buffer_copy seq=0 tid=1721 retaddr=0x7f2653e43474 offset=0x26474 resolved=1 length=2 output_ptr_supplied=1
[wrapv3][map] create_buffer_copy seq=1 tid=1721 retaddr=0x7f2653e434ad offset=0x264ad resolved=1 length=2 output_ptr_supplied=1
[wrapv3][map] set_element        seq=2 tid=1721 retaddr=0x7f2653e434c4 offset=0x264c4 resolved=1 index=1 value_ptr=0x3bed4768
[wrapv3][map] set_element        seq=3 tid=1721 retaddr=0x7f2653e434da offset=0x264da resolved=1 index=0 value_ptr=0x3bed4770
```

Exactly two distinct offsets for each symbol — matching the source's two static call
sites (`bindings.cpp:1440`/`:1447` for the key/value creations inside
`NextWorker::HandleOKCallback`, `:1453`/`:1454` for the corresponding key/value
`napi_set_element` calls; `source_build_wrap_v3/frozen_offsets.txt`). Frozen:

| role | offset | source | corresponds to |
|---|---|---|---|
| create (key) | `0x26474` | `bindings.cpp:1440` | set (key), `0x264c4` |
| create (value) | `0x264ad` | `bindings.cpp:1447` | set (value), `0x264da` |
| set (key, index=1) | `0x264c4` | `bindings.cpp:1453` | — |
| set (value, index=0) | `0x264da` | `bindings.cpp:1454` | — |

### 5.4 Armed runs (frozen offsets), reproduced twice

`NAPI_WRAP_MODE=arm NAPI_FROZEN_CREATE_OFFSETS=0x26474,0x264ad NAPI_FROZEN_SETEL_OFFSETS=0x264c4,0x264da`,
same bounds, run twice (`source_build_wrap_v3/v3_armed_run{1,2}_std{out,err}.log`):

```
[wrapv3][arm] create_buffer_copy seq=0 ... offset=0x26474: FROZEN OFFSET MATCH -- FORCING FAILURE, *result NOT written
[wrapv3][arm] create_buffer_copy seq=1 ... offset=0x264ad: FROZEN OFFSET MATCH -- FORCING FAILURE, *result NOT written
[wrapv3][arm] set_element seq=2 ... offset=0x264c4 index=1 value_ptr=0x313e8fd8: FROZEN OFFSET MATCH -- REAL CALL SITE REACHED after injected failure. Recording reach and the raw value pointer WITHOUT dereferencing it; returning a safe failure WITHOUT invoking the real implementation.
[wrapv3][arm] set_element seq=3 ... offset=0x264da index=0 value_ptr=0x2: FROZEN OFFSET MATCH -- REAL CALL SITE REACHED after injected failure. Recording reach and the raw value pointer WITHOUT dereferencing it; returning a safe failure WITHOUT invoking the real implementation.
```

Both runs: exit 0. Both frozen creation offsets matched and forced failure without
writing `*result`; both frozen `napi_set_element` offsets matched and were reached
**after** the corresponding injected failure, safely intercepted (never dereferencing
`value`). The JS-visible array is left with two empty slots since the safe
interceptor never populates it — an accepted, disclosed side effect of the
always-safe design, not a defect. No crash, no N-API error surfaced to JS (the
source doesn't check `napi_set_element`'s return status), no assertion.

Restoration verified immediately after: original prebuilt hash
`88a6a397dcec702dd901a764482b5b46a211247b19bf1ede97b222b9c8726abc` confirmed restored;
`CMakeLists.txt` and `src/` confirmed clean of the test-only wrap addition; one final
unshimmed run against the restored prebuilt confirmed real buffer values returned,
exit 0 (`source_build_wrap_v3/v3_postrestore_std{out,err}.log`).

## 6. The record, per item

| item | result |
|---|---|
| source tarball hash | `8f2213a074ae4312a03ac9137811bdd3eaa07ccb8af48420b5a08edd02460412` |
| compiler / linker versions | gcc 13.3.0 / GNU ld 2.42 |
| Node headers / version | v22.22.2 headers via cmake-js 7.4.0 |
| build flags | see identity table, §1 |
| rebuilt `.node` hash | `a4e5a7a274f68a8cacb649f58cfe9ada34dbd157375cb4baccee28d617e2afdc` |
| frozen return offsets | 2 creation (`0x26474`, `0x264ad`), 2 set_element (`0x264c4`, `0x264da`) — discovered by mapping, not assumed |
| baseline load and callback outcome | unmodified prebuilt: loads, real `iterator_next` completes normally, exit 0 |
| injected creation-call count | 2 (both frozen offsets, both armed runs) |
| `napi_set_element` reached after each injected failure | **yes, both frozen offsets, both armed runs** (2 of 2, twice) |
| exit signal/status and emitted error | prebuilt `LD_PRELOAD`: exit 0 (no interception, no error). Source-build wrap: exit 0, map run and both armed runs (no crash, no N-API error thrown, no assertion) |
| symbol interposition independently verified | **prebuilt: NO** (`PREBUILT_INTERPOSITION_UNAVAILABLE`, confirmed by silent shim + `LD_DEBUG=bindings`). **Source-build wrap: YES** — by symbol table (`nm -D`/`readelf -Ws` show `__wrap_*` defined, real symbols still `UND`) AND by offset (armed-mode log lines show `FROZEN OFFSET MATCH` at exactly the four offsets the mapping run discovered, never elsewhere) |

## Status

- **Shipped prebuilt: `PREBUILT_INTERPOSITION_UNAVAILABLE`.** Its own runtime
  handling of this failure was never injected and remains unestablished — this is
  not relabeled as confirmed in either direction.
- **Rebuilt pinned source (offset-verified `--wrap`, both mapping and armed paths
  observed): `SOURCE_BUILT_PINNED_ADDON_FAILURE_PATH_CONFIRMED`.** Compiled from the
  exact pinned source, with the sole test-only change being a linker-level call
  interposition (verified both by symbol table and by call-site offset) that never
  alters program logic, the rebuilt addon reaches `napi_set_element` at both frozen,
  source-verified call sites after the two frozen `napi_create_buffer_copy` call
  sites are forced to fail — reproduced across two independent armed runs.

This confirms the runtime handling defect **in the rebuilt, pinned-source addon**:
after the real call fails and its output is never written, the real code still
proceeds to consume that output at both real call sites. Whether the shipped prebuilt
behaves identically is consistent with this result (it is built from the same
source) but was not itself observed under injection, and is not claimed as observed.

## Claims boundary (unchanged, load-bearing)

**No claim is made about exploitability or security impact.** This is a bounded,
reproducible control-flow observation on the rebuilt, pinned-source addon: the real
compiled code proceeds to the use site after the documented N-API failure contract is
exercised, at call sites whose identity was independently discovered and frozen
before any failure was injected — not assumed. Whether this has any security
implication, whether it is triggerable by an untrusted caller in any real deployment,
what the shipped prebuilt's own behavior under injection would be, and what severity
this would carry are separate, unestablished questions this reliability analysis does
not answer. The finding remains a **confirmed API return-code handling discrepancy
with a confirmed runtime control-flow consequence in the rebuilt, pinned-source
addon** — not a confirmed vulnerability, and not a claim about the shipped prebuilt's
own runtime behavior.
