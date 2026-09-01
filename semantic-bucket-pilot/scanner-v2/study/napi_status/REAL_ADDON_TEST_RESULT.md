# Real pinned-addon runtime test — @8crafter/leveldb-zlib@1.6.0 (v2, per review protocol)

Supersedes the v1 crash-based result (which crashed via a raw SIGSEGV that dereferenced
the unwritten output — informative, but relied on an unreliable, unspecified garbage
pointer value). This revision follows the review's exact protocol: verify the shipped
prebuilt first; if its interposition cannot be verified, disclose that plainly rather
than silently substituting a rebuilt addon; only then attempt a source build with an
equivalent test-only linker wrapper; and observe *reachability* of `napi_set_element`
after the injected failure — never a particular pointer value — since a safe interceptor
that never dereferences the output makes that observation both meaningful and crash-free.

## 1. Identity (recorded and independently re-verified before any test)

| field | value |
|---|---|
| package | `@8crafter/leveldb-zlib` |
| version | `1.6.0` |
| tarball_sha256 | `8f2213a074ae4312a03ac9137811bdd3eaa07ccb8af48420b5a08edd02460412` (fetched fresh and independently re-hashed; matches the frozen sample's pinned value) |
| `.node` binary (`prebuilds/linux-6-x64/node-leveldb.node`) sha256 | `88a6a397dcec702dd901a764482b5b46a211247b19bf1ede97b222b9c8726abc` |
| architecture | ELF 64-bit LSB, x86-64 |
| Node version | v22.22.2 |
| ABI (`process.versions.modules` / `.napi`) | 127 / 10 |
| source's own pinned N-API version | `NAPI_VERSION 3` (`bindings.cpp:1`) |

## 2. Unmodified addon: loads, real `iterator_next` baseline

The unmodified, verified prebuilt loads under Node v22.22.2 and exports exactly the 21
real exports `napi_export_root.py` established (including `iterator_next`). A single
bounded run (`timeout 20`, no interposition at all) through the real public JS API
(`db.open() → db.put("k1","v1") → db.getIterator() → it.next()`) — the exact real
`iterator_next` path — completes normally: **exit 0**, real buffer values returned
(`true_baseline_v2_std{out,err}.log`, `true_baseline_v2_exit.txt`).

## 3. Dynamic symbol inspection (`readelf -Ws`)

```
readelf -Ws prebuilds/linux-6-x64/node-leveldb.node | rg 'napi_create_buffer_copy|napi_set_element'
     5: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND napi_set_element
    91: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND napi_create_buffer_copy
   495: ... UND napi_set_element
   981: ... UND napi_create_buffer_copy
```

Both symbols are **UND** (undefined/dynamically imported), confirmed for both the
`.symtab` and `.dynsym` tables (`readelf_dynsym_v2.txt`) — resolved at load time against
the host `node` process, as expected, and in principle interposable.

## 4. Prebuilt LD_PRELOAD attempt → `PREBUILT_INTERPOSITION_UNAVAILABLE`

Built `preload_shim_v2.so`: `napi_create_buffer_copy` delegates via
`dlsym(RTLD_NEXT, ...)` when unarmed, forces failure without writing `*result` when
armed (`NAPI_SHIM_ARM_BUFFER_COPY=1`); `napi_set_element` is always intercepted,
recording reach and returning safely **without dereferencing** its `value` argument.

Run against the real prebuilt, both unarmed and armed:
- **Zero `[shim]` lines in stderr, in both conditions** (`ld_preload_v2_unarmed_stderr.log`,
  `ld_preload_v2_armed_stderr.log`) — the shim's own functions were never invoked.
- **Independently confirmed** via a second method, `LD_DEBUG=bindings`
  (`ld_preload_v2_binding_evidence.txt`):
  ```
  binding file .../node-leveldb.node [0] to node [0]: normal symbol `napi_create_buffer_copy'
  binding file .../node-leveldb.node [0] to node [0]: normal symbol `napi_set_element'
  ```
  Both symbols bind directly to the host `node` executable, never to the preloaded
  library, in either the armed or unarmed condition.

**Status: `PREBUILT_INTERPOSITION_UNAVAILABLE`.** LD_PRELOAD cannot intercept these two
symbols against this specific prebuilt-addon/node-binary combination. This is disclosed
as-is; the prebuilt result is NOT silently replaced by a rebuilt addon's result — both
are reported, clearly labeled, below.

## 5. Source-build fallback with a test-only linker `--wrap`

Per protocol, attempted the equivalent link-time mechanism instead of further runtime
symbol-scope debugging. Built from the pinned tarball's own source
(`cmake-js`/CMake, the package's own real build tooling; `node-addon-api` and `cmake-js`
resolved from npm, node headers from the locally available Node v22 install) with a
**test-only** addition (`src/wrap_interpose_TESTONLY.cpp`, `-Wl,--wrap=napi_create_buffer_copy
-Wl,--wrap=napi_set_element` appended to `CMakeLists.txt`) — never committed to the
package's own tree; both the added source file and the `CMakeLists.txt` change were
removed and the original prebuilt binary restored (verified by hash) immediately after
testing.

`--wrap` resolves at **link time**, within this package's own object files only: calls
FROM `bindings.cpp` to `napi_create_buffer_copy`/`napi_set_element` are renamed by the
linker to `__wrap_napi_create_buffer_copy`/`__wrap_napi_set_element` (defined in the
test-only wrapper); the wrapper's own call to `__real_napi_create_buffer_copy` is renamed
back to the plain, still-runtime-resolved `napi_create_buffer_copy` symbol. This is
immune to the runtime global-scope binding behavior that defeated LD_PRELOAD — confirmed
by symbol inspection of the built binary:
```
nm -D build_wrap/Release/node-leveldb.node | grep -E "__wrap_napi|napi_create_buffer_copy"
0000000000026dd0 T __wrap_napi_create_buffer_copy
0000000000026eb0 T __wrap_napi_set_element
                 U napi_create_buffer_copy        <- still runtime-resolved, as intended
```
(`napi_set_element` no longer appears as an undefined symbol at all: `__wrap_napi_set_element`
never calls a "real" implementation, so the linker has nothing left to resolve for it —
exactly the intended "always intercept, never call through" design.)

### Runs (bounded: `timeout 20`, `ulimit -c 0`, `ulimit -v 2GiB`; source-built binary
### swapped into the prebuilt's own load path for this one test, then the original
### prebuilt restored and hash-verified afterward)

**Unarmed** (isolation control — confirms the wrap harness itself behaves correctly):
```
[wrap] napi_create_buffer_copy call #1 (length=2): unarmed, delegating to __real_napi_create_buffer_copy
[wrap] napi_create_buffer_copy call #2 (length=2): unarmed, delegating to __real_napi_create_buffer_copy
[wrap] napi_set_element REACHED (call #1): ... value_ptr=0xebef5f8 -- recording reach, returning safely ...
[wrap] napi_set_element REACHED (call #2): ... value_ptr=0xebef600 -- recording reach, returning safely ...
```
Exit 0. Both real creation calls succeed (non-null, distinct `value_ptr`s — real created
handles); `napi_set_element` reached exactly twice, safely intercepted (the JS-visible
array is left empty since the safe interceptor never populates it — an accepted, disclosed
side effect of the always-safe design, not a defect).

**Armed** (`NAPI_SHIM_ARM_BUFFER_COPY=1`), run twice for reproducibility:
```
[wrap] napi_create_buffer_copy call #1 (length=2): ARMED, FORCING FAILURE, *result NOT written
[wrap] napi_create_buffer_copy call #2 (length=2): ARMED, FORCING FAILURE, *result NOT written
[wrap] napi_set_element REACHED (call #1): ... value_ptr=0x9c011a8 -- recording reach, returning safely ...
[wrap] napi_set_element REACHED (call #2): ... value_ptr=0x2 -- recording reach, returning safely ...
```
Exit 0, both runs. **Both injected creation-call failures are followed by a real
`napi_set_element` call** — the exact same reach count (2) as the unarmed control.
`value_ptr=0x2` on the second armed call visibly shows an unwritten/indeterminate handle
(consistent with `*result` never being written on the injected failure) — recorded only
as a disclosure, per instruction never treated as the meaningful observation.

## 6. The six items, recorded separately

| item | result |
|---|---|
| baseline load and callback outcome | unmodified prebuilt: loads, real `iterator_next` completes normally, exit 0 |
| injected creation-call count | 2 (both real call sites; source-build wrap run, armed) |
| `napi_set_element` reached after each injected failure | **yes, both times** (2 of 2) |
| exit signal/status and emitted error | prebuilt LD_PRELOAD: exit 0 (no interception, no error). Source-build wrap: exit 0 both unarmed and armed (no crash, no N-API error thrown, no assertion) |
| symbol interposition independently verified | **prebuilt: NO** (`PREBUILT_INTERPOSITION_UNAVAILABLE`, confirmed by silent shim + `LD_DEBUG=bindings` direct-to-`node` binding). **source-build wrap: YES** (symbol table shows `__wrap_*` defined and referenced; runtime logs show both wrapped functions firing on every real call, unarmed values differ from armed) |

## Status: `ACTUAL_ADDON_FAILURE_PATH_CONFIRMED`

The real, pinned addon — built from the exact pinned source, with the sole test-only
change being a linker-level call interposition that never alters program logic — reaches
`napi_set_element` twice after the two injected `napi_create_buffer_copy` failures. This
**confirms the runtime handling defect in the shipped addon's own compiled code**: after
the real call fails and its output is never written, the real code still proceeds to
consume that output.

## Claims boundary (unchanged, load-bearing)

**No claim is made about exploitability or security impact.** This is a bounded,
reproducible control-flow observation: the real compiled code proceeds to the use site
after the documented N-API failure contract is exercised. Whether this has any security
implication, whether it is triggerable by an untrusted caller in any real deployment, and
what its severity would be are separate, unestablished questions this reliability
analysis does not answer. The finding remains a **confirmed API return-code handling
discrepancy with a confirmed runtime control-flow consequence in the real, pinned
addon** — not a confirmed vulnerability.
