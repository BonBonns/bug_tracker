# node-snap7 runtime validation (Track A): the static candidates, reproduced

Per direct instruction: build the exact pinned release configuration, harness the three real
candidates with oversized lengths, run under real memory limits, and confirm whether allocation
failure produces the predicted fatal process termination in a release build -- before this
project claims anything stronger than "confirmed static candidate."

**Result: the predicted fatal termination is REPRODUCED, real and repeatable, for all three
sites, under a real, bounded memory limit, in a genuine local Release build.** This document also
records where the ORIGINAL static analysis over-claimed (memory consumption under abundant
memory) and narrows the claim accordingly -- runtime evidence corrects static prediction where
they disagree, never the reverse.

## 1. The exact pinned release configuration (built, not assumed)

- Source: `node-snap7@1.0.9`, refetched from `https://registry.npmjs.org/node-snap7/-/node-snap7-1.0.9.tgz`, sha1 `9402be15ca318c0bba3267494c3ab8892163fd5b` (matches the registry's own real `shasum` -- re-verified, same tarball every prior review in this project used).
- Real `npm install` (no `--ignore-scripts`) run inside the extracted package: resolved `nan@^2.23.0`/`bindings@^1.5.0`/`prebuild-install@^7.1.2` for real, ran the package's own real `install` script (`prebuild-install || node-gyp rebuild`).
- To get a directly-inspectable, fully local build (rather than trust a possibly-fetched prebuilt binary), `build/` was removed and `npx node-gyp rebuild` run explicitly: a REAL local compile of the package's own pinned, vendored `deps/snap7` C++ core plus `src/node_snap7*.cpp` against the real, installed `nan` headers -- `g++ (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`, Node.js `v22.22.2`, produced `build/Release/node_snap7.node`.
- **Real, directly-read Release compile flags** (`build/node_snap7.target.mk`, not assumed):
  `CFLAGS_Release = -fPIC -pthread -Wall -Wextra -Wno-unused-parameter -m64 -O3
  -fno-omit-frame-pointer`; `CFLAGS_CC_Release = -fno-rtti -fno-exceptions -fno-strict-aliasing
  -std=gnu++17`. **`NDEBUG` is NOT defined** by node-gyp's own default `DEFS_Release` (a real
  correction to this project's own earlier assumption in `NODE_SNAP7_NAN_MANUAL_REVIEW.md`,
  which reasoned from `nan.h`'s `assert(length <= kMaxLength)` compiling out under `NDEBUG` --
  see section 4 below for what the REAL crash mechanism turned out to be instead, confirmed by
  direct observation, not re-guessed). **`-fno-exceptions` IS set** -- this turns out to be the
  operative fact, not `NDEBUG`.

## 2. The harness

`harness.js` (real, minimal, no test framework): loads the real, just-built
`build/Release/node_snap7.node` directly (bypassing `lib/node-snap7.js`'s convenience wrappers,
which are pure JS and add no safety), constructs a real `S7Client`, and calls the raw native
method under test with an attacker-shaped oversized length -- `ReadArea(S7AreaDB, 0, 0, size,
S7WLByte, undefined)`, `Upload(0, 0, size, undefined)`, `FullUpload(0, 0, size, undefined)` --
the `undefined` callback takes each method's own real synchronous code path (confirmed via
source: `if (!info[N]->IsFunction())`), matching a direct, unmediated call an application could
make. No PLC connection is opened or needed: all three methods perform their own buffer
allocation as the FIRST unconditional action, before any connection check (re-confirmed against
the exact, just-compiled source).

## 3. Real, bounded resource limits

`ulimit -v` (virtual address space) was the real, working mechanism -- `ulimit -m`/`-d` are not
enforced by the Linux kernel for a modern glibc allocator's mmap-based large allocations.
**Real, disclosed methodological finding along the way:** an initial attempt at a TIGHT `ulimit
-v` (200MB) failed before even reaching the harness's own call -- Node/V8 itself needs to reserve
a large virtual address range at startup (confirmed empirically: `ulimit -v` below ~600-1000MB
crashes `node -e "1"` alone, with V8's own `FatalProcessOutOfMemory` / "Failed to reserve virtual
memory for CodeRange", never running any JS at all). The real, correct harness sets `ulimit -v`
comfortably above Node's own real startup requirement (1200MB, empirically confirmed sufficient)
and requests an allocation (600MB) that pushes total virtual memory demand over that ceiling --
so the FAILURE specifically happens at the harness's own targeted allocation, not at Node
startup.

## 4. Real result: fatal process termination, confirmed for all three sites

```
$ ( ulimit -v 1228800; node harness.js ReadArea 629145600 )
[harness] method=ReadArea size=629145600 pid=27180
[harness] resident memory before call: 47575040 bytes
terminate called after throwing an instance of 'std::bad_alloc'
  what():  std::bad_alloc
$ echo $?
134

$ ( ulimit -v 1228800; node harness.js Upload 629145600 )
[harness] method=Upload size=629145600 pid=27188
terminate called after throwing an instance of 'std::bad_alloc'
  what():  std::bad_alloc
$ echo $?
134

$ ( ulimit -v 1228800; node harness.js FullUpload 629145600 )
[harness] method=FullUpload size=629145600 pid=27196
terminate called after throwing an instance of 'std::bad_alloc'
  what():  std::bad_alloc
$ echo $?
134
```

Exit code `134` = `128 + SIGABRT(6)` -- a real, uncatchable-from-JS process abort (confirmed:
the harness's own `try { ... } catch (e) { ... }` around each call never ran; the process
terminated before control ever returned to JS).

**The real crash mechanism, now directly observed rather than predicted from source reading
alone:** `new char[size]` (the FIRST statement in all three C++ handlers) throws a real
`std::bad_alloc` when the allocation cannot be satisfied. Because this translation unit is
compiled with `-fno-exceptions` (section 1) and node-snap7's own code contains no `try`/`catch`
anywhere around this call, the exception propagates with no handler in scope, `std::terminate()`
fires, and the process aborts. **This is a more direct crash path than
`NODE_SNAP7_NAN_MANUAL_REVIEW.md`'s own earlier framing** (which centered on `Nan::NewBuffer`'s
own `.ToLocalChecked()` fatally aborting on an empty `MaybeLocal`) -- that mechanism would only
matter if `new char[size]` itself succeeded and the LATER `node::Buffer::New()` call failed; in
practice, for a size large enough to actually exhaust available memory, the raw `new[]` fails
first. Both are real; this document records which one is REPRODUCIBLE and dominant.

## 5. Real, disclosed correction: memory-abundant conditions do NOT reliably crash or spike RSS from a single call

Per direct instruction to document reproducible impact "no stronger claim than the evidence
supports" -- this section narrows an earlier claim, not widens it. With no `ulimit` (this
container's own real 14GB available memory) and a size of `2147483647` (`INT32_MAX`, the real
upper bound an `int32` argument can carry): the call returned `false` (no crash), and resident
memory was UNCHANGED before/after (`~48MB` both times). Root cause, directly observed: `new
char[size]` (no value-initialization) does not touch any page until written; with the target
S7 connection never opened, the subsequent real `snap7Client->{ReadArea,Upload,FullUpload}()`
call fails immediately (no live PLC), and the handler's own `delete[] bufferData;` frees the
buffer synchronously, in the same call, before any real physical memory was ever committed.

A concurrent-load variant (`stress.js`, 20 simultaneous `ReadArea(..., 50_000_000, ...)` async
calls -- nominal `1000MB` if all were resident at once) confirms the same pattern: RSS moved from
`47.3MB` to `47.8MB` across the whole run, all 20 callbacks completing with no crash. **The real,
reproducible DoS this project can currently substantiate is specifically the allocation-FAILURE
crash path under memory pressure (section 4) -- not a demonstrated memory-EXHAUSTION-via-repeated-
requests path against a target that never actually connects.** A connected, real PLC streaming
genuine data back could behave differently (physically touching more of the buffer as real bytes
arrive) -- untested here, since it requires live S7 hardware or a protocol-accurate simulator,
neither available in this environment; not claimed.

## 6. Current npm version and upstream source, re-verified

`https://registry.npmjs.org/node-snap7` (fetched fresh, not cached from the earlier review):
`dist-tags.latest = "1.0.9"`, published `2025-08-30T09:42:34.428Z` -- still the current, latest
published version; no newer release has changed this. Upstream repository, from the same real
registry metadata: `git://github.com/mathiask88/node-snap7.git` (matches every prior citation in
this project).

## 7. Documentation, per direct instruction's own required elements

- **Three affected sites**: `ReadArea` (`src/node_snap7_client.cpp:1255`), `Upload` (`:1727`),
  `FullUpload` (`:1760`) -- all three independently, directly reproduced above.
- **One shared source lineage**: all three sites are the same real S7Client codebase, confirmed
  present near-byte-identically in `node-snap7-micro-client@0.1.0`
  (`NODE_SNAP7_DEDUP_REVIEW.md`'s own byte-level diff).
- **Two npm exposures**: `node-snap7` (this document's own real build target) and
  `node-snap7-micro-client` (not independently rebuilt/harnessed in this round -- its own real
  source was already confirmed byte-for-byte close enough that the same 3 crash mechanisms
  apply; a live, from-scratch build of the second package to independently reproduce the crash
  on ITS OWN compiled binary is real, disclosed follow-up work, not done here to avoid
  duplicating an already-established result on the same real source).
- **Reproducible impact**: real, deterministic, repeated on demand (every run above reproduced
  identically) -- a process hosting node-snap7 and calling `ReadArea`/`Upload`/`FullUpload` with
  an attacker/caller-supplied size large enough to exceed the process's own available memory
  headroom (a REAL, common condition for any memory-constrained deployment -- containers,
  Kubernetes pods with memory limits, edge/IoT gateways, all realistic real-world hosts for a
  PLC-communication library) crashes via an uncaught `std::bad_alloc` -> `std::terminate()` ->
  `SIGABRT`, confirmed for all three sites, in a real, locally-built Release binary.
- **No stronger claim than the evidence supports**: this is now a **runtime-reproduced,
  memory-pressure-dependent denial-of-service** for all three sites -- not merely a predicted
  consequence of static analysis. It is NOT claimed to be independently exploitable over a real
  S7/PLC network protocol boundary (no live target was used or needed -- the crash occurs before
  any network I/O), NOT assigned a CWE/CVE identifier, and NOT claimed to cause memory
  EXHAUSTION under abundant-memory conditions (section 5 directly refutes that narrower framing
  for the untargeted/unconnected case tested). The three findings remain **CONFIRMED CANDIDATE**
  per `NODE_SNAP7_NAN_MANUAL_REVIEW.md`'s own classification, now with real, reproduced runtime
  evidence attached -- this project's own discipline (`adjudication_registry.py`'s own docstring:
  no "confirmed true positive"/vulnerability status exists in this pipeline's own vocabulary)
  means this document, not a pipeline status field, is where that stronger, evidence-backed claim
  lives.
