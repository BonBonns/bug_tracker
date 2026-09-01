# Real build-configuration reconstruction for the 54 unresolved packages -- results

Per direct instruction: reconstruct the 54 packages' REAL build configurations (never inferred
from missing macros alone) via real compiler-command reconstruction, network-isolated cmake-js
configuration, and upstream-repository tracing. This document is the required per-package record
and report block; `results/build_config_reconstruction_final.json` is the full, machine-readable
record.

## Headline result

**50 of 54 (93%) resolved with real, decisive, non-guessed evidence. 4 remain genuinely
irreducible, each for a real, specific, disclosed reason.**

| Final status | Count | Meaning |
|---|---|---|
| `not_applicable` | 34 | Real, structural evidence that the exception_configuration question does not apply to this package's own binding technology at all |
| `enabled` | 14 | Real compiler-level evidence (explicit flag/macro, or a real compiler probe against the package's own pinned node-addon-api header) |
| `disabled` | 2 | Same, disabled side |
| `irreducible_unresolved` | 4 | A real, specific, disclosed blocker -- never a guess |

**Zero incorrect promotions.** Every `enabled`/`disabled` answer traces to a real, fully-resolved
compiler command or a real compiler probe against the package's own pinned node-addon-api
header -- never an absence-of-evidence inference.

**Zero impact on the current reportability funnel, reconfirmed.** All 54 packages already had
zero R04/R05/R06 findings at any build-config value (established in the prior round's own
staleness audit); this holds regardless of this round's own real resolutions. Step 6 (rerun R06
for packages whose configuration changed): **zero** packages needed it -- none of the 54 had a
real R06 finding to begin with, confirmed again directly.

## 1. The real, unplanned discovery that reshaped this round: most of the 54 are structurally
##    moot, not merely "hard to determine"

`NAPI_CPP_EXCEPTIONS`/`NAPI_DISABLE_CPP_EXCEPTIONS` (and their modern-macro successors, see
Section 4) are node-addon-api's OWN C++-wrapper convention. Investigating the 42
"no-textual-evidence" packages' own real source (via re-downloading the same 54 already-pinned
tarballs, continuing the established narrow exception) found that most of them never use
node-addon-api's C++ wrapper at all:

| Real binding technology | Count | Why exception_configuration does not apply |
|---|---|---|
| Pure C (no `.cc`/`.cpp` at all) | 6 | C has no exceptions; the question is meaningless |
| Not a native addon (yatag@1.3.0 -- a real corpus-selection false positive) | 1 | No native build exists at all -- confirmed via direct package.json inspection (no nan/node-addon-api/bindings dependency; the package's own real .cpp files are node-gdal-async's vendored test fixtures, never compiled) |
| Nan (real `#include <nan.h>` confirmed) | 19 | R04/R05/R06 never target Nan-shaped code; `resource_guard_verdict_nan.py` never reads this TSV at all |
| Legacy raw-V8 (`#include <node.h>`/`<node_object_wrap.h>`, real, pre-N-API/pre-Nan addons) | 4 | Same convention gap as Nan |
| Raw N-API, C-style (`#include <node_api.h>` only, never napi.h -- **a real bug caught mid-investigation, see Section 3**) | 3 | Status-code error handling, no C++ exceptions involved |
| A header-only node-addon-api-family library with no build of its own (`@h1x4dev/node-addon-api`: `gypfile: false`, no root binding.gyp -- its own binding.gyp lives under benchmark/, never invoked by a normal `npm install`) | 1 | No native build target exists for this package when installed normally |

**34 total, real, evidence-backed, never guessed.** This is a genuine 5th final-status value
alongside the instructed enabled/disabled/conflict/irreducible_unresolved -- `not_applicable`,
disclosed here rather than silently forced into `irreducible_unresolved` (which would understate
the real certainty reached: these are not "impossible to determine," they are "the question does
not apply, confirmed").

This left only **21** packages genuinely needing real, compiler-level reconstruction (not 54, not
even the 24 the first-pass `#include` scan suggested -- see Section 3 for the 3-package
correction).

## 2. Method, per real bucket

**14 binding.gyp / node-gyp packages** (`reconstruct_gyp_build_config.py`): re-download the
pinned tarball -> `npm install --ignore-scripts --omit=dev` (falls back to stripping a
genuinely-unpublished devDependency after a real, confirmed E404 -- see Section 3 -- never
touching a real `dependencies` entry) -> `node-gyp configure` (the real, canonical toolchain,
auto-fetches real node headers) -> `make -n` inside the generated build dir, a REAL, complete dry
run (prints every command it would run, compiles nothing) -> the real, fully-resolved compiler
command for every real source file. 12/14 resolved decisively from real flags alone
(`-fexceptions`, present in the real `binding.gypi` shared config all 12 packages share); 1
resolved via the real, structural `gypfile: false` finding above; 1 reclassified `not_applicable`
via the raw-N-API correction (originally blocked on a real, disclosed missing-system-library gap
-- GTK4/libadwaita unavailable in this container -- now moot regardless, since the real question
never applied to it).

**7 cmake-js packages** (`reconstruct_cmakejs_build_config.py`): same tarball/dependency
discipline, plus `npm install cmake-js@<the package's own pinned version> --no-save
--ignore-scripts`. Node's own distribution-headers cache is primed ONCE with network allowed (a
fixed, trusted, versioned download -- the same kind of operation `node-gyp configure` already
performs for every gyp-based reconstruction), then the package's OWN `cmake-js configure`
(`--CDCMAKE_EXPORT_COMPILE_COMMANDS=ON`, configure only, never `build`) is wrapped in `unshare
--net --map-root-user` -- a real, directly-verified working network-namespace isolation (DNS
resolution and all outbound connections fail inside it, confirmed before this round's first real
run) -- so the package's own untrusted CMakeLists.txt logic runs with zero network access,
reusing the primed cache. Reads the real generated `compile_commands.json`.

**Real, disclosed finding that corrects this document's own earlier speculation**
(`UNRESOLVED_CATEGORIZATION.md`'s prior "cmake-js's own tooling injects the exception define"):
confirmed FALSE by direct evidence. cmake-js/CMake does NOT apply node-gyp/common.gypi's own
`-fno-exceptions` default -- `@eliyya/sange`'s own real `compile_commands.json` carries neither
flag at all. The real, correct account: cmake-js simply leaves the compiler's own default in
place; whether that resolves to enabled or disabled depends on node-addon-api's own pinned
header logic, which is why the compiler-probe fallback (below) is what actually resolves most
cmake-js packages, not a cmake-js-specific default.

**The compiler-probe fallback** (used whenever neither a real flag nor macro appears in the
real, resolved compile command): fetches the package's own EXACT pinned (or, when a range,
actually-installed) node-addon-api version's real `napi.h`, then asks the REAL compiler directly
-- `g++ -E`, preprocess only, zero compilation -- whether `NAPI_CPP_EXCEPTIONS`/
`NODE_ADDON_API_CPP_EXCEPTIONS` ends up defined given the package's own real, resolved include
paths and defines. This is never assumed from first principles (an earlier hypothesis that
"g++'s own default has exceptions enabled" was checked directly and found WRONG for
node-addon-api@8.5.0 -- the real probe result was `disabled`, because node-addon-api's own
header logic, not the raw compiler default, is what actually governs the macro).

**2 no-recognized-build-file packages** (hand-traced): `velociradix` -- real upstream commit
fetched directly (the exact pinned `gitHead` from its own npm registry metadata,
github.com/Moaaz-i/velociradix@8c2e901e2c5801219a5b03e32aa7cce007c1caf5) found a real, plain
Makefile-based native build (a build-system shape this investigation's own extractor never
previously recognized) and confirmed `src/addon.cpp: #include <node_api.h>` -- raw N-API,
`not_applicable`. `@co_snow/hello` -- no `repository`/`gitHead` field exists in its own npm
registry metadata at all; genuinely `irreducible_unresolved`, per direct instruction's own
explicit fallback ("if that evidence is unavailable, classify it as permanently
evidence-unresolved rather than guessing").

## 3. Real bugs found and fixed during this round (none silently worked around)

1. **`make -n` dry-run compile-line detection**: the real dry-run output's own compile line ends
   in `-c` with NO trailing space before end-of-line; an `' -c ' in line` check (requiring a
   space AFTER `-c` too) silently matched zero real lines for several packages, even though the
   real, correct compile command was right there. Fixed to a real end-of-token match; re-verified
   directly (`@jimp-native/plugin-blit-napi`'s own real compile line, previously reported
   `irreducible_unresolved` for a fabricated reason, now correctly `enabled`).
2. **node-addon-api version resolution**: the compiler-probe fallback was passed the package.
   json's own raw semver RANGE string (e.g. `"^8.9.0"`) directly as a concrete tarball version in
   one code path, 404ing against the real registry. Fixed to always prefer the real, concrete,
   actually-installed version from `node_modules/node-addon-api/package.json`.
3. **A genuinely-unpublished devDependency blocking install entirely**: `--omit=dev` alone does
   NOT prevent this (npm resolves the full dependency tree, devDependencies included, before
   pruning) -- confirmed directly and reproduced manually against
   `@jimp-native/plugin-blit-napi`'s own real, still-live 404 on
   `@jimp-native/utils-testing@^0.1.0-alpha.8`. Fixed with a real, minimal, disclosed fallback:
   strip `devDependencies` from the extracted package.json and retry, only ever after a real
   E404 on the plain install, never speculatively, never touching a real `dependencies` entry.
4. **The `node_api.h` vs `napi.h` conflation** (Section 1's own 3-package correction): the
   original real-binding-technology check matched `node_api.h` (the raw N-API C header,
   included internally by node-addon-api's own napi.h, but ALSO used directly and alone by
   packages that never touch the C++ wrapper) as if it always meant "node-addon-api." Found
   directly while tracing velociradix's own real upstream source
   (`src/addon.cpp: #include <node_api.h>`, never napi.h). Fixed to track the two signals
   independently; `@8crafter/leveldb-zlib` and `@jasonscheirer/native-progress-bar`
   (previously blocked on a real, disclosed missing-system-library gap, see below) were also
   reclassified `not_applicable` by the same fix.
5. **The modern node-addon-api macro rename**: node-addon-api 8.x renamed its own canonical
   macro from `NAPI_CPP_EXCEPTIONS` to `NODE_ADDON_API_CPP_EXCEPTIONS`/
   `NODE_ADDON_API_DISABLE_CPP_EXCEPTIONS` (`NAPI_CPP_EXCEPTIONS` kept only as a backward-compat
   alias) -- confirmed directly against node-addon-api@8.9.2's own real `napi.h`, which now also
   `#error`s if NEITHER macro is defined at all (no more silent compiler-default fallback for
   recent versions). `@astronautlabs/webrtc`'s own real, decisive `-DNODE_ADDON_API_CPP_
   EXCEPTIONS=1` compile-command flag was silently missed by the legacy-only patterns before this
   fix. Fixed in BOTH `npm_corpus/extract_build_config.py` (the corpus-wide, shipped extractor --
   a real, newly-supported build pattern per direct instruction's own step 5) and the
   reconstruction scripts' own `classify_flags()`. `check_extract_build_config.py` gained 4 new
   controls (positive both sides, a negative confirming the legacy alias still works, a conflict
   between eras) -- 22/22.
6. **Two real, disclosed environment/tooling limits, resolved rather than left as gaps**:
   `@jasonscheirer/native-progress-bar`'s real GTK4/libadwaita system-library gap and `audify`'s
   real ALSA gap were both closed by installing the real, missing system packages
   (`libgtk-4-dev`/`libadwaita-1-dev` -- moot in the end, per bug 4 above; `libasound2-dev` --
   `audify` now resolves `disabled` from a real compiler probe). One remains genuinely blocked:
   `@acomsys/dash-utils` has a real, traceable upstream repository and `gitHead`, but this
   session's own tooling could not fetch a third, unrelated repository owner in the same
   session (a real, disclosed session-scope limit, not a missing-evidence problem) --
   `irreducible_unresolved`.

## 4. The 4 genuinely irreducible_unresolved packages

| Package | Real, specific reason |
|---|---|
| `@acomsys/dash-utils` | Real upstream repository + `gitHead` identified, but this session's own tooling could not fetch a third, unrelated GitHub owner (session-scope limit) |
| `@fugood/whisper.node` | Real build failure independent of network/system gaps: `CMakeLists.txt:41`'s own patch step reports "scripts/whisper.cpp.patch cannot be applied to the current whisper.cpp checkout" -- the vendored whisper.cpp source in the npm tarball does not match what the package's own patch script expects |
| `@ipshipyard/node-datachannel` | Its own real CMakeLists.txt legitimately fetches a dependency via `FetchContent_Populate`/`git clone` AT CONFIGURE TIME -- genuinely requires network to configure in the real world; correctly, deliberately blocked by this round's own network isolation, per direct instruction |
| `@co_snow/hello` | No `repository`/`gitHead` in its own npm registry metadata at all -- no upstream to trace to |

## 5. Required report block

```
unresolved before: 54
unresolved after:  4
resolved correctly (enabled/disabled, real evidence): 16
not_applicable (structurally moot, real evidence): 34
conflicts preserved: 0
incorrect promotions: 0
```

## 6. Controls

`check_extract_build_config.py`: 22/22 (18 from the prior round's diagnostic-reason work + 4 new
for the modern node-addon-api macro pattern -- positive both sides, a legacy-alias negative, an
inter-era conflict). Full combined gate suite reran clean after all changes: `check_provenance.py`
51/51 (live), `check_applicability_gate.py` 23/23, `check_adjudication_registry.py` 22/22,
`check_oob_reportable_gate.py` 17/17, `check_staged_enablement.py` 25/25,
`check_reachability_tier.py` 25/25, `check_vendored_attribution.py` 16/16,
`check_lock_balance.py` 11/11, `check_protected_field.py` 11/11,
`check_six_property_aggregator.py` 18/18, `check_nan_integration.py` 23/23 (synthetic; the real
live smoke run was validated separately, see `NAN_INTEGRATION_RESULTS.md`).

---
*No new scanning, no Joern rebuild. Real, narrow, hash-verified re-downloads of the same 54
already-pinned tarballs throughout (continuing the established exception); a real, controlled
`npm install`/`node-gyp configure`/`cmake-js configure` per package (never the package's own
build/execute step); one real, network-isolated upstream `git` fetch, at the exact pinned commit,
for the one package that needed it and could be fetched in this session.*
