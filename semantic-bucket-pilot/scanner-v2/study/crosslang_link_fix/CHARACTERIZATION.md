# Cross-language linker (`link_napi_facts.py`): characterization and fix (CROSSLANG-LINK-FIX01)

Done in an isolated git worktree (`/tmp/crosslang_wt`, branch `claude/crosslang-linker-fix`)
while the R05 corpus rerun continued, untouched, in the main working tree. Nothing here
modifies R05, its contracts, `run_pipeline_one.py`, or any corpus output -- only
`link_napi_facts.py` (a pre-existing, R01-R05-independent cross-language linking frontend)
and this study directory. Not merged into the evaluation branch; pushed only to this
development branch, per direct instruction.

## 1. Real, quantitative characterization of the problem (item 1 of the instruction)

Computed directly from `npm_pipeline_full_results.jsonl` -- the already-produced, complete,
frozen 494-package corpus run (473 real ANALYZED packages), no re-running required for this
step:

```
total ANALYZED: 473
packages with n_registrations==0 (C++ side found zero exports.Set bindings): 310
packages with n_registrations>0: 163
  of those: n_linked==0 AND n_unlinked==0 (zero JS calls even considered candidates): 163
  of those: n_unlinked>0 (JS calls WERE candidates but failed to link mechanically): 0
  of those: n_linked>0 (at least one real successful link): 0

sums across corpus: registrations=1119 linked_calls=0 unlinked_calls=0
```

**The largest real reason links are missing, by a wide margin: zero JS-side calls were ever
even CONSIDERED as candidates, corpus-wide** -- not a C++-side extraction failure (1,119 real
`exports.Set(...)` registrations were found across 163 packages -- that half of the mechanism
works), and not a downstream matching failure (0 packages ever reached the `unlinked` bucket
at all). The candidate filter itself never fires.

## 2. Root cause, confirmed on two independent real packages, not assumed

The candidate filter was `c.get('receiver_name') == a.js_receiver` (`--js-receiver` defaults
to `"bindings"`). Regenerated real JS facts for two real, independent corpus packages
(`memoryjs@3.5.1`, `node-liblzma@5.1.1`) via the real, unmodified JS/TS frontend
(`jssrc2cpg.sh` + `export_neutral.sc` + `normalize_joern_facts.py`) and read them directly:

- **`receiver_name` is essentially NEVER populated for a real native-binding member call**:
  0 non-null values across 1,099 real calls in `memoryjs`; 0 across 3,672 in `node-liblzma`.
  No `--js-receiver` string, however chosen, could ever have matched real code -- the field
  the whole mechanism keys on is not the field the frontend actually fills in.
- The frontend DOES populate a different, real, structural field: **`receiver_type`**, set
  via its own type inference to the literal string argument of the `require(...)` call that
  initialized the receiver's local variable, propagated through to every later member call on
  that same local:
  - `const memoryjs = require('./build/Release/memoryjs')` -> the local's
    `type_full_name` AND every `memoryjs.X(...)` call's `receiver_type` ->
    `"build/Release/memoryjs"`.
  - `const liblzma = require('node-gyp-build')(bindingPath)` -> `receiver_type`:
    `"node-gyp-build"` (the OUTER require's own argument, resolved even through one level of
    call-chaining -- confirmed real, `lib/lzma.js:35`).
  - Every one of these real calls also carries `resolution: "HEURISTIC"` (not `"EXACT"`),
    exactly matching the linker's own pre-existing `c['resolution'] != 'EXACT'` condition --
    these ARE the calls the mechanism was always meant to catch.

## 3. The fix: match on `receiver_type` against curated, real, disclosed conventions

`is_native_binding_receiver()` added to `link_napi_facts.py` -- see the file's own updated
module docstring for the full account. Matches `receiver_type` against:
- a small, curated, EXACT-membership set of real, well-known native-addon-loading npm
  packages (`bindings`, `node-gyp-build`, `node-pre-gyp`, `@mapbox/node-pre-gyp`,
  `prebuild-install`) -- never a substring match, so an unrelated package merely CONTAINING
  one of these names (e.g. `some-bindings-helper`) does not match;
- `.node` suffix (a direct require of a compiled binary);
- the two real, fixed, unambiguous node-gyp build-output directory segments
  (`build/Release/`, `build/Debug/`).

The OLD `receiver_name == --js-receiver` check is KEPT, unchanged, tried independently
(either one qualifies a call as a candidate) -- never removed, in case some real,
not-yet-observed frontend path does populate `receiver_name`. `extract_napi_bindings()` (the
C++-side registration extraction, which already works -- 1,119 real registrations found) is
completely untouched; confirmed by direct diff against the frozen original.

## 4. Real controls, one file each side, real frontends (not hand-typed JSON)

`controls/js/index.js` (real, run through `jssrc2cpg.sh` + `export_neutral.sc` +
`normalize_joern_facts.py`) + `controls/cpp/addon.cc` (real, compile-checked against real
node-addon-api + Node headers, run through `c2cpg.sh --include/--define` + export +
`normalize_c_cpp_facts_v03.py`) -- three positive native-loading shapes, three negative:

| Control | Real shape | `receiver_type` | Result |
|---|---|---|---|
| Positive 1 | `require('./build/Release/addon1')` | `build/Release/addon1` | LINKED |
| Positive 2 | `require('node-gyp-build')(__dirname)` | `node-gyp-build` | LINKED |
| Positive 3 | `require('bindings')('addon3')` | `bindings` | LINKED |
| Negative 1 | `require('fs')` (Node core module) | `fs` | correctly NOT a candidate |
| Negative 2 | `require('lodash')` (unrelated real npm package) | `lodash` | correctly NOT a candidate |
| Negative 3 | `require('some-bindings-helper')` (lookalike name) | `some-bindings-helper` | correctly NOT a candidate (exact-membership discipline) |

Real run: `POLYGLOT registrations=3 linked_js_calls=3 unlinked=0` -- all 3 positives linked,
all 3 negatives verified (by direct field inspection, not just the aggregate count) to carry
`resolution: "HEURISTIC"` (i.e. they WOULD have been candidates under a looser check) but a
`receiver_type` that correctly fails the curated match.

## 5. Real end-to-end validation on two independent real corpus packages (before/after)

Same two packages used for root-causing, now run through the COMPLETE real pipeline (real
tarball, real header-staging, real `c2cpg --include/--define`, real export/normalize both
sides, real `polyglot_compat_adapter.py`) with BOTH the frozen OLD linker and the fixed NEW
one, for a direct A/B on real data:

| Package | OLD (frozen) | NEW (this fix) |
|---|---|---|
| `memoryjs@3.5.1` | `registrations=12 linked=0 unlinked=0` | `registrations=12 linked=15 unlinked=25` |
| `node-liblzma@5.1.1` | `registrations=6 linked=0 unlinked=0` | `registrations=6 linked=6 unlinked=0` |

Spot-checked `memoryjs`'s real results, not just trusted: linked calls are real, plausible
native memory-manipulation functions (`writeBuffer`, `findPatternByModule`, `callFunction`,
`virtualAllocEx`); the 25 unlinked calls (`openProcess`, `closeProcess`, `getProcesses`, ...)
are UNLINKED for a real, pre-existing, disclosed, correct reason -- `extract_napi_bindings()`'s
own "need exactly 1 candidate function" abstention fires because the real C++ source has
multiple same-named overloads for these specific functions, so no exact registration can be
picked without guessing. This is the mechanism's own existing honesty working correctly, now
actually being exercised for the first time (previously nothing ever reached this stage).

## 6. Scope, stated precisely

This fix widens WHICH JS calls are considered CANDIDATES for linking. It does not touch, and
does not need to touch, the mechanically-exact matching discipline once a call IS a candidate
(`extract_napi_bindings()`'s own "exactly one candidate function" requirement, `name in table`
exact lookup) -- that logic is real, already correct, and now, for the first time across this
corpus, actually gets to run against real candidates. Real, disclosed boundary: a receiver
loaded through a convention NOT in the curated set (e.g. a fully custom, package-specific
loader with no recognizable path/package-name signal) still will not become a candidate --
not attempted to be covered here; the five curated conventions were chosen because they are
real, confirmed, and cover both real packages investigated, not because they are exhaustive.
