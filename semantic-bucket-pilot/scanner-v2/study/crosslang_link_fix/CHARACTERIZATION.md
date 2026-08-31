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
`normalize_c_cpp_facts_v03.py`) -- ten real controls, current as of FIX01D:

| Control | Real shape | `receiver_type` | Result |
|---|---|---|---|
| Positive 1 | `require('./build/Release/addon1')` | `build/Release/addon1` | LINKED |
| Positive 2 | `require('node-gyp-build')(__dirname)` | `node-gyp-build` | LINKED |
| Positive 3 | `require('bindings')('addon3')` | `bindings` | LINKED |
| Positive 4 (FIX01D) | `require("node-gyp-build")(__dirname)` -- SAME as #2, double-quoted | `node-gyp-build` | LINKED (proves the marker check is quote-style-independent) |
| Negative 1 | `require('fs')` (Node core module) | `fs` | correctly NOT a candidate |
| Negative 2 | `require('lodash')` (unrelated real npm package) | `lodash` | correctly NOT a candidate |
| Negative 3 | `require('some-bindings-helper')` (lookalike name) | `some-bindings-helper` | correctly NOT a candidate (exact-membership discipline) |
| Negative 4 (FIX01B) | `loader.path(x)` where `loader = require('node-gyp-build')`, never invoked | `node-gyp-build` | correctly NOT a candidate (no `<returnValue>` marker) |
| Negative 5 (FIX01D) | `require('@mapbox/node-pre-gyp').find(path)` | `@mapbox/node-pre-gyp` | correctly NOT a candidate (package removed from the curated set, section 6b) |
| Negative 6 (FIX01D) | `require("prebuild-install").download({})` (double-quoted) | `prebuild-install` | correctly NOT a candidate (package removed from the curated set, section 6b) |

Real run: `POLYGLOT registrations=4 linked_js_calls=4 unlinked=0` -- all 4 positives linked
(`Foo`, `Bar`, `Baz`, `Qux`), all 6 negatives excluded before ever reaching the `unlinked`
bucket. The two newest negatives (5 and 6) verified by direct field inspection, same
discipline as the first three: both carry `resolution: "HEURISTIC"` (the risk was real, not
hypothetical -- they would have been candidates had those packages stayed in the curated
set) but a `receiver_type` no longer present in `NATIVE_LOADER_PACKAGES` at all.

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

## 5b. CROSSLANG-LINK-FIX01B: the loader-helper-vs-invoked-result boundary control

Requested review caution, checked for real, not just acknowledged: `receiver_type` alone
CANNOT distinguish a method called on the LOADER HELPER itself
(`const loader = require('node-gyp-build'); loader.path(x)`) from one called on the
actual native binding it produces once INVOKED
(`const native = require('node-gyp-build')(x); native.Bar()`) -- both carry the identical
`receiver_type: "node-gyp-build"`. Confirmed real and ambiguous with a dedicated fixture,
then confirmed the SAME ambiguity already existed, unnoticed, in `node-liblzma`'s own real
facts (its real `isXZ` call).

**Real, structural signal that DOES distinguish them, found by direct inspection, not
assumed:** only the INVOKED case's `candidate_target_full_names`/`canonical_targets`
contains a `require('<pkg>'):<returnValue>:` marker (e.g.
`"lib/lzma.js::program:require('node-gyp-build'):<returnValue>:isXZ"` -- real, from
`node-liblzma`). The bare, non-invoked loader reference (`loader.path(x)`) never has this
marker -- confirmed: its `candidate_target_full_names` is just `["node-gyp-build:path"]`.

`_via_loader_invocation()` checks for exactly this marker, scoped to the SAME package name
matched via `receiver_type` (never a bare "any `<returnValue>` marker", which could in
principle belong to an unrelated `require()`). Applied ONLY to the loader-PACKAGE-name
branch of `is_native_binding_receiver()` -- the build-path/`.node` branch needs no such
check, since a direct `require('./build/Release/x')` already IS the real module in one
step, with no separate "helper vs. invoked result" to confuse.

Added as a fourth negative control (`controls/js/index.js`'s `checkLoaderPath`), real,
regenerated through the real frontend, verified directly: `receiver_type: "node-gyp-build"`,
`resolution: "HEURISTIC"` (i.e. it WOULD have been treated as a candidate under the
`receiver_type`-only check -- the risk was real, not hypothetical), no `<returnValue>`
marker -> `is_native_binding_receiver()` correctly returns `False`. All three original
positive controls and both real end-to-end packages (`memoryjs`, `node-liblzma`)
re-verified unchanged after this addition (`registrations=3 linked=3 unlinked=0`;
`registrations=12 linked=15 unlinked=25`; `registrations=6 linked=6 unlinked=0` --
identical to before this control was added, confirming it only removes the one real risky
case, changes nothing else).

## 6. Scope, stated precisely

This fix widens WHICH JS calls are considered CANDIDATES for linking. It does not touch, and
does not need to touch, the mechanically-exact matching discipline once a call IS a candidate
(`extract_napi_bindings()`'s own "exactly one candidate function" requirement, `name in table`
exact lookup) -- that logic is real, already correct, and now, for the first time across this
corpus, actually gets to run against real candidates. **Coverage is intentionally a LOWER
BOUND, stated precisely, not a claim of completeness**: a receiver loaded through a
convention NOT in the curated set (e.g. a fully custom, package-specific loader with no
recognizable path/package-name signal) still will not become a candidate -- unknown/custom
loaders are still missed by design, not attempted to be covered here; the five curated
conventions were chosen because they are
real, confirmed, and cover both real packages investigated, not because they are exhaustive.

**A linked/ambiguous count is a BINDING LINK, not a complete attacker-source-to-native-
finding PATH.** This fix establishes that a JS call structurally reaches a specific real C++
function -- it does not, by itself, establish that JS-controlled input flows through that
binding into an R05-recovered (or R04-direct) unguarded acquisition. That composition (JS
input -> linked native callback -> R05 finding) is real, separate follow-on work, planned
for after R05's own corpus results are frozen (see section 7 below) -- not claimed here.

## 6b. CROSSLANG-LINK-FIX01C: a real overclaim in the curated set, found and corrected

Prompted by a direct "anything else to fix" review pass, not found during the original work
-- worth recording precisely rather than quietly amending. The original `NATIVE_LOADER_
PACKAGES` set (`bindings`, `node-gyp-build`, `node-pre-gyp`, `@mapbox/node-pre-gyp`,
`prebuild-install`) was documented as "confirmed against real require() targets in two
independent real corpus packages" -- true for `bindings` and `node-gyp-build` only. The
other three were added from general npm-ecosystem knowledge, never verified per-package the
way the discipline this whole project runs on requires. Checked directly against each
package's own real, published source:

- **`bindings`**: confirmed, `bindings@1.5.0`'s `module.exports = exports = bindings;` is a
  callable function -- matches the `require(PKG)(args)` shape `_via_loader_invocation` checks.
- **`node-gyp-build`**: already confirmed via real corpus usage (`node-liblzma`'s own
  `require('node-gyp-build')(bindingPath)`).
- **`node-pre-gyp`/`@mapbox/node-pre-gyp`**: `node-pre-gyp@0.17.0`'s real
  `lib/node-pre-gyp.js` exports a plain OBJECT (`exports.find = ...`, `exports.Run = ...`),
  not a function. Real usage is `require('node-pre-gyp').find(path)` (itself the exact
  "method call on the bare loader helper" case CROSSLANG-LINK-FIX01B exists to reject) then
  a SEPARATE `require(<dynamic path>)` whose non-literal argument this mechanism cannot
  resolve to a matching `receiver_type` at all. Including these names never matched real
  node-pre-gyp usage (confirmed: removing them changed nothing in any regression re-run --
  `memoryjs`, `node-liblzma`, and the controls fixture all reproduce byte-identical results)
  -- inert, not actively wrong, but the "confirmed" claim did not hold for them.
- **`prebuild-install`**: CORRECTED below (6c) -- an earlier version of this section claimed
  it has no `main` field and is therefore never `require()`-able. That was itself factually
  wrong, caught on a follow-up review: absence of `main` does not mean unrequireable, and
  the real disqualifying reason is the export SHAPE, not requireability.

**Fix:** `NATIVE_LOADER_PACKAGES` narrowed to `{'bindings', 'node-gyp-build'}` -- the only
two entries with real, per-package verification. All prior real controls and both real
end-to-end packages re-verified unchanged after the removal -- confirming the removed
entries contributed nothing real, only an overclaim in the documentation. If real coverage
of `node-pre-gyp`-style two-step loaders is wanted later, it needs a genuinely different
mechanism (tracking a helper-method-call -> dynamic-`require()` chain) -- not attempted here,
and not implied to already work by this set's presence.

## 6c. CROSSLANG-LINK-FIX01D: two more real, found-on-review corrections

Both prompted directly by review, neither found during the original work -- recorded exactly
as found, including the fact that 6b's own `prebuild-install` reasoning was itself wrong.

**1. `prebuild-install` IS require()-able -- the real disqualifying reason is its export
shape, not requireability.** Node's own CommonJS resolution, absent a `main` field, defaults
to the package root's `index.js` -- confirmed real:
`prebuild-install@7.1.3`'s own published `index.js` exists and is exactly
`exports.download = require('./download')`. So `require('prebuild-install')` resolves fine
and returns `{ download: <function> }` -- an OBJECT exposing an install-time downloader
HELPER, not a callable function that itself returns a loaded native addon. Calling
`.download(...)` on it is a method call on that bare helper object -- structurally the SAME
"helper, not the binding" shape `_via_loader_invocation` (6a/FIX01B) already exists to
reject, now exercised as an explicit negative control (`checkPrebuildInstallDownload`,
section 4) rather than just reasoned about. `node-pre-gyp`/`@mapbox/node-pre-gyp`'s own real
export shape (6b) is confirmed to be the same kind of helper object, and now also has an
explicit negative control (`checkNodePreGypFind`).

**2. The `<returnValue>` marker preserves the source's own quote character verbatim -- a
real bug, confirmed and fixed.** `_via_loader_invocation`'s marker check was hardcoded to
single quotes (`f"require('{pkg}'):<returnValue>:"`). Regenerating a real fixture with
`require("node-gyp-build")` (double-quoted) showed the frontend produces
`require("node-gyp-build"):<returnValue>:...` -- a DIFFERENT literal string for the exact
same real convention. The hardcoded check would have silently missed every double-quoted
real `require()` call, corpus-wide, with no error at all -- a real, serious gap, not a
theoretical one, given how common double-quoted JS source is. Fixed: `_via_loader_invocation`
now matches via `_loader_invocation_pattern()`, a regex accepting either quote character
(`require(['"]<pkg>['"]\):<returnValue>:`), so the linker's own behavior never depends on
the analyzed package's source-formatting style. Verified directly (not just via the
aggregate count): the double-quoted real fixture case now returns
`is_native_binding_receiver() -> True`; the pre-existing single-quoted real case
(`node-liblzma`'s `isXZ`) re-verified still `True` after the change.

All prior controls, both new negative controls, and both real end-to-end packages
re-verified after both fixes: `registrations=4 linked_js_calls=4 unlinked=0` (controls,
now including the double-quoted `Qux` positive and the two removed-package negatives);
`memoryjs`: `registrations=12 linked=15 unlinked=25`; `node-liblzma`: `registrations=6
linked=6 unlinked=0` -- byte-identical to before both fixes on the two real end-to-end
packages, since both happened to use single-quoted `require()` throughout; the quote-style
fix matters for OTHER, not-yet-tested real corpus packages, which is exactly why it is
fixed now rather than left as a latent, undetected gap.

## 6d. CROSSLANG-LINK-FIX01E: the regex itself was source-formatting-fragile -- replaced

Direct review, correctly predicted before testing: "the quote fix exposed that
`_via_loader_invocation()` still relies on source-formatted `candidate_target_full_names`."
Tested four real, semantically-equivalent programs through the real frontend before
deciding anything:

| Form | Real source | What broke |
|---|---|---|
| Template literal | `` require(`node-gyp-build`)(dir) `` | Marker uses a backtick, not `'`/`"` -- the FIX01D regex's character class doesn't include it. |
| Whitespace | `require( 'node-gyp-build' )( dir )` | `receiver_type` degrades to `"ANY"` entirely -- the FIRST gate fails before the marker regex is even reached. |
| Comment | `require('node-gyp-build') /* load */ (dir)` | Worked, coincidentally (single-quoted, no interference). |
| Aliased (two statements) | `const f = require('pkg'); const native = f(dir);` | `receiver_type` becomes `"pkg:<returnValue>"` DIRECTLY -- a completely different shape; no `"require("` substring exists anywhere for the regex to find. |

**Three of four real, equivalent programs would have been silently mis-decided.** This
confirmed the review's diagnosis precisely: matching on `candidate_target_full_names` text
is fundamentally shaped by source formatting, not derived from real provenance.

**The real fix, as directed:** `resolve_loader_provenance()` -- CANONICAL evidence walked
from real CPG node IDENTITY (call ids, `<operator>.assignment` records, argument node ids),
never a serialized target/marker string. For a candidate call's receiver identifier, it
finds that identifier's own single, unambiguous `<operator>.assignment` (by real id, not
text), and asks: is the RHS an INVOCATION of something that is -- directly, or through up
to `LOADER_ALIAS_DEPTH` bounded hops of single-assignment variable aliasing -- a real
`require(<literal-pkg>)` call for a curated package? The quote-style problem is sidestepped
structurally, not patched around: a string LITERAL's own `code` field is already
quote-NORMALIZED by the frontend to double quotes regardless of the real source's quote
character (confirmed: single/double/backtick `require()` all produce a literal argument
whose `code` is exactly `"node-gyp-build"`), so reading that field directly needs no
per-quote-style branching at all. A BARE `receiver = require(pkg)` (no invocation
wrapping it) is structurally distinguished from `receiver = f(pkg-args)` where `f` itself
resolves to a bare `require(pkg)` (aliased invocation) by walking the real assignment
graph, not by comparing text shapes.

One further real fix inside this same change, found while wiring it in: the canonical
resolver must run BEFORE, not behind, the `receiver_type` gate -- the whitespace case's
`receiver_type` degrades to `"ANY"` even though the underlying `<operator>.assignment`/
`require()` call graph the resolver walks remains fully intact, so gating the canonical
walk behind `receiver_type` would have silently lost exactly the case it exists to
recover. `receiver_type` is now consulted only AFTER the canonical walk, for the
build-path/`.node` branch (no analogous ambiguity there) and as the fallback tier's own
gate.

**The old regex is KEPT, exactly as directed -- demoted to an explicitly labeled FALLBACK,
never presented as established evidence.** Every linked call's own audit record now
carries an `evidence_tier` field (`"canonical"`, `"fallback_marker_regex"`, `"build_path"`,
or `"js_receiver_name"` for the original, untouched `--js-receiver` path) -- a reader can
always tell which tier produced a given link; the merged output never blends them silently.

**Real controls, all four syntax forms, each with its own positive AND bare-helper
negative pair** (`controls/js/index.js`, regenerated through the real frontend):
direct chain, double-quoted chain, template-literal chain, whitespace/comment chain,
aliased two-statement chain -- 14 real controls total now (8 positive: `Foo`/`Bar`/`Baz`/
`Qux`/`Quux`/`Corge`/`Grault`/`Garply`; 6 negative bare-helper/unrelated cases). Real run:
`registrations=8 linked_js_calls=8 (canonical=7 fallback_regex=0 other=1) unlinked=0` --
every real loader-package positive resolves via the CANONICAL tier now (the regex fallback
contributed ZERO real links, across every form tested, including the two real end-to-end
corpus packages below); `Foo` (build-path) is the one `"other"`/`build_path`-tier link, as
designed. Every bare-helper negative verified by direct field inspection, not just the
aggregate count: all six carry `resolution: "HEURISTIC"` (the risk was real in every one)
but `native_binding_receiver_evidence()` correctly returns `(False, None)` -- including the
whitespace case, whose `receiver_type` is `"ANY"`, rejected via the canonical resolver
rather than by accident.

**Both real end-to-end corpus packages re-verified, byte-identical:** `memoryjs`:
`registrations=12 linked=15 (canonical=0 fallback_regex=0 other=15) unlinked=25` (all
`build_path` tier, as expected -- memoryjs never uses a loader package); `node-liblzma`:
`registrations=6 linked=6 (canonical=6 fallback_regex=0 other=0) unlinked=0` -- every one
of its real links now resolves via the canonical mechanism, zero reliance on the fallback
regex, where before this fix ALL SIX depended entirely on it.

## 6e. CROSSLANG-LINK-FIX01F: "exactly one assignment by name" was not real reaching-def

Direct review, correctly predicted before testing: FIX01E's `resolve_loader_provenance`
matches "exactly one `<operator>.assignment` to this NAME, anywhere in the file" -- a blunt
proxy for real reaching-definition, not the real thing. Five real, adversarial programs
were built and run through the real frontend to check this precisely, matching the
instruction's own list:

| Case | Real shape | What FIX01E did (before this fix) |
|---|---|---|
| Overwrite-before-use | `native1 = require(pkg)(dir); native1 = fakeObject; native1.Foo();` | **FALSE POSITIVE** via the fallback tier -- canonical correctly abstained (2 assignments), but the regex fallback has no concept of reassignment and matched anyway. The real call at runtime invokes the fake object, not the native binding. |
| Branch multi-definition | `if (c) { native2 = require(pkg)(dir); } else { native2 = fakeObject; } native2.Bar();` | **FALSE POSITIVE**, same mechanism -- canonical abstained, fallback matched regardless of which branch actually ran. |
| Parameter shadowing | `const native3 = require(pkg)(dir); function wrap(native3) { return native3.Baz(); }` | **FALSE POSITIVE via the CANONICAL tier itself** -- the worst of the three: the inner function's own PARAMETER `native3` shadows the outer definition entirely, is bound to a real caller-supplied value at the actual call site, and the "exactly one assignment by name" check had zero awareness that parameters exist at all. |
| Assignment-after-use | `function callQux() { return native4.Qux(); } var native4; native4 = require(pkg)(dir);` | Not decisively differentiated by this fixture (the function was never actually invoked before the assignment in the test) -- see the disclosed limitation below. |
| Alias cycle | `let x5 = someFn; let y5 = x5; x5 = y5; const native6 = x5(dir);` (neither ever bottoms out at a real `require()`) | Correctly rejected, no hang or crash (the existing depth bound already handled this safely). |

**Three of five real cases -- the two most operationally common (reassignment,
conditional definition) plus the most security-relevant (parameter shadowing) -- would
have produced a false link.** This confirms the review's diagnosis: name-based lookup
across the WHOLE FILE, with no awareness of scope, shadowing, or multiplicity beyond a
blunt count, is not real reaching-definition.

**The real fix, as directed:** provenance is now keyed by DEFINITION node identity within a
real, reconstructed LEXICAL SCOPE chain, not by name alone. `JsCallIndex.function_ancestor_
chain()` derives a function's real, structural nesting path from the frontend's own
colon-separated `full_name` convention (confirmed real and reliable: a function nested
`program -> outer -> inner` gets `full_name` `"file::program:outer:inner"`, and EVERY
successive colon-delimited prefix is independently a real function's own `full_name` in
this schema -- verified directly, not assumed, before relying on it). `JsCallIndex.
receiver_definition()` then requires ALL of:

1. Exactly one real `<operator>.assignment` to the name anywhere in the file (unchanged
   from FIX01E, but now the SOLE gate for identity, not a check only the canonical tier
   respected).
2. The assignment's own enclosing function is a REAL ancestor of (or equal to) the use
   site's enclosing function in the reconstructed lexical chain -- an assignment in an
   unrelated/sibling scope is `DEFINITION_NOT_IN_SCOPE`, not a match.
3. No function strictly between the definition's scope and the use site (inclusive of the
   use site's own function) declares a PARAMETER with the same name -- `PARAMETER_SHADOWED`
   otherwise.

Every real abstention reason (`MULTIPLE_DEFINITIONS_AMBIGUOUS`, `SCOPE_UNRESOLVED`,
`DEFINITION_NOT_IN_SCOPE`, `PARAMETER_SHADOWED`, `BARE_LOADER_REFERENCE`,
`CALLEE_NOT_REQUIRE`) is now explicit, not a silent `None` -- exactly as directed
("ambiguous reaching definitions must abstain with an explicit reason"). This same,
identical check is now used for the ALIAS-hop resolution inside `_callee_resolves_to_
require()` too (an alias is exactly as capable of being ambiguous or shadowed as the
top-level receiver, and was not checked this way before this fix).

**CFG reachability, as the instruction also offered as an alternative:** at the time of
this fix, the JS/TS program-facts schema did not export CFG edges at all (confirmed:
`export_neutral.sc`'s own output had no `cfg_edges` key, unlike the C/C++ side) --
building real CFG-based reachability would require a genuine frontend/export change, not
a Python-side fix. The lexical-scope + single-definition + shadow check above is the
strongest provenance available from data exported AT THIS POINT, and it is what actually
falsified all three real bugs above -- stated precisely as what it is, not oversold as
full dataflow reachability. **This gap was closed in CROSSLANG-LINK-FIX01G below
(section 6f)**, once real adversarial testing showed scope-uniqueness alone is not
sufficient either.

**The regex fallback is now gated behind this SAME check, not tried independently** --
confirmed necessary: without this, the fallback alone reproduces the overwrite/branch false
positives (it matches on marker TEXT, which has no concept of reassignment at all). The
fallback is now reached ONLY when `resolve_loader_provenance` returns the specific
`'CALLEE_NOT_REQUIRE'` reason -- meaning the receiver's identity is ALREADY established as
real, single, in-scope, and unshadowed; only the shape of its own value could not be
canonically proven. Every other abstention reason is now a hard rejection the fallback
never gets a chance to override.

**Disclosed limitation, not silently left out:** assignment-AFTER-use in true execution
order (a closure invoked before its capturing assignment actually runs -- possible in real
JS via hoisting/event-loop timing) is NOT independently verified, because no CFG/execution-
order data is available (same underlying gap as the CFG-reachability point above). This
analysis assumes the standard, near-universal CommonJS pattern real native-addon packages
follow: the whole module body (including the `require()` call that loads the binding) runs
to completion synchronously before any function that uses the binding is ever invoked by an
external consumer of the package. A pathological package that invokes its own callback
before its `require()` line executes would not be caught by this check -- stated here as a
real, disclosed boundary, not discovered as a surprise later.

**Real audit-trail quality check, not just a design claim:** logging every real abstention
reason unfiltered was tried first and found to swamp the audit trail on real data (`node-
liblzma`: 220 entries, nearly all unrelated array/promise-method calls whose names happened
to be reassigned elsewhere in the file for reasons having nothing to do with loaders --
`resolve_loader_provenance` necessarily runs for EVERY identifier receiver, not only
loader-shaped ones, to still catch the whitespace-degraded-`receiver_type` case). Narrowed
to only log when the call's own `receiver_type` is at least PLAUSIBLY loader-related (a
curated package name, a build-path/`.node` shape, or the degraded `"ANY"` this project's
own whitespace fixture proved can still hide a real loader use) -- real result:
`node-liblzma` 220 -> 29, `memoryjs` 90 -> 15, the controls fixture 9 -> 4. Some residual
noise remains (generic method calls on an `ANY`-typed receiver still appear) -- a real,
disclosed tradeoff: `"ANY"` cannot be dropped from the filter without losing the exact
whitespace case this whole redesign exists to catch.

**All prior real controls, all five reaching-definition probes, and both real end-to-end
corpus packages re-verified after this fix:** the 14-control fixture and both end-to-end
packages reproduce IDENTICAL `linked`/`unlinked` counts to before this fix (`registrations=8
linked=8 unlinked=0`; `memoryjs`: `registrations=12 linked=15 unlinked=25`; `node-liblzma`:
`registrations=6 linked=6 unlinked=0`) -- this fix closes real false-positive risk without
losing any previously-correct real link. The five reaching-definition probes (a NEW real
fixture, `controls/js_reaching_def_probe/reaching_def_probe.js`) now resolve exactly as
intended: overwrite and
branch cases -> `MULTIPLE_DEFINITIONS_AMBIGUOUS`; parameter shadowing ->
`PARAMETER_SHADOWED`; the single, real, unambiguous definition case (`Qux`) -> accepted
(tagged `canonical` at the time this section was written; see section 6f, where this
same case's tag changes to `dominance_proven` once real CFG dominance is also checked --
the accept decision itself does not change); the alias cycle -> `CALLEE_NOT_REQUIRE`, no
hang or crash.

## 6f. CROSSLANG-LINK-FIX01G: scope-uniqueness was not real reachability either

Direct instruction: test assignment-after-use, one-branch-only assignment, loop-only
assignment, and try/catch-only assignment through the real frontend; the FIX01F
"unique-scope-definition" rule must not establish loader provenance for any of them;
first check whether jssrc2cpg already contains usable CFG edges even though the exporter
omits them, and if so extend the exporter/normalizer and prove real dominance; rename the
existing tier from `canonical` to `scope_unique` until true reachability is established;
apply the same gate to the regex fallback.

**A new, real, adversarial fixture** (`controls/cfg_dominance_probe/index.js`, four
cases, each with exactly ONE real `<operator>.assignment` to its name so FIX01F's own
rule cannot reject any of them on scope-uniqueness alone):

| Case | Shape | FIX01F verdict (before this fix) |
|---|---|---|
| `Foo` | assignment-after-use: `callFoo()` invoked synchronously BEFORE the `require(...)` line | WRONGLY `matched=True, tier=canonical` |
| `Bar` | one-branch-only: the sole assignment is inside an `if` with no `else` | WRONGLY `matched=True, tier=canonical` |
| `Baz` | loop-only: the sole assignment is inside a `for` loop body | WRONGLY `matched=True, tier=canonical` |
| `Qux` | try/catch-only: the sole assignment is inside a `try`, empty `catch` | WRONGLY `matched=True, tier=canonical` |

All four confirmed wrongly accepted by direct testing against the FIX01F implementation
before starting this fix -- exactly the gap the instruction predicted.

**Step 1 -- do real CFG edges exist?** Checked directly via Joern REPL on the real CPG
(`fooCall.outE("CFG").l` / `.inE("CFG").l` / `.cfgNext`) before writing any exporter
code: yes, jssrc2cpg builds real CFG structure; the exporter had simply never surfaced
it. This settled which branch of the instruction applied -- extend the exporter, not the
"CFG facts genuinely do not exist" conservative fallback.

**Step 2 -- extending the exporter, and a real quirk found while doing it.**
`export_neutral.sc` gained two new blocks: `cfg_edges.tsv` (owner/from/to, walking
`method.cfgNode.cfgNext`, mirroring the C/C++ side's own `export_c_cpp_facts_v03.sc`
convention exactly) and `method_cfg_endpoints.tsv` (method_id/entry_id/exit_id, using
the Method node as entry and MethodReturn as exit -- Joern's own stated convention).

Regenerating the cfg_dominance_probe fixture's real facts through this first version and
inspecting the raw edges directly (not assumed) found the exit id UNREACHABLE from the
walked edge set for every function: `method.cfgNode` -- the set the walk iterates --
excludes BOTH the Method node itself and its own MethodReturn node. Confirmed precisely
via direct REPL query: `RETURN.cfgNext` (successor, the semantic step the walk uses)
returns EMPTY even though a real raw CFG edge into MethodReturn exists
(`methodReturn.inE("CFG").size == 1`, and `methodReturn.cfgIn` -- the PREDECESSOR step --
correctly returns the real terminal node). An intentional, direction-asymmetric filter in
Joern's own semantic CFG steps, not a bug in this exporter, but one that silently breaks
every dominance computation downstream if not patched around. Fixed by adding the two
boundary hops explicitly: `method.start.cfgNext` for entry -> first-real-node, and
`method.methodReturn.cfgIn` for last-real-node(s) -> exit. Re-verified real: the
cfg_dominance_probe fixture's edge count went 127 -> 137 (the ten real boundary hops
across five real functions), and entry/exit became reachable from the walked graph.

**Step 3 -- `loader_definition_dominates()`, the real dominance algorithm
(`link_napi_facts.py`).** Standard node-removal CFG dominance (`cfg_dominates()`): does
every real path from a function's entry to a target node pass through a given node?
Applied as two real, disclosed requirements, both necessary before a `scope_unique`
definition (FIX01F's rule, renamed from `canonical` since it establishes scope-
uniqueness only, nothing about execution order) is trusted as loader provenance:

  (a) the assignment must dominate its own defining function's real exit (MethodReturn)
      -- any real path from entry to a real return statement that bypasses the
      assignment fails this. This alone rejects `Bar` (the `else`-less branch has a path
      to exit that never assigns) and `Baz` (the loop may run zero times, so a path to
      exit exists that never enters the body) -- confirmed real, independent of whether
      the defining function is ever invoked at all.

  (b) ONLY when the use lives in a DIFFERENT function than the assignment, the
      assignment must ALSO dominate every real, DIRECT, SAME-DEFINING-SCOPE call whose
      own `candidate_target_ids` names the use's function. This is what rejects `Foo`:
      the assignment alone unconditionally dominates its own function's exit (it is the
      last, straight-line statement -- check (a) alone would WRONGLY accept it), but the
      direct `callFoo();` invocation inside the SAME scope, found via (b), is NOT
      dominated by the assignment (it runs first) -- correctly rejected.

  Check (b)'s scope is deliberately bounded and disclosed: only a call found DIRECTLY
  within the assignment's own defining function is checked, matching this project's
  established bounded-trace discipline (`LOADER_ALIAS_DEPTH`). A function merely
  DEFINED then exported via `module.exports`, invoked later by external code after the
  whole module has finished loading -- the common, safe, real pattern -- is correctly
  NOT penalized: no such invocation site exists inside the defining function to check,
  so only requirement (a) applies, which that pattern already satisfies. Verified as a
  real, deliberate A/B distinction, not just an assumption: the reaching-def probe's own
  `Qux` case (FIX01F, section 6e -- assignment-after-use, but the closure is only
  EXPORTED, never invoked within that file) is now correctly ACCEPTED
  (`dominance_proven`) by this exact same code path, while cfg_dominance_probe's `Foo`
  (assignment-after-use WITH a real, direct, same-scope invocation before the
  assignment) is correctly REJECTED -- the two fixtures differ in exactly the one
  variable this design means to test.

**Step 4 -- a second real gap, found only by testing, not anticipated in the design:**
after steps 1-3, `Qux` (try/catch-only) was still WRONGLY accepted
(`dominance_proven`). Investigated by direct REPL query rather than assumed: jssrc2cpg's
static CFG construction does not model an implicit exceptional edge from an arbitrary
statement into its `catch` handler -- only a real, explicit `throw` statement would
create one, and this fixture has none. Removing the assignment node from the graph
(the dominance test's own node-removal step) therefore finds NO alternate path to exit
through the catch block, because the catch block is not wired into this frontend's CFG
at all for this shape -- CFG dominance is genuinely UNSOUND for a try-nested assignment,
not merely imprecise. Fixed by adding a third, real, disclosed exported fact,
`try_nested_calls.tsv` (`cpg.controlStructure.controlStructureType("TRY").ast.isCall.id`
-- confirmed via REPL to correctly identify the real assignment call id nested inside
the fixture's own `try` block), and an explicit, syntactic override in
`loader_definition_dominates()`: an assignment AST-nested inside a `try` block is
rejected outright (`DEFINITION_IN_TRY_BLOCK_UNVERIFIABLE`), regardless of what CFG
dominance alone would say, since that answer cannot be trusted for this shape.

**The regex fallback tier is gated by the identical dominance requirement, with no
separate plumbing needed** -- by construction: `resolve_loader_provenance()` now runs
the dominance check immediately after establishing a `scope_unique` definition, BEFORE
ever inspecting the definition's own value shape. The `CALLEE_NOT_REQUIRE` reason (the
ONLY reason the fallback is ever tried) can therefore only be reached AFTER dominance has
already passed. The same dominance check is also applied to each alias hop inside
`_callee_resolves_to_require()` (an alias is exactly as capable of being defined in a
dead branch, a loop, a try block, or after its own use as the top-level receiver is).

**Tier naming.** Per direct instruction, the FIX01F tier is not called `canonical` in
this file's own internal terminology any more -- `JsCallIndex.receiver_definition()`
establishes SCOPE_UNIQUE evidence only, a real but, as these four fixtures proved, NOT
sufficient condition. Accepted, dominance-proven evidence is now tagged
`"dominance_proven"` in `link_napi_facts.py`'s own output (not `"scope_unique"` -- that
name would itself have been a real overclaim, since a `scope_unique` definition that
fails dominance is REJECTED, never surfaced as a linked call under any tier name).
`"scope_unique"` is used only descriptively, for the specific, narrower thing FIX01F's
own reaching-definition check establishes on its own.

**All prior real controls, all five FIX01F reaching-definition probes, and both real
end-to-end corpus packages re-verified after this fix, re-run through the extended
exporter so real `cfg_edges`/`method_cfg_endpoints`/`try_nested_calls` data is present
(not assumed carried over from stale facts):** the 14-control fixture reproduces IDENTICAL
counts (`registrations=8 linked=8 unlinked=0`; 7 of the 8 positives now tagged
`dominance_proven`, one straight `build_path` match unaffected by this fix's scope);
`memoryjs` reproduces IDENTICAL counts (`registrations=12 linked=15 unlinked=25`; all 15
were always `build_path` matches, outside this fix's scope entirely, confirming this fix
changes nothing for a package that loads its binding via a direct build-path require);
`node-liblzma` reproduces the SAME 6 `dominance_proven` links, 0 unlinked, plus ONE new,
real, correctly-conservative abstention (`DEFINITION_IN_TRY_BLOCK_UNVERIFIABLE`, 29 -> 30
abstained) on a real, previously-unflagged try-nested loader-adjacent assignment
elsewhere in that package's own source -- a genuine new finding from this fix, not a
regression. The five FIX01F reaching-def probes are unaffected except `Qux`, whose tier
label changed from `canonical` to `dominance_proven` (same accept decision, stronger,
now-accurate evidence). `gate_crosslang_link_fix.py` (new, this fix) re-asserts all of
the above plus the four new cfg_dominance_probe cases in one script: PASS.

## 7. What happens next (after R05 is frozen -- not started yet)

Per direct instruction: this branch stays unmerged until the R05 corpus rerun (main working
tree, separate branch) is frozen. Once it is, the plan is to RERUN ONLY THE LINKER over the
already-saved JS/C++ facts from that run (no CPG rebuild needed -- normalize_c_cpp_facts_v03.py
and normalize_joern_facts.py's outputs are the only inputs `link_napi_facts.py` needs, and
`run_pipeline_one.py` currently deletes them per-package; the R05 rerun would need to be told
to retain `cpp_facts.json`/`js_facts_adapted.json` for this purpose, or this fix folded into
a small follow-up pass that regenerates just those two artifacts from each package's already-
downloaded tarball -- decided at merge time, not before), then report, corpus-wide:

- packages with real C++ registrations (`n_registrations > 0`);
- packages with at least one eligible JS native receiver (`is_native_binding_receiver` true
  for at least one real candidate call);
- total linked vs. ambiguous/unlinked calls, corpus-wide;
- how many linked calls reach a real R05 (or R04-direct) finding;
- complete JS-input -> native-callback -> vulnerable-site paths, where establishable.

Not started -- this section exists so the plan is on record before the merge, not invented
after the fact.
