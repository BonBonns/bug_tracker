# node-libcurl@5.1.2: real false-positive review, two corpus-wide R05 defects found and fixed

Found while manually spot-checking the first real finding surfaced by the still-running
494-package R05 corpus rerun (`full_scan_r05_working.jsonl`, real, unattended background
scan -- not touched by this review). Verified against the exact real published tarball
(`node-libcurl@5.1.2`, the current npm `latest`, sha512-matched against
`eligible_packages.tsv`'s own recorded hash), never assumed.

## The finding

`Easy::ReadFunction` (`Easy.cc:1599`), `Napi::Buffer<char>::New(env, n)` where
`n = size * nmemb` -- R05 classified `VALUE_ACQUISITION_GUARD_MISSING`, tracing `size` as
attacker-influenced (`"hops": 3, "traced_to_parameter": "size"`).

## Verdict: FALSE POSITIVE, for two independent, compounding reasons

1. **`size` is not JS/attacker-controlled.** `ReadFunction` is registered exactly once via
   `curl_easy_setopt(this->ch, CURLOPT_READFUNCTION, Easy::ReadFunction)` -- a libcurl
   callback, invoked internally by libcurl during a transfer, never called by JS. Per
   libcurl's own `CURLOPT_READFUNCTION` contract (confirmed by the function's own header
   comment, "Called by libcurl as soon as it needs to read data") and confirmed
   structurally in the real code -- the JS callback receives `size`/`nmemb` only as
   read-only informational `Napi::Number` arguments; it never supplies or influences them.
   R05's own `attacker_influence_evidence` reached a C++ function PARAMETER and treated
   that alone as attacker evidence, without checking who actually calls the function or
   populates that parameter -- a real, general, corpus-wide analyzer defect (see below).

2. **The contract's own applicability precondition (exceptions disabled) does not hold.**
   `binding.gyp` explicitly depends on node-addon-api's `node_addon_api_except` gyp target
   (comment: "using exceptions (instead of maybe, like we used to have on nan)"). Traced
   through node-addon-api 8.5.0's real `node_addon_api.gyp` -> `except.gypi` -> `defines:
   NAPI_CPP_EXCEPTIONS`. `ReadFunction`'s own code confirms it explicitly in a comment:
   "This is in theory not needed, as we have exceptions enabled." Traced the real macro
   chain in node-addon-api 8.5.0 (`napi.h`): with exceptions enabled,
   `Buffer<T>::New`'s own `NAPI_THROW_IF_FAILED` throws a real `Napi::Error` C++ exception
   on allocation failure, BEFORE any Buffer is returned -- and `ReadFunction`'s own code
   wraps the allocation in a `try`/`catch (const Napi::Error&)` that converts this into a
   clean `CURL_READFUNC_ABORT` return to libcurl. A real, working guard, just implemented
   via C++ exceptions rather than the explicit `.IsEmpty()`/null-`Data()` pattern R05's
   static contract-matching looks for. `npm_build_configuration.tsv`'s own precomputed row
   said "disabled" -- itself the second real defect (below).

## Defect 1 -- parameter reached != attacker-controlled

R05's backward attacker-influence trace reaches a C++ function's own parameter and stops
there, without verifying the function is actually reachable from JS (as opposed to a
native callback invoked by a native library like libcurl). Deferred: change this evidence
class from being treated as established attacker influence to an explicit
`SOURCE_BOUNDARY_UNRESOLVED` state, resolved to real attacker influence only when JS
linkage or a real, curated callback contract proves it -- not implemented in this pass
(deferred to the post-R05-freeze rerun, per the agreed plan; R05 itself stays untouched
and running).

## Defect 2 -- build-configuration extraction, fixed now (`extract_build_config.py`)

Root-caused by direct comparison of `npm_build_configuration.tsv`'s own recorded row
(`node-libcurl 5.1.2 disabled binding.gyp: -fno-exceptions`) against the real source:

1. **Gyp `<key>!` list-removal polarity.** `binding.gyp` contains
   `'cflags!': ['-fno-exceptions', '-O3']` / `'cflags_cc!': [...]` -- node-addon-api's own
   canonical `except.gypi` idiom, copied inline, comment "# Allow C++ exceptions" directly
   above it. A flat text search for the substring `-fno-exceptions` cannot see that gyp's
   `!`-suffixed list keys REMOVE entries from an inherited list rather than adding to
   them -- the extractor found the disable-looking substring and reported "disabled", the
   OPPOSITE of the source's own explicit, commented intent.
2. **Missing node-addon-api gyp target-name convention.** A package can enable exceptions
   purely via depending on the `node_addon_api_except`/`node_addon_api_except_all` gyp
   target (`node-libcurl`'s own real usage:
   `"<!(node -p \"require('node-addon-api').targets\"):node_addon_api_except"`) without the
   literal text `NAPI_CPP_EXCEPTIONS` ever appearing in the package's own binding.gyp.

Fixed in `extract_build_config.py`: `_gyp_removal_spans()`/`_in_any_span()` detect real
`<key>!` list bodies in binding.gyp and invert matched-pattern polarity only for matches
genuinely inside one; a new enable pattern matches the real `node_addon_api_except` gyp
target-name convention. See the file's own module docstring and inline comments for the
full account.

**Verified, not assumed:**
- `node-libcurl@5.1.2` (the regression case): `disabled` -> `enabled`, both new enable
  signals present, zero disable evidence remaining.
- `node-crc16@2.0.7` (used as a negative control in the same review): `disabled` ->
  `conflict` -- its real `binding.gyp` is genuinely internally self-contradictory
  (target-level cflags remove `-fno-exceptions`, but top-level cflags add it back, AND a
  separate, unconditional `NAPI_DISABLE_CPP_EXCEPTIONS` define is also present) -- a MORE
  honest classification than the old code's silent "disabled", not a regression (this
  package's own R05 verdict is unaffected either way: its one recovered acquisition was
  independently classified `SIZE_ATTACKER_INDEPENDENT`, a fixed-literal buffer size,
  never reaching the exceptions-applicability gate at all).
- A broader, real, 20-package sample (5 each from the corpus's existing
  disabled/enabled/unresolved/conflict buckets, refetched from the real registry): **8 of
  20 (40%) changed classification, ALL from disabled/conflict to enabled**, all via the
  gyp `!`-list-removal pattern -- confirming this is a real, high-impact, corpus-wide
  defect, not a one-off specific to node-libcurl. Every "enabled"/"unresolved" sampled
  package, and the one genuinely-still-`conflict` sampled package (`node-spdlog`), were
  unaffected (`SAME`) -- no evidence this fix over-corrects.

**Not done in this pass, per the agreed plan (R05 keeps running unattended; these steps
wait until it finishes, so the two expensive jobs never compete for the same container):**
- Re-extract `npm_build_configuration.tsv` for all 494 real corpus packages with the fixed
  extractor.
- Implement `SOURCE_BOUNDARY_UNRESOLVED` (Defect 1) in `resource_guard_verdict_r05.py`.
- Rerun R04/R05 verdict generation only, over already-saved facts (no CPG rebuild).
- Re-review all resulting findings.

## R06 addendum: the 40% flip rate needed target-scoping verification -- it did NOT hold up unmodified

Direct review flagged a real, un-checked risk in the section above: a single binding.gyp
can define MULTIPLE gyp targets, each with its OWN, independently-resolved exception
configuration (per-target cflags/cflags_cc/defines, OS-`conditions` branches, or
per-target `dependencies`) -- the whole-package `classify_from_tarball()` fix above
(Defect 2) still does FLAT, package-wide text matching, which can silently MERGE two
genuinely different targets' evidence into one misleading verdict, or attribute evidence
to a target that does not even compile the file the finding is actually in.

**Fixed** (`extract_build_config.py`): `parse_gyp_targets()` -- a real, quote-and-comment-
aware, bracket-matching parser (NOT another flat regex) that finds each real gyp target's
own `{...}` block, its own `sources` list, and a real `target_defaults` block if present
-- `classify_target_aware()` (per-target classification, scoped to each target's own real
block span union `target_defaults`), and `resolve_build_config_for_file()` (the real,
required entry point: given a finding's own source file, resolves EXACTLY the target that
compiles it; zero or conflicting matches yield `BUILD_CONFIGURATION_UNRESOLVED`/
`"conflict"`, NEVER a package-wide guess).

A genuine parsing bug was found and fixed WHILE building this against real corpus text,
not merely the synthetic fixtures: node-libcurl's own real binding.gyp contains a `#`
comment reading "...because it doesn't start with a -..." -- a real, single, UNBALANCED
apostrophe. Without skipping `#`-to-end-of-line comments FIRST, the quote-aware bracket
matcher treated that apostrophe as opening a real string and silently consumed real gyp
structure (including the actual closing bracket) scanning for a matching quote that was
never there. Fixed via `_skip_gyp_comment()`, checked before string detection in every
scanning loop. Caught by the real end-to-end node-libcurl regression check in
`tests/test_target_scoping.py`, not by any synthetic fixture -- exactly the value of
testing against real, not hand-typed, corpus text.

**Five real, adversarial fixtures** (`tests/test_target_scoping.py`, all PASS): two
targets with genuinely different real configs (one `enabled`, one `disabled`, each real
source file resolves to its OWN target's own verdict, never the other's); a `cflags!`
removal in an UNRELATED target correctly does NOT contaminate the real target that
actually compiles the finding's file; a real OS-`conditions` branch (both branches
statically visible, cannot resolve which OS applies) correctly yields `conflict`, never a
guess; a removal immediately followed by a target-level re-add within the SAME target
correctly yields `conflict` (both real signals present in the same scope); real
`node_addon_api_except` vs. bare `node_addon_api` dependency correctly distinguishes
`enabled` from `unresolved` (bare `node_addon_api` is deliberately NOT treated as disable
evidence on its own -- a real, disclosed, conservative choice, not a proven-safe default).

**The 40% flip-rate number from section 3 above needed re-verification, not blind
trust, and it partially changed shape under target-aware resolution:**
re-ran the SAME 20-package sample through `classify_target_aware()`. Of 19 packages with a
real binding.gyp, **17 have exactly ONE real gyp target** -- for those, target-aware and
package-wide resolution are, by construction, identical, so the original 40%-flip finding
stands UNCHANGED for the single-target majority. But real, concrete divergence was found
in the remaining two:

- **`node-spdlog@0.1.5`**: the whole-package flat classifier reports `conflict` (both
  disable and enable evidence found SOMEWHERE in the tarball's matched config files), but
  its one real gyp target resolves CLEANLY to `enabled` on its own real scope -- the
  package-wide "conflict" was itself a package-wide-merge artifact, not a genuine
  ambiguity in the target that actually compiles the code. The section-3 table above
  listed this package as "unaffected (SAME)" under the flat-vs-flat comparison; it is
  NOT actually a safe, resolved case once scoped to the real compiling target.
- **`node-snap7-micro-client@0.1.0`**: TWO real gyp targets
  (`node_snap7_micro_client`, `snap7-micro-client`) with GENUINELY DIFFERENT real
  configs (`enabled`, `unresolved`) -- the flat package-wide verdict (`conflict` before
  this fix, `enabled` after Defect 2 alone) is only correct for whichever target
  actually compiles the finding's own file, and WRONG (silently swallowing a real
  `unresolved` target) for the other. Confirms, concretely, the exact real risk direct
  review predicted, not merely a theoretical one.

**Conclusion, stated precisely, not oversold:** the underlying Defect 2 fix (gyp
`!`-list-removal polarity, `node_addon_api_except`) is real and correct at the SINGLE-
TARGET-SCOPE level, confirmed by both the synthetic fixtures and the real regression
cases. The 40% flip-rate number is NOT retracted, but it is NOT a corpus-wide-final
statistic either: it was computed via flat, package-wide comparison, real multi-target
packages exist in the corpus (2 of 19 real, gyp-based packages in this small sample
alone), and package-wide merging is confirmed, concretely, to sometimes disagree with
the real, correctly-scoped, per-target answer. The full corpus-wide re-extraction
(deferred until R05 finishes, per the agreed plan) MUST use `resolve_build_config_for_
file()` against each finding's own real source file, never the flat, package-wide
`classify_from_tarball()` result, and any resulting corpus statistic must be reported
target-resolved, not re-quoted from this preliminary flat-comparison number.

## Separate, NOT combined with this false positive: a real candidate needing its own review

`Easy::ReadFunction`'s own downstream code: `returnValue` (the JS callback's own claimed
byte count) is checked `> 0 && < CURL_READFUNC_ABORT` but never bounds-checked against `n`
(the actual allocated buffer size) before `std::memcpy(ptr, data, returnValue)`. If a JS
callback returns a value larger than `n`, this is a real heap over-read from `data`
(and likely an over-write into `ptr`, itself sized `n` on libcurl's side). This is a
DIFFERENT vulnerability shape (an unchecked-length copy from a JS-influenced RETURN VALUE,
not an unguarded allocation) and a DIFFERENT threat actor (the JS callback is
application-developer-supplied code, not literally the same "attacker" model R04/R05
target) -- it is NOT folded into the verdict above, and requires its own real controls and
threat-model analysis before any classification. Recorded here so it is not lost.

## R06 addendum: SOURCE_BOUNDARY_UNRESOLVED -- reaching a parameter is not attacker control

Defect 1 (deferred in the sections above) is now fixed: `backward_attacker_trace` (both
R04's and R05's own copy) treated reaching ANY real parameter of the call's own enclosing
method as proof of "attacker influence" -- no check on whether that method is itself
reachable from JS at all. `Easy::ReadFunction`'s own `size` parameter is a real, concrete
case: libcurl-supplied, never JS-supplied, yet `attacker_influence_evidence:
{"traced_to_parameter": "size", "hops": 3}` implied otherwise.

**Fixed in a new `resource_guard_verdict_r06.py`** (a proper frozen copy of R05, matching
this project's own established R01->R05 lineage discipline -- R05 itself is untouched):
the reached parameter's own real `type_full_name` (already present in `parameters.tsv`,
just not previously consulted) is checked against `JS_CALLBACK_ORIGIN_TYPES` --
node-addon-api's real, canonical N-API entry-point parameter type, `Napi::CallbackInfo`
(matched tolerant of the real rendering variance c2cpg itself produces -- both
`"Napi::CallbackInfo"` and `"Napi.CallbackInfo&"` confirmed real, see below). A parameter
of this type is N-API's own ONLY mechanism for JS-caller-supplied data to enter native
code (`info[i]` access) -- real, structural, verified JS-linkage, tagged
`"source_boundary": "JS_CALLBACK_INFO_PARAMETER", "attacker_controlled": true`. Any OTHER
reached parameter is now reported `"source_boundary": "SOURCE_BOUNDARY_UNRESOLVED",
"attacker_controlled": false` -- explicitly, never silently dropped, never claimed as
attacker evidence. The finding's own field is renamed `source_boundary_evidence`
(from `attacker_influence_evidence`, which itself overclaimed once a reached parameter
could mean either proven linkage or an unresolved boundary). This corrects the EVIDENCE
FIELD's own claimed meaning; it does not suppress or change the underlying
`VALUE_ACQUISITION_GUARD_MISSING` verdict, which was never actually gated on
`attacker_trace` succeeding in the first place (confirmed by reading R04/R05's own
verdict-construction code directly) -- the contract's own failure predicate (an unguarded
acquisition result) is a real, separate claim regardless of proven attacker influence on
the size argument specifically.

**Three real verifications, not synthetic assumptions:**

1. **node-libcurl -- the required rejection case.** Ran the REAL published tarball through
   the actual pipeline (`run_pipeline_one.run_one`, fully isolated `work_root` far outside
   the live R05 scan's own index range, confirmed zero interference before and after) to
   generate real, fresh C++ facts, then ran `resource_guard_verdict_r06.py` directly
   against them: `ReadFunction`'s own finding now shows exactly `{"attacker_controlled":
   False, "source_boundary": "SOURCE_BOUNDARY_UNRESOLVED", "parameter_type": "size_t",
   "traced_to_parameter": "size", "hops": 3}` -- confirmed correct rejection on real,
   live-generated data, not reasoned about abstractly.
2. **`r05_controls`' own real, committed, compiled fixture -- the real positive
   confirmation that `JS_CALLBACK_INFO_PARAMETER` actually fires.** `PositiveBufferNew`'s
   own finding shows `{"attacker_controlled": True, "source_boundary":
   "JS_CALLBACK_INFO_PARAMETER", "parameter_type": "Napi.CallbackInfo&",
   "traced_to_parameter": "info", "hops": 5}` -- confirms the mechanism itself works on
   real, compiled, real-`#include <napi.h>` code. This control's own `build_config.json`
   is deliberately gitignored (`study/resource_guard_r05/.gitignore`, present only
   locally from earlier session work, never tracked) -- respected as an existing,
   deliberate policy rather than forced into git; `tests/test_source_boundary.py`
   instead constructs the same, real, small config content inline (the fixture is
   compiled with `-DNAPI_DISABLE_CPP_EXCEPTIONS`, confirmed from `fixture_source.cpp`),
   so the test stays genuinely self-contained and reproducible from git alone without
   overriding that policy. Note the real type string c2cpg
   produces is `"Napi.CallbackInfo&"` (a DOT, not `::`) -- confirmed real via this exact
   run, which is why `JS_CALLBACK_ORIGIN_TYPES` matches both forms; the dot form was not
   an assumption, it is what real c2cpg output actually contains.
3. **Cartesi -- requested as the positive development case; found, honestly, to NOT
   exercise this specific code path at all, before or after this fix.** Ran R06 against
   the real, cached Cartesi raw facts (`/tmp/cartesi_raw5`, same real data the original
   R05 recovery used) with the real build-config used at the time: all 3 real findings
   (`ReadMemory`, `ReadVirtualMemory`, `ReadConsoleOutput`) are UNCHANGED --
   `source_boundary_evidence: None` under R06, exactly matching `attacker_influence_
   evidence: None` under the original, unmodified R05 on the identical data. This is
   NOT a regression: `backward_attacker_trace`'s own backward walk never reaches ANY
   parameter for these three specific real acquisition sites at all (exhausted before
   reaching one, or the size value's own real definition chain does not resolve to a
   bare parameter name within the walk's structure) -- a real, pre-existing
   characteristic of these sites, confirmed identical on both sides, unrelated to this
   fix. Cartesi therefore serves as a real, valid REGRESSION check (proving the fix
   changes nothing about Cartesi's own 3 real findings) but NOT as a working example of
   the new `JS_CALLBACK_INFO_PARAMETER` path specifically -- `r05_controls` (2 above) is
   the real fixture that demonstrates that. Reported precisely rather than silently
   assumed to confirm what was asked.

**Not done in this pass, per the agreed plan:** applying this same fix's logic to R04
directly (R04 stays frozen, matching this lineage's own established discipline -- a
package running ONLY R04, never reaching R05's recovery path, would still see the old,
uncorrected `attacker_influence_evidence` field; out of scope for this pass, disclosed
rather than silently left inconsistent); establishing real JS-source-to-native-argument
linkage beyond the CallbackInfo-parameter case (e.g. joining `link_napi_facts.py`'s own
real cross-language links once that work is merged) is a distinct, larger effort, not
attempted here; rerunning R06 corpus-wide waits for R05 to finish, per the same resource-
contention discipline as the build-config fix.

`tests/test_source_boundary.py` (new, committed): direct unit checks of
`_is_js_callback_origin_type` against real and synthetic type strings, plus the real,
now-self-contained `r05_controls` regression check (verification #2 above) -- both PASS.
