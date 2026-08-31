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
