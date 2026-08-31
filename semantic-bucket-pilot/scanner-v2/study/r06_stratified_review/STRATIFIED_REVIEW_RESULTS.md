# Stratified manual review -- results

Sample pre-registered in `PRE_REGISTRATION.md` (fixed seed `20260831`) before any source in
this review was read. Conducted read-only against the live R05 corpus scan (never stopped,
restarted, or otherwise touched -- confirmed healthy throughout, 357->362/494 packages
processed during this review). No scanner code was changed as part of this review.

## Bucket 1: positive findings -- ALL reviewed (population = 1)

**`node-libcurl@5.1.2`, `Easy::ReadFunction`, `acquisition_call_id=30064771980`** (a
`Napi::Buffer<uint8_t>::New(env, static_cast<size_t>(size))` call inside a real libcurl
`CURLOPT_READFUNCTION` callback). Already exhaustively investigated earlier this session
(`study/resource_guard_r05/NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md`): confirmed real false
positive under the live R05 scan's own pre-fix build-config extraction (misclassifies
`enabled` as `disabled`) and pre-fix source-boundary logic (treats reaching the `size`
parameter as attacker evidence, with no check that `Easy::ReadFunction` is ever JS-reachable
at all -- it is registered with libcurl via `curl_easy_setopt`, never called by JS).
**Verdict: bucket behaving as expected under R05 (a real, disclosed, already-root-caused
false positive) -- correctly suppressed under the fixed R06 scanner (`actionable_findings:
0`, confirmed by `test_aggregation_boundary.py`).**

## Bucket 2: `SIZE_ATTACKER_INDEPENDENT` -- reviewed (population = 1)

**`node-crc16@2.0.7`**. Already investigated earlier this session: the one real recovered
`Buffer::New` call's size argument is a fixed, real C++ literal (not a JS-influenced value),
correctly rejected before any dominance/attacker-trace logic runs at all. **Verdict:
correct.** Real corpus-wide population is currently only 1 -- a larger sample awaits more of
the corpus finishing (`R05_ACQUISITION_CALL_RECOVERED` has occurred for only 2/357 packages
so far, see Bucket 4 below for why this gate is rarely reached at all).

## Bucket 3: `CONTRACT_NOT_APPLICABLE` -- reviewed (population = 1, from R06 re-run, disclosed)

**`node-libcurl@5.1.2`** (the same real acquisition site as Bucket 1), re-run through the
FIXED R06 scanner against its own cached real facts (not the live R05 corpus scan, which has
zero real instances of this verdict -- see `PRE_REGISTRATION.md` for why). Real per-target
resolution correctly identifies `Easy.cc`'s own compiling target (`<(module_name)`) as
`enabled` (via the real `node_addon_api_except` gyp-target dependency and a real `!`-list
removal of `-fno-exceptions`), giving `CONTRACT_NOT_APPLICABLE` instead of a false
`VALUE_ACQUISITION_GUARD_MISSING`. **Verdict: correct**, and independently cross-checked
against the real, hand-verified account in `NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md` (node.js
addon-api's own real exception-handling macro chain, traced by hand earlier this session).

## Bucket 4: acquisition/overload/type abstentions (`R05_RECOVERY_RESULT_TYPE_UNRECOGNIZED`)

Real corpus-wide rate: 23,642 of 23,644 candidates (99.99%) rejected here. Fixed-seed sample
of 5 packages drew `fontnik@0.7.7`, `libpq@1.11.0`, `@ipshipyard/node-datachannel@0.26.6`,
`node-libcurl@5.1.2` (redrawn, already covered under Bucket 1 -- kept as drawn, not
resampled), `@ssxv/node-printer@1.1.1`. Real tarballs fetched and real source read for each
of the 4 new draws:

| Package | Real `New(`-named calls found | Real `Napi::Buffer::New` present? | Rejection correct? |
|---|---|---|---|
| `fontnik@0.7.7` | `Function::New` x3, `Array::New`/`Object::New` (glyph serialization), `TypeError::New` x~15, ONE real `Napi::Buffer<char>::New(env, &str[0], str.size(), <finalizer lambda>, hint)` | Yes, but the EXTERNAL-DATA overload (5 real args: env, data ptr, length, finalizer, hint) -- NOT the 2-arg allocating overload this contract targets, and its `auto buffer = ...`-declared local's own type is a known, ALREADY-DOCUMENTED R05 scope boundary (`AB_FIXTURE_RESULT.md`'s own "Unresolved qualifier" control: `auto`-declared locals resolve to `ANY`, not a Buffer form) | **Yes** -- correctly rejected, for the same real, already-tested-and-disclosed reason (external-data overload + `auto` local), not a new bug |
| `libpq@1.11.0` | All 11 real candidates are `Nan::New(...)` calls | No -- **`libpq` is a `Nan`-based addon**, not `node-addon-api` (same real pattern independently found in `jpeg-turbo` earlier this session) | **Yes** -- `Nan::New` is a structurally different API this contract was never built for; trivially, correctly out of scope |
| `@ipshipyard/node-datachannel@0.26.6` | 313 real `Napi::<Type>::New(...)` calls counted directly (`TypeError`/`Error`/`Number`/`String`/`Boolean`/`Object`/`Function`/`Array`::New -- zero `Buffer::New`) | **No** -- its real buffer-producing call is `Napi::Buffer<std::byte>::Copy(env, bin.data(), bin.size())`, a DIFFERENT real node-addon-api factory (`::Copy`, not `::New`) | **Yes** -- correctly rejected (none of the 333 real candidates are Buffer allocations at all); see note below |
| `@ssxv/node-printer@1.1.1` | `Object::New`/`Array::New`/`String::New`/`Number::New`/`Error::New`/`TypeError::New` -- zero `Buffer::New`/`Buffer::Copy` anywhere (buffers are received FROM JS as arguments, never allocated internally) | No | **Yes** -- correctly rejected |

**Verdict: this bucket is behaving correctly in all 5/5 real, sampled instances** (4 newly
investigated plus node-libcurl's own already-known case, where the SAME real acquisition
call correctly passes this gate on its way to becoming the one real recovered finding). The
overwhelming 99.99% rejection rate is real and expected, not a sign of a broken gate: most
`New`-named candidates across the real corpus are legitimately non-Buffer factories
(`TypeError`/`Error`/`Object`/`Array`/`String`/`Number`/`Function`::New), and a meaningful
minority of packages are `nan`-based rather than `node-addon-api`-based (now confirmed in
TWO real corpus packages: `jpeg-turbo`, `libpq`) -- both entirely out of this contract's real
scope by design.

**One real, disclosed, NOT-a-bug observation for future scope work**: `node-datachannel`
uses `Napi::Buffer<T>::Copy(env, data, size)` to allocate its own buffers -- a real,
structurally distinct node-addon-api factory this project's `RECOVERY_CONTRACTS` do not
currently cover at all (only `New` is curated). This is not a false negative in what was
reviewed here (the `New`-named candidates are correctly rejected), but it IS a real,
concrete candidate for extending `resource_contracts_r05.py`'s coverage in future work --
recorded here, not acted on, per the "review, not implementation" instruction for this pass.

## Bucket 5: `SOURCE_BOUNDARY_UNRESOLVED` (R06-specific) -- reviewed (population = 1, disclosed limitation)

**`node-libcurl@5.1.2`** (same real site as Buckets 1/3), from the fixed R06 scanner's own
real output: `traced_to_parameter: "size"`, `parameter_type: "size_t"`,
`is_js_callback_origin_type: false`, `attacker_controlled: false`. Manually re-verified
against `Easy::ReadFunction`'s own real signature
(`size_t(char*, size_t, size_t, void*)`, confirmed via `curl_easy_setopt`'s own real,
published contract) -- there genuinely is no `Napi::CallbackInfo` anywhere in this function's
signature, so `SOURCE_BOUNDARY_UNRESOLVED` is the only honest classification. **Verdict:
correct**, but this is a real sample of ONE -- the live R05 corpus scan has no
`source_boundary_evidence` field at all (R06 has not run corpus-wide), so a genuinely
stratified sample of this bucket is not yet possible with real data. Disclosed plainly here
rather than padded with synthetic instances; a real, larger sample is exactly what the
post-freeze R06 corpus-wide rerun will provide.

## Overall conclusion

Every bucket sampled -- the entire real positive-finding population, the entire real
`SIZE_ATTACKER_INDEPENDENT` population, a fixed-seed sample from the dominant abstention
bucket (5/5 packages, all correctly rejected for real, identifiable, mostly-already-disclosed
reasons), and the one real `CONTRACT_NOT_APPLICABLE`/`SOURCE_BOUNDARY_UNRESOLVED` instance
available -- is behaving correctly. No new bug was found in this review. One real, disclosed
scope-extension candidate (`Napi::Buffer::Copy`) was surfaced for future work, not acted on
here.

## Standing claims limitation (restated, unchanged)

Cartesi's own real, currently-published package still abstains (`SOURCE_BOUNDARY_UNRESOLVED`
/ untraced) under the fixed R06 scanner -- the R06/FIX01I integration's `JS_ARGUMENT_
CONTROLLED` promotion mechanism has real fixture evidence (registration recognition, the
structural `info[N]`-via-out-parameter detector, and index-convention-correct linkage
checking, all independently verified) but **no successful real-package development case
yet**. This is not claimed as a real-package promotion anywhere in this review or in the
R06/FIX01I integration's own docs. It remains open until the post-run corpus work finds and
verifies one.
