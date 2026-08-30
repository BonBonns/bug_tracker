# NPM-CORPUS-HDR-FIX: header-staging correction -- status (IN PROGRESS, not yet frozen)

This file exists because the stop-hook required a commit mid-investigation. It records real,
verified status as of this commit -- it is NOT a freeze declaration. Per the standing
instruction ("Fix header staging and prove it on Cartesi plus another real node-addon-api
package. Freeze that pipeline-only correction."), the freeze happens only after BOTH proof
packages are evaluated and the result is written up precisely. Only proof package 1 (Cartesi)
is complete as of this commit; proof package 2 (`@appthreat/sqlite3@9.0.1`) is running.

## What changed in `run_pipeline_one.py` (uncommitted->committed here, NOT yet re-hashed/frozen)

Added `stage_native_dep_headers()` + `resolve_npm_dep_version()` + a minimal, hand-written,
unit-tested npm semver-range matcher (`_range_satisfied`, 19/19 real range cases pass,
including two real bugs in the caret/tilde lower-bound found and fixed during this same pass
-- see git history). Before c2cpg runs, the pipeline now: reads the package's own
`package.json`, resolves its declared `node-addon-api`/`nan` dependency range against the
real npm registry, fetches and extracts ONLY that dependency's own tarball (no full `npm
install`, no scripts, no transitive tree), and passes the extracted directory to c2cpg via
`--include`. Disclosed scope is documented in the function's own module-level comment in the
file (not a full npm resolver; not raw N-API `<node_api.h>` support).

## Proof package 1 (Cartesi): COMPLETE -- real, mixed result, not a clean win

Used the REAL, currently-published `@cartesi/machine@1.0.0-alpha.1` npm tarball (not the old
R02/R03 hand-stubbed single-file fixture) -- confirmed real: `native/addon.cc` contains the
actual `Machine::ReadMemory` function, `#include <napi.h>`, `node-addon-api: "^8.3.0"` in its
own `package.json`, `NAPI_DISABLE_CPP_EXCEPTIONS` in its own `binding.gyp` -- matching the R02
fixture almost exactly, now on real, live source.

**A second real bug found and fixed during this proof, before the result below was reached:**
`napi.h` itself `#error`s out (`Exception support not detected`) unless
`NAPI_CPP_EXCEPTIONS`/`NAPI_DISABLE_CPP_EXCEPTIONS` is predefined -- confirmed directly via
`SL_LOGGING_LEVEL=INFO c2cpg.sh --log-preprocessor`. Fixed by passing `--define` for this
package's own already-extracted `exception_configuration` evidence (from
`npm_build_configuration.tsv`, item 5's own output) to c2cpg.

**Real, positive result:** with headers staged and the exception macro defined, many
previously-`<unresolvedNamespace>` `Napi::` types now resolve to real, namespace-qualified
`methodFullName`s in real exported facts: `Napi.Value`, `Napi.Number`, `Napi.CallbackInfo`,
`Napi.Env`, `Napi.String`, `Napi.ObjectWrap`, `Napi.TypedArray`, `Napi.Function`, `Napi.Error`,
`Napi.Object`, `Napi.Uint8Array`, `Napi.FunctionReference` all confirmed resolved (verified by
directly decoding real `calls.tsv`/`methods.tsv`/`type_decls.tsv` base64 fields, not assumed).

**Real, negative result -- the specific thing R04 needs, still does NOT resolve:** every real
`Napi::Buffer<uint8_t>::New(...)`, `Napi::Buffer<uint8_t>::Copy(...)`, and
`Napi::External<cm_machine>::New(...)` call in the real file remains
`<unresolvedNamespace>.New:<unresolvedSignature>` / `.Copy:<unresolvedSignature>` -- 100% of
these specific calls, confirmed by direct decode, even with headers correctly staged and the
exception macro defined. Root-caused, not just observed: `type_decls.tsv` DOES contain
`Napi.Buffer` (`isExternal=true`) -- the class itself is discovered -- but c2cpg's CDT-based
C++ frontend does not resolve calls made via **explicit-template-id static member syntax**
(`ClassName<TemplateArgs>::StaticMethod(...)`), which is exactly the idiom every real
`Napi::Buffer<T>::New()`/`::Copy()` call uses. This is NOT a blanket "templates don't
resolve" limitation -- confirmed by contrast: template *constructor* calls
(`Napi::ObjectWrap<Machine>(info)`) and member-function templates
(`value.As<Napi::Number>()`) DO resolve correctly in the same real file, same run. The failure
is specific to the static-factory-via-explicit-template-id call shape.

**What this means, stated precisely:** the header-staging fix is real and does improve
resolution quality broadly (more real Napi:: types resolve, better cross-language-link
evidence generally) -- but it does NOT, by itself, resolve the specific call shape R04's own
contract requires. Rerunning the full 494-package corpus on this fix alone would very likely
still show close to zero real R04 findings, for a DIFFERENT, now precisely identified reason
(a c2cpg frontend limitation on explicit-template-id static calls) rather than the originally
hypothesized one (missing headers alone). This corroborates, rather than contradicts, R03's
own node-canvas observation (`<unresolvedNamespace>.New:<unresolvedSignature>(3)`, attributed
there to an unrelated overload-arity issue) -- it may in fact be the same underlying frontend
limitation, not a separate cause; this was not re-investigated for node-canvas specifically in
this pass and is flagged here, not asserted.

## Proof package 2 (`@appthreat/sqlite3@9.0.1`): IN PROGRESS

Running through the actual, updated `run_pipeline_one.run_one()` end-to-end (real pipeline
call, not a manual step-by-step reconstruction) as of this commit. Result pending -- will be
written up in `PIPELINE_FREEZE.md` (or a corrected `FINDINGS_REVIEW.md` section) once
complete, alongside a final, precise verdict on whether/how to proceed with a corpus-wide
rerun given the Cartesi result above.

## What is explicitly NOT yet true, as of this commit

- This correction is NOT yet frozen (no new md5 recorded for `run_pipeline_one.py`).
- No corpus-wide rerun has been started or should be started on the premise that this fix
  alone resolves R04's zero-hit result -- that premise is now known to be false for the
  dominant real call pattern, pending proof package 2's confirmation.
- `PIPELINE_FREEZE.md` and `FINDINGS_REVIEW.md` have NOT been updated yet -- this file is the
  interim, honest record until that write-up is complete.
