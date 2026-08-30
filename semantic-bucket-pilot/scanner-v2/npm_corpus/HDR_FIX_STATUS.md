# NPM-CORPUS-HDR-FIX: header-staging correction -- FINAL, FROZEN

Supersedes this file's own earlier in-progress version. Both proof packages are now complete.
The correction is real and frozen; the outcome is a genuine but NARROWER win than the
originally-hoped-for one, and that gap is now precisely characterized, not glossed over.

## Frozen file

- `run_pipeline_one.py` md5: `4597cd64117d29efad4ac58e7f725d2e` (supersedes
  `8b1ea67b7853cb2dfadf64f80d579cc6` recorded in `PIPELINE_FREEZE.md`; that file's own record
  is left unchanged as the historical 50-pilot freeze, this file is the authoritative current
  hash going forward).

## What the fix does (real, working, unchanged from the in-progress record)

Before c2cpg runs, the pipeline now resolves each package's own declared `node-addon-api`/
`nan` dependency range against the real npm registry (minimal hand-written semver matcher,
19/19 real range cases verified, two real caret/tilde lower-bound bugs found and fixed during
this pass), fetches ONLY that dependency's own tarball (no full `npm install`, no scripts, no
transitive tree), and hands it to c2cpg via `--include`. Also fixed: `napi.h` itself `#error`s
out unless an exception-handling macro is predefined, so this package's own already-extracted
`exception_configuration` evidence (item 5's own output) is now passed via `--define`.

## Proof package 1: Cartesi (`@cartesi/machine@1.0.0-alpha.1`, real, currently-published tarball)

See this file's git history (previous version, same commit range) for the full record.
Summary: many `Napi::` types now resolve correctly and namespace-qualified. `Napi::Buffer<T>::
New/Copy` and `Napi::External<T>::New` remain unresolved -- initially characterized as an
"explicit-template-id static member call" limitation.

## Proof package 2: `@appthreat/sqlite3@9.0.1` (real, in the frozen 494-package corpus)

Run through the ACTUAL, updated `run_pipeline_one.run_one()` end-to-end, not a manual
reconstruction. First attempt hit `RESOURCE_LIMIT` (`cpp_normalize` exceeded the standard
180s ceiling -- a real, expected outcome: this package bundles the full SQLite C amalgamation,
~1.58M raw fact rows, comparable to the pilot's own `re2` case). Re-run with
`NPM_CORPUS_TIMEOUT_MULTIPLIER=8` completed cleanly: `ANALYZED`, 569.6s total, header staging
resolved `node-addon-api ^8.9.2 -> 8.9.2` correctly.

**Real result, decoded directly from `calls.tsv`, not inferred from aggregate counts alone:**
many `Napi::` calls now resolve (`Napi.String.New`, `Napi.Object.Get`, `Napi.Function.
IsFunction`, `Napi.HandleScope.HandleScope`, `Napi.Env.IsExceptionPending`, 15+ more distinct
qualified methodFullNames, hundreds of call sites). **But `Napi::Buffer<char>::Copy(...)`
(x3) and, newly informative, `Napi::ArrayBuffer::New(env, length)` -- a call to a
NON-template class's static factory -- both remain `<unresolvedNamespace>`.**

## Root cause, REVISED and now precisely confirmed across two independent real packages

The ArrayBuffer result falsifies the narrower "explicit-template-id on a template CLASS"
characterization from proof package 1 alone -- `ArrayBuffer` is not a template class. Reading
its real declaration in the staged `napi.h` explains why: `ArrayBuffer::New` has **three**
overloads, one of which is itself a template (`template <typename Finalizer> static
ArrayBuffer New(env, externalData, byteLength, finalizeCallback)`) -- even though the actual
call site (`New(env, length)`, 2 args) unambiguously binds to the plain, non-template,
2-argument overload. By contrast, `Napi::String::New(env, "code")` -- which resolves cleanly,
confirmed 18+ real call sites -- has no template overload anywhere in its own overload set.

**Precise, evidence-based characterization:** c2cpg's CDT-based C++ frontend fails to resolve
a static-factory call whenever the callee NAME's overload set contains ANY template overload
-- whether because the enclosing class itself is a template (`Napi::Buffer<T>`, all of whose
methods are therefore template-dependent) or because one specific overload among several is a
function template (`ArrayBuffer::New<Finalizer>`) -- even when the real call in question
would in fact bind to a plain, non-template overload. This is a real, disclosed, structural
limitation of the third-party frontend (not this project's own R01-R04 files, and not fixable
by header staging), confirmed by contrast against calls that DO resolve (plain, non-overloaded
statics; template constructors; member-function templates called on an already-typed
receiver, e.g. `value.As<Napi::Number>()`).

**Node-addon-api's own real API surface makes this maximally damaging for R04 specifically:**
`Napi::Buffer<T>` is a template class (100% of its methods affected, unconditionally) and
`Napi::ArrayBuffer`/`Napi::TypedArrayOf<T>`/`Napi::External<T>` all declare at least one
templated overload alongside their plain ones. The two real proof packages independently
confirm the practical result is the same either way: the acquisition calls R04's own contract
curates never resolve to a qualified methodFullName, headers vendored or not.

## Aggregate R04 result, both proof packages, after the fix

| Package | ACQUISITION_NAME_MATCH_CANDIDATE | ACQUISITION_CALL_FOUND | r04_findings |
|---|---|---|---|
| `@cartesi/machine@1.0.0-alpha.1` | (Buffer/External calls unresolved; not run through r04_scan standalone in this pass -- c2cpg/export evidence alone was sufficient to establish the negative result) | 0 (implied) | 0 |
| `@appthreat/sqlite3@9.0.1` | 774 | 0 | 0 |

## What this means for the corpus-wide plan, stated precisely

- **The header-staging fix is real, correctly built, unit- and integration-tested, and is a
  genuine improvement** -- it measurably increases the fraction of real `Napi::` calls that
  resolve to qualified, usable methodFullNames (confirmed: 15+ distinct types across two real
  packages), which is real, positive value for cross-language-link evidence quality generally,
  independent of R04.
- **It does NOT resolve R04's own zero-hit result.** Both real, independent proof packages
  confirm `ACQUISITION_CALL_FOUND=0` persists after the fix, for a newly and precisely
  identified reason (a c2cpg frontend limitation on template-overloaded static factories,
  not the header-vendoring gap originally hypothesized in `FINDINGS_REVIEW.md`).
- **Rerunning the full 494-package corpus on this fix alone will, with high confidence based
  on 2/2 real proof packages, still show ~zero real R04 findings corpus-wide** -- not because
  the fix doesn't work, but because R04's contracted acquisition calls
  (`Napi::Buffer<T>::New/Copy`, and by the same mechanism likely `Napi::External<T>::New`,
  `Napi::TypedArrayOf<T>::New`) sit exactly in the frontend's blind spot regardless of header
  availability.
- This is now a DIFFERENT decision point than the one the corpus-wide rerun plan was written
  to test. Flagging for direction rather than spending the ~5-hour corpus-wide compute budget
  to reconfirm a result already evidenced twice, unless the rerun's OTHER value (refreshed,
  generally-better-resolved facts across the whole corpus; a corpus-scale, not just 2-package,
  confirmation number) is worth it on its own terms.
