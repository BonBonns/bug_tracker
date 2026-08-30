# R05 blind test: `@gjsify/node-gi@0.44.0` -- a real, honest TRUE NEGATIVE

Per direct instruction, Cartesi and `@appthreat/sqlite3` are disqualified as blind evidence --
both already motivated/were used to investigate the problem this pass fixes. This package was
selected from `npm_pipeline_full_results.jsonl`'s own real `r04_classification` counts
(already computed and committed BEFORE this blind test, from the original, R05-less corpus
run) by ONE structural signal only -- `ACQUISITION_NAME_MATCH_CANDIDATE` count (516, the
2nd-highest in the whole corpus after sqlite3) -- with no prior reading of its source. The
package's own real, already-extracted build-configuration evidence
(`npm_build_configuration.tsv`: `disabled`, `binding.gyp: NAPI_DISABLE_CPP_EXCEPTIONS`) was
also already on file from before this test, not looked up after the fact.

## Real pipeline run

Real tarball download, extract, header-staging (`node-addon-api ^8.0.0` resolved to `8.9.2`,
staged), real c2cpg with `--include`/`--define NAPI_DISABLE_CPP_EXCEPTIONS`, real export,
real `resource_guard_verdict_r05.py --real` scan -- the exact same stages/flags used
throughout this pass, nothing special-cased for this package.

```
classification: {ACQUISITION_NAME_MATCH_CANDIDATE: 516, ACQUISITION_SIGNATURE_UNRECOGNIZED: 516,
                  R05_RECOVERY_CANDIDATE: 516, R05_RECOVERY_RESULT_TYPE_UNRECOGNIZED: 516}
findings: 0
```

**Zero recovered findings.** Reported exactly as obtained -- no re-selection of a different
blind-test candidate attempted after seeing this null result (that would violate the whole
point of a blind test).

## Why, explained honestly by reading the real facts and real source -- not left as a mystery

Of the 516 real `"New"`-named calls, only 3 mention `Buffer` in their own code at all; the
other 513 are real, legitimate, unrelated `Napi::Function::New(env, SomeCFunction)` calls
(GObject-Introspection method/property registration -- this package's actual dominant
pattern, nothing to do with fallible buffer acquisition). Of the 3 real Buffer-adjacent calls:

1. `Napi::ArrayBuffer::New(env, &g_pump_async_pending, sizeof(...))` (`MakePumpPendingCount`)
   -- the real 3-argument external-data overload, correctly out of `RECOVERY_CONTRACTS`'
   curated scope (arity 3, not 2) -- same disclosed boundary as R05_DESIGN.md's own arity gate,
   working as designed.
2. `Napi::TypeError::New(...)` (`VariantExtractBytes`) -- correctly rejected, wrong result
   type, same as the `WrongResultTypeTypeError` negative control.
3. `Napi::Buffer<uint8_t>::New(env, 0)` (`GIArrayToJs`, `src/marshal.cc:1159`) -- a REAL 2-arg
   allocating call. Read directly from the real source:
   ```cpp
   Napi::Value buf = (data == nullptr || length <= 0)
                         ? static_cast<Napi::Value>(Napi::Buffer<uint8_t>::New(env, 0))
                         : ...;
   ```
   The call's result is immediately `static_cast<Napi::Value>(...)` INSIDE a ternary and
   assigned to a local explicitly declared `Napi::Value buf`, not `Napi::Buffer<...> buf` --
   so the local's own resolved type is `Napi.Value`/`Value`, not a `result_type_forms` match.
   This is a REAL, newly-observed scope boundary, not previously encountered in Cartesi or
   the r05_controls fixture: a base-class upcast performed at the acquisition site itself,
   before assignment. Correctly not recovered -- not a bug in R05's gates, a genuine
   uncovered pattern, disclosed here rather than silently absorbed as a false "it just
   doesn't work" impression. (Separately, this specific call's own length argument is the
   literal `0`, so even a recovered finding here would very likely have been filtered by the
   existing `SIZE_ATTACKER_INDEPENDENT` classification R04's own logic already applies --
   noted for completeness, not the reason this one wasn't recovered.)

## What this blind test establishes

- **A true, honest negative on a genuinely untouched real package**, with every one of its
  zero-finding reasons independently read and confirmed from real source -- not asserted, not
  hand-waved, and not treated as license to pick a different, more favorable package.
- **A new, real, disclosed scope boundary** (base-class upcast at the acquisition site,
  before assignment) that Cartesi's own three real sites never exercised -- recorded here,
  and in `R05_DESIGN.md`'s own scope-boundaries section, so it is available for any future
  extension of this recovery mechanism.
- Together with `CARTESI_RECOVERY.md`'s real, independently-verified positive recovery (3
  findings, 2 of them newly discovered beyond R02/R03's own original scope), this pass has
  now demonstrated BOTH a real positive and a real, honestly-explained negative -- exactly
  the pair a blind test is meant to produce, neither one hidden or spun.
