# RESOURCE-GUARD-R05: structured-evidence recovery for c2cpg's unresolved static factories

R05 exists to fix ONE thing: the corpus-wide header-staging fix (`npm_corpus/HDR_FIX_STATUS.md`)
proved real node-addon-api headers can be correctly staged for c2cpg, but also proved --
across two independent real packages and six real, compiled fixture controls
(`study/resource_guard_r05/AB_FIXTURE_RESULT.md`) -- that c2cpg still leaves
`Napi::Buffer::New`, `Napi::TypeError::New`, `Napi::ArrayBuffer::New`, and every other real
node-addon-api static factory as `<unresolvedNamespace>.<name>:<unresolvedSignature>(N)`,
even with headers correctly staged. **This is a real, disclosed, UNISOLATED c2cpg frontend
limitation** -- four increasingly precise synthetic A/B fixtures failed to reproduce it, and
the precise trigger remains unexplained (see `AB_FIXTURE_RESULT.md`). R05 does not explain or
fix that trigger. It recovers from its OBSERVED, CONFIRMED consequence.

## 1. R01-R04 stand, exactly as frozen

Untouched, verified before and after every step of this file's own work
(`gate_resource_guard_r05.py`'s own hash check, re-run immediately before this doc was
written):

- `resource_guard_verdict.py` (R01): `ce641e1acf05ac90af9ea942c934f62e`
- `resource_guard_verdict_r02.py` / `resource_contracts_r02.py`:
  `016b1b327d22418b326b3b1a3fafd91d` / `91df28ae16f36bfa1656bfb6529a1eb5`
- `resource_guard_verdict_r03.py` / `resource_contracts_r03.py`:
  `81ce5856f142d77f9da33472faafc65a` / `7a73af8853c28ec3edba4fd078d67305`
- `resource_guard_verdict_r04.py` / `resource_contracts_r04.py`:
  `b8c0e058b832b428d739b048d0f34c83` / `68d2448e36556c4442bc10065b504ed3`

## 2. What R05 adds

See `study/resource_guard_r05/R05_DESIGN.md` for the full evidence chain. Summary: a NEW
recovery path, taken only for a call R04's own qualifier check would already abstain on
(`ACQUISITION_SIGNATURE_UNRECOGNIZED`), gated on the SPECIFIC, structurally-recognizable
`<unresolvedNamespace>.../<unresolvedSignature>(...)` shape (never a resolved-but-different
qualifier, which stays on R04's own rejection path). Structural evidence gathered, none of it
code-string matching:

1. Call name (`calls.tsv`) matches a curated `RECOVERY_CONTRACTS` entry.
2. `dispatchType == STATIC_DISPATCH`.
3. The unresolved shape itself.
4. Result-object identity + type: the enclosing assignment's LHS identifier's own
   independently-resolved `typeFullName`, checked against a PLURAL set of real, observed
   forms (`result_type_forms`) -- c2cpg represents the same real type inconsistently (bare
   `"Buffer"` vs qualified `"Napi.Buffer"`, both real, confirmed on two independent packages).
5. Exact real argument arity (from `arguments.tsv` directly, never `_param_count(mfn)`, which
   is meaningless for an unresolved signature -- confirmed by reading the string).
6. Argument-index-1's own resolved type, against a curated `arg0_env_type_forms` set.

Only `Napi::Buffer::New`'s 2-arg allocating overload is curated (`resource_contracts_r05.py`),
matching R02/R03/R04's own `REAL_CONTRACTS` scope exactly. Once all six gates pass, a
single-site contract dict is synthesized and handed UNCHANGED to R04's own existing
object-identity/alias-resolution/failure-predicate/dominance-walk/attacker-trace/
applicability-gate machinery, factored into a shared `evaluate_acquisition()` helper so both
paths provably run the SAME downstream logic. Every recovered finding is stamped
`"evidence_source": "r05_structural_recovery"`, never silently merged with direct R04 findings.

## 3. Six real controls, one file, real `#include <napi.h>` (`gate_resource_guard_r05.py`: PASS)

A synthetic stub does NOT reproduce the unresolved shape (`AB_FIXTURE_RESULT.md`) -- these
controls use the real, staged node-addon-api header, compile-checked against real
node-addon-api + Node core headers, run through real c2cpg with the same `--include`/
`--define` flags the corpus pipeline uses.

| Control | Real call | Result |
|---|---|---|
| Positive | `Napi::Buffer<uint8_t>::New(env, length)`, unguarded, real use | RECOVERED, `VALUE_ACQUISITION_GUARD_MISSING` |
| Wrong result type | `Napi::TypeError::New(env, "bad argument")` | REJECTED -- local type `Napi.TypeError` |
| Lookalike namespace | `Other::Buffer::New(env, length)` | REJECTED -- local type `Other.Buffer` |
| Unrelated class | `Widget::New(env, length)` | REJECTED -- local type `Widget` |
| External-data overload | `Napi::Buffer<uint8_t>::New(env, external, length)` | REJECTED -- arity 3 |
| Unresolved qualifier | `auto data = Napi::Buffer<uint8_t>::New(env, length);` | REJECTED -- local type `ANY` |

## 4. Cartesi: post-fix RECOVERY, a development case, not a blind test

`study/resource_guard_r05/CARTESI_RECOVERY.md`. Cartesi's own real, currently-published
source (`@cartesi/machine@1.0.0-alpha.1`) motivated this correction, so per this project's
own established discipline (RESOURCE_GUARD_R03.md section 6) it cannot also be R05's blind
holdout. Real result: **3 real `VALUE_ACQUISITION_GUARD_MISSING` findings**, all
`r05_structural_recovery` --

- `Machine::ReadMemory` -- the SAME real site (same `acquisition_call_id`) R02/R03 originally
  found, now reached via the local-type recovery path.
- `Machine::ReadVirtualMemory`, `Machine::ReadConsoleOutput` -- genuinely NEW, never
  previously reported (R02/R03/R04 only ever examined `ReadMemory`). Both independently
  verified by direct read of the real source, not taken on the algorithm's word: same shape,
  JS-controlled length via `get_u64`, no `IsEmpty()` guard, real downstream use.

`ReadConsoleOutput` also contains a real, unresolved, correctly UN-recovered
`return Napi::Buffer<uint8_t>::New(env, 0);` (a direct return, no intermediate local) --
confirming R05_DESIGN.md's own disclosed scope boundary in real code, not just in theory.

## 5. Blind test: `@gjsify/node-gi@0.44.0` -- a real, honest true negative

`study/resource_guard_r05/BLIND_TEST.md`. Selected by ONE structural signal (516 real
`ACQUISITION_NAME_MATCH_CANDIDATE`, already computed before this test), no source read
beforehand. Real result: **0 recovered findings**, reported as obtained. Explained
afterward, honestly, by reading real facts and real source: 513/516 are unrelated
`Napi::Function::New` registrations; of the 3 Buffer-adjacent calls, one is the real 3-arg
external-data overload (correctly out of scope), one is `TypeError::New` (correctly wrong
result type), and one reveals a genuinely NEW scope boundary -- a base-class upcast
(`static_cast<Napi::Value>(...)`) performed at the acquisition site itself, before
assignment to a `Napi::Value`-typed local -- recorded in `R05_DESIGN.md`'s own
scope-boundaries section.

## 6. Claims boundary -- same discipline as every prior file in this series

A recovered `VALUE_ACQUISITION_GUARD_MISSING` finding is a real, unguarded CANDIDATE under
this contract's static property -- not a confirmed real vulnerability, not automatically
CWE-787, not proof of exploitable memory corruption. R05 changes HOW the acquisition call is
IDENTIFIED (structural recovery instead of a resolved methodFullName); it does not change
what a missing guard means, what "proven_unsafe_uses" means, or the disclosed
exceptions-disabled applicability assumption, all of which are unchanged from R03/R04.

## 7. What R05 does NOT establish

- The real c2cpg trigger for the unresolved shape remains unisolated (`AB_FIXTURE_RESULT.md`)
  -- R05 recovers from the observed consequence, not a root-caused mechanism.
- Coverage is real but bounded, stated up front, not discovered as a surprise: only
  `Napi::Buffer::New`'s 2-arg allocating overload; only the "assigned to an explicitly-typed
  local" pattern; not a direct return or a base-class upcast at the acquisition site (both
  confirmed real, both currently unrecovered). The SAME mechanism could extend to
  `ArrayBuffer`/`External<T>`/`Copy`/these two new patterns in future work -- not attempted
  in this pass.
- One real positive (3 findings) and one real, honestly-explained negative (0 findings) does
  not establish a base rate for how often real, unguarded `Napi::Buffer::New` sites occur
  across the whole corpus -- that is exactly what the frozen full-494-package rerun (see
  `npm_corpus/PIPELINE_FREEZE.md`'s R05 addendum) is for.

## 8. Frozen files

- `resource_contracts_r05.py`: `c498764b1294f6c6a4af372b1ad56871`
- `resource_guard_verdict_r05.py`: `9d6a7bdaeb88b0bdc368a994048215b6`
- `gate_resource_guard_r05.py`: PASS (6/6 real controls + R01-R04 hash regression)
- `npm_corpus/run_pipeline_one.py`: `1c031795a3383ff63aa1a22e382daeae` (adds header-staging's
  own `--define` fix and an `r05_scan` stage alongside, not instead of, `r04_scan` -- see
  `npm_corpus/PIPELINE_FREEZE.md`'s R05 addendum for the full accounting)
