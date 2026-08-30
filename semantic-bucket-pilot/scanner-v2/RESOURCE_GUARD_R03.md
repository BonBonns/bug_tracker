# RESOURCE-GUARD-R03: a narrow, disclosed contract-curation correction on top of R02

R03 exists to fix ONE thing: `REAL_CONTRACTS["Napi::Buffer"]["qualifier_type"]` was authored
(during R02) as the unnamespaced string `"Buffer"`, against a probe fixture that never
modeled node-addon-api's real `namespace Napi { ... }` structure. R02's own blind test #2
(RESOURCE_GUARD_R02.md) found a real site -- cartesi/rollups-ts's `@cartesi/machine`,
`Machine::ReadMemory` -- that satisfied every property the contract cares about and STILL
produced zero findings, because the real, correctly-resolved `methodFullName` for
`Napi::Buffer<T>::New(...)` is namespace-qualified (`"Napi.Buffer.New:Napi.Buffer(...)"`),
which the old, unnamespaced qualifier could never match. **This is a genuine contract-
curation error -- not evidence that the property (`FALLIBLE_VALUE_ACQUISITION`) or the
algorithm is wrong.**

## 1. R02 stands, exactly as frozen

Untouched, verified before and after every step of this file's own work:

- `resource_guard_verdict_r02.py` md5: `016b1b327d22418b326b3b1a3fafd91d`
- `resource_contracts_r02.py` md5: `91df28ae16f36bfa1656bfb6529a1eb5`
- `gate_resource_guard_r02.py`: 20/20
- `gate_resource_guard_r02_blindtest.py`: 6/6 -- BOTH recorded blind-test results (node-canvas
  and cartesi) still reproduce exactly, unmodified.
- R01 (`resource_guard_verdict.py` md5 `ce641e1acf05ac90af9ea942c934f62e`): 19/19, also
  untouched by any of this.

Cartesi's original R02 result is **not rewritten as a success**. It remains, permanently, in
RESOURCE_GUARD_R02.md's "Blind test #2" section:

```json
{"classification": {"ACQUISITION_NAME_MATCH_CANDIDATE": 2, "ACQUISITION_SIGNATURE_UNRECOGNIZED": 2},
 "contract_pool": "real", "findings": [], "schema": "resource-guard-verdict-r02/0.1"}
```

The exact qualifier mismatch that produced it: the real call's `methodFullName` resolved to
`"Napi.Buffer.New:Napi.Buffer(napi_env__*,long)"`; R02's contract required a match against
`"Buffer.New:"` (from `qualifier_type: "Buffer"`); a namespace-qualified real mfn can never
start with an unnamespaced required prefix. That is the whole defect, isolated to one field.

## 2. R03's one correction

`resource_contracts_r03.py` changes exactly one value from R02's contract:

```python
REAL_CONTRACTS["Napi::Buffer"]["qualifier_type"]:  "Buffer"  ->  "Napi.Buffer"
```

the exact canonical form observed in real c2cpg output (confirmed directly, repeatedly:
`Napi.Env`, `Napi.RangeError`, `Napi.CallbackInfo`, `Napi.Buffer` are all namespace-prefixed
by c2cpg for every type declared inside `namespace Napi { ... }`). Matched by the SAME exact-
prefix check R02 already used (`mfn.startswith(qualifier_type + "." + acquisition_call +
":")`) -- **no loose suffix/substring matching was added.** A nested/prefixed namespace
(`"Foo.Napi.Buffer.New:..."`) or an unrelated lookalike class with no namespace separator at
all (`"NapiBuffer.New:..."`) is still correctly rejected, because neither is a literal PREFIX
of the required string -- proven empirically below (controls R03B and R03E), not just argued
from the code.

`result_type` was NOT changed (`"Buffer"`, unchanged) -- confirmed correct: c2cpg's
`type_full_name` for an EXPLICITLY-declared local (`Napi::Buffer<uint8_t> data = ...`, the
real cartesi/node-addon-api style) resolves to the bare, unqualified `"Buffer"`, unlike a
CALL's `methodFullName`, which stays namespace-qualified. (An `auto`-deduced local, by
contrast, was found to resolve namespace-qualified -- `"Napi.Buffer"` -- a real, confirmed
asymmetry discovered while building this file's own controls below; every R03 fixture uses
an explicit declared type, matching real usage, never `auto`, so this never becomes a live
issue for any real site.)

Nothing else changed. `resource_guard_verdict_r03.py` is a byte-for-byte copy of
`resource_guard_verdict_r02.py`'s matching/dominance/tracing/verdict-construction logic (see
the file's own module docstring, and the `diff` recorded in this project's commit log --
only docstrings, the import source, the `schema` string, and disclosure-text wording differ).
Explicitly unchanged: acquisition modes, dominance logic, object identity resolution,
attacker tracing, downstream-use reasoning, verdict categories.

## 3. Namespace-discrimination controls (5 required behaviors, real Joern v4.0.608 facts)

All four new fixtures compiled clean with a real C++17 compiler before being run through
Joern; all real facts committed under `study/resource_guard_r03/`.

| Control | Fixture | Real, confirmed methodFullName | Expected | Result |
|---|---|---|---|---|
| R03A | `raw_r03a_napi_buffer_matches` -- correctly-namespaced `Napi::Buffer<uint8_t>::New(env, len)`, unguarded | `Napi.Buffer.New:Napi.Buffer(napi_env__*,long)` | MATCHES -> `VALUE_ACQUISITION_GUARD_MISSING` | PASS |
| R03B | `raw_r03b_other_namespace_rejected` -- same class/method name, arity, under `namespace Other` | `Other.Buffer.New:Other.Buffer(napi_env__*,long)` | does NOT match -> zero findings, `ACQUISITION_SIGNATURE_UNRECOGNIZED` | PASS |
| R03C (synthetic pool) | `raw_r03c_unqualified_synthetic_buffer` -- global-scope, unnamespaced `Buffer::New` | `Buffer.New:Buffer(napi_env__*,long)` | matches ONLY its own, separate `SYNTHETIC_CONTRACTS["Buffer"]` entry -> `VALUE_ACQUISITION_GUARD_MISSING` | PASS |
| R03C (real pool, same fixture) | same facts, `--real` | same | does NOT match `REAL_CONTRACTS`'s namespaced entry -> zero findings, `ACQUISITION_SIGNATURE_UNRECOGNIZED` | PASS |
| R03D | reused, unchanged: `study/resource_guard_r02/raw_case_node_canvas_streampdf` (real node-canvas facts) | `<unresolvedNamespace>.New:<unresolvedSignature>(3)` | ABSTAINS (unresolved by the c2cpg frontend itself) -> zero findings, `ACQUISITION_SIGNATURE_UNRECOGNIZED` | PASS |
| R03E | `raw_r03e_lookalike_class_rejected` -- global-scope class literally named `NapiBuffer` (no namespace separator), same method name/arity | `NapiBuffer.New:NapiBuffer(napi_env__*,long)` | does NOT match (`"NapiBuffer.New:"` is not a prefix of `"Napi.Buffer.New:"` -- the dot matters) -> zero findings, `ACQUISITION_SIGNATURE_UNRECOGNIZED` | PASS |

R03D deliberately reuses node-canvas's own already-committed real facts rather than a new
fixture: it is the same real site, and this correction must NOT change its result (node-
canvas's abstention has an entirely separate, disclosed cause -- the 3-argument external-data
overload and an unresolved frontend methodFullName -- unrelated to the namespace-qualifier
fix). Confirmed unchanged: still zero findings, still `ACQUISITION_SIGNATURE_UNRECOGNIZED`.

## 4. Cartesi: post-fix RECOVERY, not a blind success

`study/resource_guard_r02/raw_case_cartesi_readmemory` (real, already-committed Joern facts,
not re-run through Joern for this) re-run through the corrected `--real` pipeline:

```json
{"verdict": "VALUE_ACQUISITION_GUARD_MISSING", "object": "data", "result_type": "Buffer",
 "acquisition_kind": "STATIC_FACTORY", "method_name": "ReadMemory",
 "unguarded_use_call_id": 30064771129, "downstream_write_evidence": null,
 "applicable_exception_configuration_assumed": "exceptions_disabled -- ...",
 "evidence_note": "invalid-handle-use evidence only -- ... no CWE-787 or capacity claim is "
                   "made here, and this finding alone is not a vulnerability claim -- "
                   "runtime behavior and security impact are separate, unestablished questions"}
```

This is a DEVELOPMENT/REGRESSION case for R03, not a blind test and not a retroactive rewrite
of R02's own result -- Cartesi's own R02 outcome is exactly what motivated this correction, so
it cannot also serve as R03's blind holdout (see the evaluation boundary in section 6).

**Evidence checklist, verified precisely, distinguishing what the tool itself automatically
attaches from what was independently confirmed by reading the real source:**

- **Exact two-argument allocating overload** -- automatically evidenced:
  `ACQUISITION_CALL_FOUND=1` (param-count match against the corrected contract),
  `acquisition_kind: "STATIC_FACTORY"`, `result_type: "Buffer"`.
- **JS-controlled length** -- **NOT automatically evidenced** by this run's own
  `attacker_influence_evidence` field, and this gate asserts that absence explicitly rather
  than silently ignoring it. `length` is populated via `get_u64(env, info[1], "length",
  &length)` -- an OUT-PARAMETER call, not an `lhs = rhs` assignment -- and
  `backward_attacker_trace` (UNCHANGED from R02, per the standing instruction not to touch
  attacker tracing) only follows assignment chains, so it finds no path and the field is
  simply absent from this finding. The underlying fact remains true and was independently
  verified by reading the real source directly (RESOURCE_GUARD_R02.md's Blind test #2:
  `get_u64` reads a JS-caller-supplied argument, bounded only by `SIZE_MAX`) -- it is just not
  a piece of evidence this contract's own automatic trace produces for this real call shape.
  Documented here as a real, disclosed scope boundary of the (unmodified) trace heuristic,
  not something this correction introduced or attempted to fix.
- **Exceptions-disabled configuration** -- automatically evidenced, as a disclosed ASSUMPTION
  (`applicable_exception_configuration_assumed`, unchanged text from R02), never a per-site
  detection -- independently corroborated by `binding.gyp`'s explicit
  `NAPI_DISABLE_CPP_EXCEPTIONS` (RESOURCE_GUARD_R02.md's Blind test #2).
- **Returned object identity** -- automatically evidenced: `object: "data"`.
- **Downstream use before any failure check** -- automatically evidenced:
  `unguarded_use_call_id` present (the real `cm_read_memory(machine_, address, data.Data(),
  length)` call).
- **No dominating `IsEmpty()`/exception-pending guard** -- automatically evidenced by the
  verdict itself: `VALUE_ACQUISITION_GUARD_MISSING`, not `..._ESTABLISHED` (there is no
  `IsEmpty()`/`IsExceptionPending()` call anywhere in the real function at all).

## 5. Claims boundary -- stated exactly, including the one requested wording correction

**Cartesi's `Machine::ReadMemory` is a real, unguarded CANDIDATE under this contract's static
property -- not a confirmed real vulnerability.** The code satisfies every property this
contract's `VALUE_ACQUISITION_GUARD_MISSING` verdict is defined to detect (a fallible
acquisition, matched by contract; no guard on the path to a real downstream use); the
resulting RUNTIME behavior and SECURITY IMPACT -- whether an empty/invalid `Napi::Buffer`
can actually be produced at this call site in practice, and what using it would actually do
-- have not been established by this work. Restated precisely, matching R02's own discipline:

- This is a missing guard under the curated node-addon-api contract.
- It is not automatically a vulnerability.
- It is not automatically CWE-787.
- It is not proof of exploitable memory corruption.
- Cartesi is now an R03 development/regression case, because its own result motivated this
  correction -- it can never also be R03's blind holdout (see section 6).

## 6. Evaluation boundary: only an untouched third package can be R03's blind test

- R02 remains the frozen blind-test miss (unmodified, unrewritten).
- Cartesi is the development case that exposed the bad contract, and is now R03's
  recovery/regression case.
- After correcting the contract, Cartesi cannot become R03's blind holdout -- it was
  inspected, diagnosed, and used to motivate and validate the correction. Its inclusion as a
  "post-fix recovery" finding is real and useful evidence that the correction works, but it
  is not evidence of GENERALIZATION to an untouched site.
- **A third, genuinely untouched real npm package is required for an actual R03 blind test.**
  That candidate must be selected, and the frozen R03 pipeline run against it, BEFORE any
  further change is made to `resource_guard_verdict_r03.py` or `resource_contracts_r03.py` --
  see the "R03 blind test" section below, appended after this file's Freeze section.

## Freeze

`resource_guard_verdict_r03.py` md5: `81ce5856f142d77f9da33472faafc65a`
`resource_contracts_r03.py` md5: `7a73af8853c28ec3edba4fd078d67305`
`gate_resource_guard_r03.py`: 33/33 (16 parity controls reproducing R02's own expectations +
5 namespace-discrimination behaviors + Cartesi post-fix recovery with full evidence-field
assertions + cross-cutting no-cwe-hint/disclosure checks).

Everything above this line -- the correction, the namespace-discrimination controls, and the
Cartesi recovery check -- was written and verified BEFORE any third, untouched real npm
package was inspected. What follows (appended after this line, once found) is that blind
test: select a real npm package independently, using the same applicable allocating overload,
a real `Napi::` namespace, exceptions-disabled behavior, an attacker-influenced size, and a
genuine downstream use (either a correct guard or a missing one), run the frozen R03 pipeline
against it, and record the result without modifying anything above in response to it.
