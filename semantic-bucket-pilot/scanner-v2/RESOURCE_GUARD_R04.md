# RESOURCE-GUARD-R04: enforcing contract applicability (build-configuration evidence)

R03's own blind test against `@julusian/jpeg-turbo` (see `RESOURCE_GUARD_R03.md`'s
"Reclassification" addendum) found a real problem, not a successful generalization: the
scanner correctly recognized the code SHAPE (acquisition, qualifier, object identity,
downstream use, absence of a guard) on a genuinely untouched real site, but never verified
that the shape carried the same MEANING under that site's actual build configuration.
jpeg-turbo most likely builds with C++ exceptions enabled, under which a failed
`Buffer::New()` throws directly rather than returning an empty value -- the contract's whole
premise does not hold there, and R03's `VALUE_ACQUISITION_GUARD_MISSING` finding was a
**configuration-driven false positive**. R04 exists to fix exactly that: require real
evidence of the applicable build configuration BEFORE a MISSING/ESTABLISHED verdict is ever
reported, rather than carrying it as a disclosed-but-unenforced assumption.

## 1. R03 stands, exactly as frozen; the jpeg-turbo result is reclassified, not rewritten

- `resource_guard_verdict_r03.py` md5: `81ce5856f142d77f9da33472faafc65a`
- `resource_contracts_r03.py` md5: `7a73af8853c28ec3edba4fd078d67305`
- `gate_resource_guard_r03.py`: 33/33; `gate_resource_guard_r03_blindtest.py`: 6/6 --
  reproducing the SAME `VALUE_ACQUISITION_GUARD_MISSING` result on jpeg-turbo it always did.
- `study/resource_guard_r03/raw_case_jpegturbo_decompress/expected_output.json` is untouched.
- R02 (both hashes) and R01 (hash) also completely untouched throughout R04's own work,
  reconfirmed before and after every step below.

`RESOURCE_GUARD_R03.md` carries a new "Reclassification" addendum (appended, nothing above it
rewritten) stating the corrected interpretation: **`FALSE_POSITIVE_CONFIGURATION_MISMATCH`**
(equivalently, the limitation this revealed in R03 itself: `CONTRACT_APPLICABILITY_NOT_
ENFORCED`). Claims restated there: cross-project syntactic/graph-shape recognition
established; cross-contract semantic portability NOT established; cross-project vulnerability
generalization NOT established (unchanged, never claimed).

## 2. R04's one addition: an applicability gate, external evidence only

`resource_contracts_r04.py` and `resource_guard_verdict_r04.py` carry R03's contract data and
matching/dominance/tracing/verdict-construction logic forward BYTE-FOR-BYTE (see
`resource_guard_verdict_r04.py`'s own module docstring; only docstrings, the import source,
the `schema` string, and the one new gate block differ -- diff-verified). The ONE new piece
of logic: immediately before a `VALUE_ACQUISITION_GUARD_MISSING`/`..._ESTABLISHED` verdict
would be finalized, R04 checks the run's own `build_config.json` evidence:

| `exception_configuration` | Verdict reported | Meaning |
|---|---|---|
| `"disabled"` | `VALUE_ACQUISITION_GUARD_MISSING` / `..._ESTABLISHED` (R03's own unchanged result) | contract's premise established -- report exactly as R03 always did |
| `"enabled"` | `CONTRACT_NOT_APPLICABLE`, reason `ACQUISITION_FAILURE_THROWS` | acquisition failure throws directly; a missing `IsEmpty()` is not a defect under this contract |
| `"unresolved"` | `BUILD_CONFIGURATION_UNRESOLVED` | no usable evidence either way -- abstention, never defaulted to `"disabled"` |
| `"conflict"` | `BUILD_CONFIGURATION_CONFLICT` | contradictory evidence (e.g. both macros defined) -- abstention |

None of the three new categories is a memory-safety/CWE/vulnerability claim -- each is an
applicability/abstention classification, the same status `ACQUISITION_SIGNATURE_UNRECOGNIZED`
and `VALUE_ACQUISITION_SEMANTICS_UNRESOLVED` already hold in R02/R03. Every
`CONTRACT_NOT_APPLICABLE` finding also carries `"r03_would_be_verdict"` -- R03's own unchanged
algorithm's answer, preserved as diagnostic information, never reported as the final verdict.

**Evidence source, explicitly constrained:** `build_config.json` (via `--build-config PATH`,
default `RAW_DIR/build_config.json`) -- a separate, hand-curated, citation-backed manifest,
schema:
```json
{"exception_configuration": "disabled" | "enabled" | "unresolved" | "conflict",
 "evidence": [{"source": "...", "detail": "...", "citation": "..."}],
 "citation": "human summary of how this was determined"}
```
Built from binding.gyp defines, CMake compile definitions, compiler flags, package build
scripts, node-addon-api configuration macros, or an explicit trusted build manifest -- e.g.
Cartesi's real `NAPI_DISABLE_CPP_EXCEPTIONS` in `binding.gyp`, or jpeg-turbo's real,
verified absence of either macro combined with node-addon-api's own real default-resolution
logic (`napi.h`, independently fetched: absent either macro, exceptions are enabled if the
compiler itself was built with exceptions on). **Never inferred from the absence of a
try/catch in the analyzed source** -- a source-level signal with no bearing on the actual
compiled build configuration (R02's own `r02c10_exceptions_enabled_try_catch` control already
proved the exported CPG facts can't even see try/catch AST structure at all). **Never
silently defaulted to `"disabled"`** (the permissive choice that would let a finding through)
-- a missing file, an unparseable file, a missing/unrecognized `exception_configuration`
value, or evidence about an unrelated flag all resolve to `"unresolved"`.

## 3. The 6 required controls (`gate_resource_guard_r04.py`, 12/12)

Build-configuration resolution is independent of the CPG facts entirely (Joern carries no
preprocessor state), so these controls exercise the new gate by varying ONLY the
`build_config.json` input against already-committed real Joern facts -- no new Joern runs
needed for controls 1/3/4/4b/5/6 (all reuse `study/resource_guard_r03/
raw_r03a_napi_buffer_matches`, real, unguarded, real Joern facts). Control 2 required one new
real fixture (correctly guarded, namespace-qualified) -- `study/resource_guard_r04/
raw_r04c02_disabled_correct_guard/`, compiled with a real C++17 compiler, real Joern v4.0.608
facts.

| # | Control | build_config | Expected | Result |
|---|---|---|---|---|
| 1 | `NAPI_DISABLE_CPP_EXCEPTIONS` established + missing guard | `disabled` | `VALUE_ACQUISITION_GUARD_MISSING` | PASS |
| 2 | `NAPI_DISABLE_CPP_EXCEPTIONS` established + correct guard | `disabled` | `VALUE_ACQUISITION_GUARD_ESTABLISHED` | PASS |
| 3 | exceptions established enabled + missing `IsEmpty()` | `enabled` | `CONTRACT_NOT_APPLICABLE` (`ACQUISITION_FAILURE_THROWS`) | PASS |
| 4 | exception mode unresolved (explicit `"unresolved"`) | `unresolved` | `BUILD_CONFIGURATION_UNRESOLVED` | PASS |
| 4b | no `build_config.json` at all (neither flag nor default path) | *(none)* | `BUILD_CONFIGURATION_UNRESOLVED` | PASS |
| 5 | conflicting build definitions (both macros present) | `conflict` | `BUILD_CONFIGURATION_CONFLICT` | PASS |
| 6 | unrelated exception-sounding flag (no bearing on the two real macros) | *(invalid value)* | `BUILD_CONFIGURATION_UNRESOLVED` -- not mistaken for real evidence | PASS |

Control 5's evidence is a structural scenario (no real package with this exact contradiction
was located during this mining pass) -- labeled as such in its own `build_config.json`
citation, matching this project's convention for synthetic-but-structurally-real controls
(R02/R03's own `SYNTHETIC_CONTRACTS`). Controls 1/3/4/4b/5/6 all reuse the exact SAME
underlying acquisition facts (`raw_r03a_napi_buffer_matches`) -- proving the applicability
gate's outcome is driven purely by the build-configuration input, not by any variation in the
underlying code.

## 4. Named development/regression cases

**jpeg-turbo (the case that motivated R04):** `study/resource_guard_r03/
raw_case_jpegturbo_decompress/` (real, already-committed facts, unmodified) + REAL
build-configuration evidence (`study/resource_guard_r04/build_configs/
bc_jpegturbo_enabled.json`: no `NAPI_CPP_EXCEPTIONS`/`NAPI_DISABLE_CPP_EXCEPTIONS` anywhere in
the real `CMakeLists.txt`, independently re-verified; node-addon-api's own real
default-resolution logic) -> **`CONTRACT_NOT_APPLICABLE`**, `r03_would_be_verdict:
"VALUE_ACQUISITION_GUARD_MISSING"`. R04 correctly REJECTS R03's own finding as not
applicable -- exactly the fix this file exists to make.

**Cartesi (the opposite case):** `study/resource_guard_r02/raw_case_cartesi_readmemory/`
(real, already-committed facts, unmodified) + REAL build-configuration evidence
(`study/resource_guard_r04/build_configs/bc_cartesi_disabled.json`: explicit
`NAPI_DISABLE_CPP_EXCEPTIONS` in the real `binding.gyp`, independently re-verified) ->
**`VALUE_ACQUISITION_GUARD_MISSING`**, matching R03's own recovery result exactly. R04 does
NOT become over-cautious and suppress every finding -- when the applicability evidence is
real and positive, the missing-guard property is evaluated and reported exactly as before.

## 5. Claims boundary (unchanged discipline, restated for R04)

A `CONTRACT_NOT_APPLICABLE` finding is an applicability determination, not a security
verdict of any kind -- it does not claim the code IS safe, only that THIS contract's
premise does not hold there (a different, unmodeled failure mode -- a thrown C++ exception --
may or may not itself be handled correctly elsewhere; R04 makes no claim about that either).
A `VALUE_ACQUISITION_GUARD_MISSING` finding under an established `"disabled"` configuration
(Cartesi's own) remains, exactly as R03 stated it: a real, unguarded CANDIDATE under this
contract's static property -- not a confirmed vulnerability, not automatically CWE-787, not
proof of exploitable memory corruption.

## Freeze

`resource_guard_verdict_r04.py` md5: `b8c0e058b832b428d739b048d0f34c83`
`resource_contracts_r04.py` md5: `68d2448e36556c4442bc10065b504ed3`
`gate_resource_guard_r04.py`: 12/12 (6 required controls + jpeg-turbo rejection + Cartesi
missing-guard evaluation + cross-cutting no-cwe-hint/disclosure checks).

Everything above this line -- the applicability gate, the 6 controls, and the two named
development/regression cases -- was written and verified BEFORE the complete npm JS/TS+C/C++
dataset run begins. Per the next instruction: stop selecting individual packages one at a
time and begin the complete dataset run, with build-configuration evidence included in each
package's own applicability record (not assumed, not defaulted, per the discipline above).
