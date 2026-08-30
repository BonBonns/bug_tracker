# RESOURCE-GUARD-R02: a second acquisition mode (STATIC_FACTORY / INSTANCE_FACTORY),
# tested for cross-contract structural portability

R01 (`RESOURCE_GUARD_R01.md`) is a SEPARATE, unchanged algorithm. R02 does not modify
`resource_guard_verdict.py` or `resource_contracts.py` -- not one line, confirmed by md5
before and after every step of this file's own work (`ce641e1acf05ac90af9ea942c934f62e`,
unchanged throughout). R01's own conclusion stands exactly as written: constructor-syntax
acquisition only, structurally generalized within the Hermes `ScopedNativeCallFrame`
contract, cross-contract generalization untested by R01 itself. **The node-addon-api result
documented below is NOT retroactively counted as an R01 success** -- it is R02's own,
separate result.

## Why R02 exists

Mining for a second, independent RESOURCE_GUARD contract (R01's "Mining beyond Hermes")
found that direct-constructor-syntax fallible-resource classes -- R01's exact shape -- are
the MINORITY real-world pattern. Two real, independent codebases both use a STATIC FACTORY
METHOD returning the fallible object instead: Chromium Embedded Framework
(`region.Map()`/`IsValid()`, correctly rejected there as belonging to a different property,
RUNTIME_CAPACITY, not RESOURCE_GUARD -- see R01's Pass 3) and `node-addon-api`
(`Napi::Buffer<T>::New(env, size)`/`IsEmpty()`, this file's real target). R01's schema
conflates "the call that identifies acquisition" with "the resulting object's type" into
one `class_name` field -- sound only for constructor syntax (`Type x(args)`, where the call
name and the object's type are the same string), unsound for `Type::Method(args)` factory
syntax, where they're different strings. Confirmed empirically, not assumed: a real
node-addon-api-shaped probe fixture shows the acquired object's declared type ("Buffer")
and the acquisition call's own name ("New") ARE different strings in the real Joern facts,
and a static factory call's `arguments.tsv` indexing has no implicit receiver slot at index
0 at all (confirmed: `Buffer<unsigned char>::New(env, len)`'s own arguments start at index
1 -- `env`=1, `len`=2 -- there is no index-0 row), unlike a constructor-init call, whose
index 0 IS the implicit receiver/temp address (R01's own RESOURCE-OBJ-ID-R01 finding).

## Schema: acquisition_kind, and the fields it requires

`resource_contracts_r02.py` separates what R01 conflated:

- `acquisition_kind` -- `CONSTRUCTOR` (R01's own shape, supported for completeness, not
  otherwise exercised here), `STATIC_FACTORY` (`Type::Method(...)`, no receiver argument),
  or `INSTANCE_FACTORY` (`obj.Method(...)`, a receiver argument at index 0 that is NOT the
  acquired resource itself).
- `acquisition_call` -- the call node's own name (e.g. `"New"`), NOT the result's type.
- `result_type` -- the type of the value produced; drives ALL identity binding (the
  assignment that receives the acquisition result, alias resolution, the failure
  predicate's own receiver, downstream-use receivers) -- the field R01's `class_name`
  conflated with `acquisition_call`.
- `qualifier_type` -- the class that QUALIFIES the acquisition call's own `methodFullName`.
  Found necessary empirically, not designed in advance: a STATIC_FACTORY call's
  `methodFullName` is qualified by the RESULT's own class (`"Buffer.New:..."` -- the
  static method belongs to the type it constructs), but an INSTANCE_FACTORY call's is
  qualified by the RECEIVER's class instead (`"Factory.Make:..."`, confirmed against this
  file's own `r02c16_instance_factory` control) -- `result_type` and `qualifier_type`
  coincide for STATIC_FACTORY, diverge for INSTANCE_FACTORY, and the algorithm never
  derives one from the other.
- `size_arg_index` -- must already reflect the per-kind indexing difference above (STATIC_
  FACTORY has no index-0 receiver slot; CONSTRUCTOR/INSTANCE_FACTORY do); the algorithm
  applies no offset.
- `failure_predicate` / `failure_polarity` -- same meaning as R01's own fields, renamed
  for clarity alongside the split above.
- `applicable_exception_configuration` -- a DISCLOSED, NEVER-DETECTED assumption (see
  below).
- `proven_unsafe_uses`, `citation` -- documentation, citation-backed, not consulted by the
  matching logic itself.

Verdicts are `VALUE_ACQUISITION_GUARD_MISSING` / `..._ESTABLISHED` / `..._UNRESOLVED` --
per explicit instruction, the property is classified `FALLIBLE_VALUE_ACQUISITION`, never
`FALLIBLE_BOUNDED_RESOURCE`/CWE-787. No R02 finding ever carries a `cwe_hint` (verified by
`gate_resource_guard_r02.py`'s own assertion, over every control's findings) -- a
`failure_predicate` like `IsEmpty()` proves the acquired HANDLE is valid, not that any
buffer it wraps is large enough for a subsequent write (that would be a capacity
COMPARISON between two sizes -- exactly the distinction that got CEF correctly rejected as
a RESOURCE_GUARD candidate in R01). `downstream_write_evidence` is still recorded as a
plain fact (the unguarded use is itself a write), paired with an explicit `evidence_note`
stating this is invalid-handle-use evidence only, never a capacity claim.

## The verified semantics (before writing a single fixture)

Read node-addon-api's real, pinned `main`-branch source and official documentation before
designing anything, per the required sequence:

- `napi.h`: `Value::IsEmpty()` -- "When C++ exceptions are disabled at compile time, a
  method with a Value return type may return an empty value to indicate a pending
  exception... callers should check whether the value is empty before attempting to use
  it." `Buffer<T>::New(napi_env env, size_t length)` is a static factory.
- `doc/error_handling.md`, "Handling Errors With C++ Exceptions": when exceptions are
  ENABLED, "node-addon-api automatically converts and throws the error as a C++ exception
  of type `Napi::Error`" -- the acquisition call THROWS on failure; code after it is never
  reached on failure at all.
- `doc/error_handling.md`, "Handling Errors With Maybe Type and C++ Exceptions Disabled" /
  "Handling Errors Without C++ Exceptions": when exceptions are DISABLED, "any calls to
  node-addon-api functions do not throw C++ exceptions... raises pending JavaScript
  exceptions and returns an empty Napi::Value. The calling code should check
  `env.IsExceptionPending()` [or check the result's own `IsEmpty()`] before attempting to
  use a returned value."

Two real, valid guard forms exist under the exceptions-disabled configuration:
`result.IsEmpty()` (checked on the acquired object itself) or `env.IsExceptionPending()`
(checked on a DIFFERENT object, the ambient `Env`). R02 models only the first -- the one
structurally analogous to R01's own shape (a predicate on the SAME object) -- and states
this as a disclosed scope boundary, not a silent miss: an `env.IsExceptionPending()`-only
guard is invisible to this contract, by design, not by oversight.

**`applicable_exception_configuration` is a disclosed ASSUMPTION, never a per-call-site
DETECTION.** This project's exported CPG facts (`calls.tsv`, `cfg_edges.tsv`, `locals.tsv`,
`identifiers.tsv`, `members.tsv`, `aggregate_kinds.tsv`, `returns.tsv`, `parameters.tsv`,
`method_returns.tsv`, `literals.tsv`, `type_decls.tsv`, `meta.tsv` -- the full field list
`export_c_cpp_facts_v03.sc` emits) carry no representation of preprocessor state and no
try/catch AST structure at all. R02 cannot tell, from source, which configuration a given
translation unit was compiled under -- confirmed, not assumed, by `r02c10_exceptions_
enabled_try_catch` (below): a REAL try/catch visibly wrapping the acquisition still yields
`VALUE_ACQUISITION_GUARD_MISSING`, identical to a fixture with no try/catch at all, because
the exported facts give R02 nothing to distinguish them with. Every finding states the
assumed configuration explicitly (`applicable_exception_configuration_assumed`) rather than
silently presupposing it.

## The 16 controls (`gate_resource_guard_r02.py`, 20/20 including cross-cutting checks;
## all real Joern v4.0.608 facts, all against the NEUTRAL synthetic contracts)

Neutral naming (`FactoryResource::Acquire`/`isInvalid()`, `Factory::Make`) deliberately
decoupled from node-addon-api's real names -- passing these proves the ALGORITHM
generalizes on its own terms, not that it recognizes `Buffer`/`New`/`IsEmpty` specifically.

| # | Control | Expected |
|---|---|---|
| 1 | missing guard | `..._MISSING` |
| 2 | correct guard (terminating) | `..._ESTABLISHED` |
| 3 | inverted predicate | `..._MISSING` |
| 4 | check after first use | `..._MISSING` |
| 5 | check on a different result object | `..._MISSING` (for the unguarded object) |
| 6 | factory called twice, only one checked | 1 `..._ESTABLISHED` + 1 `..._MISSING` |
| 7 | result copied to a one-hop alias | `..._ESTABLISHED` |
| 8 | non-dominating guard | `..._MISSING` |
| 9 | failure branch that does not terminate | `..._MISSING` |
| 10 | exceptions-enabled config (real try/catch) | `..._MISSING` (invisible to CPG facts, by design) |
| 11 | exceptions-disabled config (loop-shaped) | `..._ESTABLISHED` |
| 12 | unrelated uncontracted class, same method names | `..._MISSING` (for the real object) |
| 13 | factory without the curated size argument | `..._SEMANTICS_UNRESOLVED` |
| 14 | attacker-independent size (literal 0) | no finding at all |
| 15 | unnamed/chained temporary result | `..._SEMANTICS_UNRESOLVED` |
| 16 | INSTANCE_FACTORY kind (bonus, not separately itemized in the required list but implied by the schema's 3 kinds) | `..._ESTABLISHED` |

One real design bug found and fixed while building these (same "verify against real facts,
not assumption" discipline as every R01 fix): the synthetic `FactoryResource` contract was
first authored with `size_arg_index=1` (pointing at `ctx`, not `size`) -- 15 of 16 controls
still passed, because `ctx` is ALSO a non-literal parameter, so the (wrong) attacker-
influence trace still resolved to *a* parameter, just the wrong one (evidence said `"ctx"`,
not `"size"`). Only `r02c14_zero_length_valid` (a literal `0` specifically at the REAL size
position) caught it -- confirming, concretely, why a dedicated "the size argument is
provably a compile-time constant" control matters even when every other control's
top-level verdict happens to look right. A second, structural fix (not a mistake --
discovered through the INSTANCE_FACTORY control's own construction, before any freeze):
`qualifier_type` had to be added as a field distinct from `result_type`, since `Factory::
Make`'s own `methodFullName` is qualified by `Factory` (the receiver's class), not
`FactoryResource` (the result's class) -- both fixed BEFORE freezing, per the required
sequence (design, then controls, then freeze -- not freeze, then patch around what's found).

## Freeze

`resource_guard_verdict_r02.py` md5: `016b1b327d22418b326b3b1a3fafd91d`
`resource_contracts_r02.py` md5: `91df28ae16f36bfa1656bfb6529a1eb5`
(as committed in the same commit as this file's initial version -- the git commit hash IS
the durable freeze record; these md5s are the quick-check convenience R01 already
established the convention for).

Everything above this line was written, and the 16 controls verified 20/20, BEFORE any real
npm package was inspected. `resource_contracts_r02.py`'s `REAL_CONTRACTS["Napi::Buffer"]`
entry was authored from node-addon-api's own public source/documentation only (the
citations above) -- no npm package's specific code shaped it. What follows this line is the
blind test: select a real npm package using `Buffer<T>::New()`/`IsEmpty()`, run its real
source through the frozen pipeline above, and record the result without modifying anything
above in response to it.

## Blind test: Automattic/node-canvas, `src/Canvas.cc`, `streamPDF`

Target selected (step D): `Automattic/node-canvas` (a real, widely-used npm native addon),
`src/Canvas.cc`, `streamPDF`, HEAD as of this mining pass -- fetched from
`raw.githubusercontent.com/Automattic/node-canvas/master/src/Canvas.cc`. Real code:

```cpp
static cairo_status_t
streamPDF(void *c, const uint8_t *data, unsigned len) {
  PdfStreamInfo* streaminfo = static_cast<PdfStreamInfo*>(c);
  Napi::Env env = streaminfo->fn.Env();
  Napi::HandleScope scope(env);
  Napi::AsyncContext async(env, "canvas:StreamPDF");
  // TODO this is technically wrong, we're returning a pointer to the data in a
  // vector in a class with automatic storage duration. If the canvas goes out
  // of scope while we're in the handler, a use-after-free could happen.
  Napi::Value buf = Napi::Buffer<uint8_t>::New(env, (uint8_t *)(data), len);
  streaminfo->fn.MakeCallback(env.Global(), { env.Null(), buf, Napi::Number::New(env, len) }, async);
  return CAIRO_STATUS_SUCCESS;
}
```

A minimally-stubbed, statement-faithful fixture
(`study/resource_guard_r02/raw_case_node_canvas_streampdf/fixture_source.cpp`, real TODO
comment preserved) was compiled through the same real Joern v4.0.608 pipeline as every other
fixture in this project (`c2cpg.sh` -> `export_c_cpp_facts_v03.sc`), and run (step E) against
the FROZEN `REAL_CONTRACTS` exactly as committed -- no edits to `resource_guard_verdict_r02.py`
or `resource_contracts_r02.py` before or during this run (md5s unchanged from the Freeze
section above, re-checked immediately before running).

**Recorded result** (`expected_output.json` in that directory):

```json
{"classification": {"ACQUISITION_NAME_MATCH_CANDIDATE": 1, "ACQUISITION_SIGNATURE_UNRECOGNIZED": 1},
 "contract_pool": "real", "findings": [], "schema": "resource-guard-verdict-r02/0.1"}
```

**Correction to the initial write-up of this result.** This site is not an applicable test
of the curated contract, and the zero-findings result must not be read as R02 "failing to
detect" anything at this call site. The curated contract
(`REAL_CONTRACTS["Napi::Buffer"]["result_mfn_prefixes"]`) targets the 2-argument ALLOCATING
overload, `Buffer<T>::New(napi_env, size_t length)`. The real call here is the 3-argument
EXTERNAL-DATA overload, `Buffer<T>::New(napi_env, T* data, size_t length)` -- a different
overload of the same family, wrapping caller-supplied storage instead of allocating new
storage, with different failure semantics that were never curated into this contract. The
correct reading is: **the scanner correctly found the call family (`ACQUISITION_NAME_MATCH_
CANDIDATE`), then correctly abstained because the signature is outside its contract
(`ACQUISITION_SIGNATURE_UNRECOGNIZED`).** This is an out-of-contract blind test, not a missed
detection -- there is no vulnerability claim of any kind to make or fail to make here, because
the contract this scanner enforces was never applicable to this call in the first place.

Inspecting the real exported facts (`calls.tsv`/`locals.tsv`, decoded) shows two further,
independently-confirmed facts about why nothing beyond `_UNRECOGNIZED` could have fired, kept
here as disclosed structural notes, not as reasons the site "should" have been flagged:

1. **The c2cpg frontend itself never resolves the call.** The real `Buffer<uint8_t>::New(...)`
   call's own exported `methodFullName` is `<unresolvedNamespace>.New:<unresolvedSignature>(3)`
   -- not `Buffer.New:Buffer(napi_env__*,unsigned long)`. Joern's C++ frontend could not
   resolve this templated static-factory call at all (a frontend/template-resolution
   limitation, not an R02 logic defect) -- there is no qualified `Buffer.New:` prefix for
   R02 to match against in the first place. The tool still matched the call by NAME first
   (`ACQUISITION_NAME_MATCH_CANDIDATE`), then correctly rejected it once the qualified-prefix
   check failed (`ACQUISITION_SIGNATURE_UNRECOGNIZED`) -- exactly the same code path exercised
   by control 12 (`raw_r02c12_unrelated_class`), doing its job on a real site.
2. **Real base-class-typed LHS.** The real code declares `Napi::Value buf = ...` -- `buf`'s
   exported declared type is `Value` (confirmed in `locals.tsv`: `['...', 'buf', 'Value buf',
   'Value', '64']`), not `Buffer` (the contract's `result_type`). Even on an applicable call
   of the curated overload, RESOURCE-OBJ-ID-R02's `type_matches()` requires an EXACT
   `result_type` match and has no notion of base-class widening/upcast -- a real, disclosed
   scope boundary worth naming, independent of this particular site's inapplicability.

None of this was fixed before the result was recorded, per the required sequence (step F:
do not modify R02 in response to the package result until the result is recorded) -- and
none of it should now be "fixed" retroactively to make this specific site match. Widening
`REAL_CONTRACTS["Napi::Buffer"]` to also cover the 3-argument external-data overload would be
a real, legitimate, SEPARATE contract addition (with its own citation-backed failure
semantics, since an external-data `Buffer` may have different validity/lifetime behavior
than an allocating one) -- not a retune of this result, and not attempted here.

**A separate, distinct issue is visible in the real source and must not be folded into this
contract's property.** `streamPDF`'s own comment states: "we're returning a pointer to the
data in a vector in a class with automatic storage duration. If the canvas goes out of scope
while we're in the handler, a use-after-free could happen." That is a LIFETIME/OWNERSHIP
defect class (the wrapped external buffer may outlive, or be outlived by, its backing
storage) -- categorically different from `FALLIBLE_VALUE_ACQUISITION` (whether the
acquisition call itself succeeded) or `FALLIBLE_BOUNDED_RESOURCE` (capacity). R02 makes no
claim about it, and it must not be counted as evidence for or against R02 in any direction.

**What this establishes, and what it does not -- stated precisely:**

- **Schema-level factory support:** established synthetically (the 16 controls, `STATIC_
  FACTORY` and `INSTANCE_FACTORY` both exercised, 20/20).
- **Cross-contract structural portability:** NOT yet established on applicable real code --
  no real call site matching the curated contract's exact overload and result type has been
  run through R02 yet. The synthetic controls establish the algorithm generalizes on its own
  terms; they do not by themselves establish it against a real, un-curated codebase.
- **Real node-canvas site:** correctly recorded as `ACQUISITION_SIGNATURE_UNRECOGNIZED` --
  an out-of-contract abstention, not a detection attempt that failed, and not evidence that
  `streamPDF` is or is not vulnerable. `IsEmpty()`-shaped predicates prove handle validity
  under an applicable exception configuration; they do not prove buffer capacity, and a
  missing check is not, by itself, evidence of CWE-787 or any other memory-corruption defect
  -- this holds independently of whether this contract even applied here.
- **Cross-project vulnerability generalization:** not established.

## Next blind target: required shape (must be verified BEFORE running the pipeline)

Per the correction above, the next real site selected for a blind test must satisfy ALL of
the following before it is run -- verified from the real source, not assumed, exactly as
`REAL_CONTRACTS["Napi::Buffer"]` itself was verified before freezing:

- `Buffer<T>::New(env, attacker_influenced_length)` -- the two-argument ALLOCATING overload,
  matching `result_mfn_prefixes` as curated (not the three-argument external-data overload
  node-canvas used).
- The length argument is attacker-influenced (not a compile-time-constant/literal size --
  see control 14's `SIZE_ATTACKER_INDEPENDENT` behavior, which correctly produces no finding
  for a provably-safe constant size).
- An exceptions-disabled build configuration is established for the call site (or at least
  plausible/documented for the project), matching this contract's own disclosed
  `applicable_exception_configuration` assumption -- not an exceptions-enabled site, where a
  missing `IsEmpty()` check is not the same defect at all.
- The returned `Buffer`/`Value` is subsequently used (a real downstream operation exists to
  evaluate guard-dominance against).
- `IsEmpty()` (or `env.IsExceptionPending()`, the modeled-vs-unmodeled distinction already
  documented above) is the semantically applicable guard for that configuration.

R02 stays frozen (unchanged md5s, reconfirmed above) while this search continues -- the
current abstention on node-canvas is the correct, expected behavior of the frozen algorithm
on an out-of-contract site, not a defect to patch around.

## Blind test #2: cartesi/rollups-ts (`@cartesi/machine`), `native/addon.cc`, `Machine::ReadMemory`

Target selected and independently verified (not taken on trust from any search report) by
fetching the pinned real source directly: `cartesi/rollups-ts`,
`packages/machine/native/addon.cc`, commit `1d0f419c7fdcb1dbaac31589990a1d946716a1d9`.
Checked against every item in the "Next blind target" list above, from the real source and
`binding.gyp`, BEFORE writing any fixture:

```cpp
Napi::Value Machine::ReadMemory(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    uint64_t address = 0;
    uint64_t length = 0;
    if (!get_u64(env, info[0], "address", &address) || !get_u64(env, info[1], "length", &length)) {
        return env.Undefined();
    }
    if (length > SIZE_MAX) {
        Napi::RangeError::New(env, "length is too large").ThrowAsJavaScriptException();
        return env.Undefined();
    }
    Napi::Buffer<uint8_t> data = Napi::Buffer<uint8_t>::New(env, static_cast<size_t>(length));
    CHECK_CM(env, cm_read_memory(machine_, address, data.Data(), length));
    return data;
}
```

- **Two-argument allocating overload:** yes -- `Napi::Buffer<uint8_t>::New(env, static_cast<size_t>(length))`, no data-pointer argument.
- **Attacker-influenced length:** yes -- `length` comes from `get_u64(env, info[1], "length", &length)`, a JS-caller-supplied value; `get_u64` (read from the same file) only rejects non-safe-integers, and `ReadMemory` itself only rejects `length > SIZE_MAX` -- no application-level bound.
- **Exceptions-disabled configuration plausible:** yes -- `packages/machine/binding.gyp` (fetched and read directly) defines `"defines": ["NAPI_VERSION=8", "NAPI_DISABLE_CPP_EXCEPTIONS", "NODE_ADDON_API_DISABLE_DEPRECATED"]`, with its own comment clarifying this is specifically about node-addon-api's error handling, independent of the separate compiler-level `-fexceptions` re-enablement done for an unrelated file. No `try`/`catch` appears anywhere in `addon.cc` (grepped, zero hits).
- **Downstream use:** yes -- `data.Data()` is passed as the destination pointer to `cm_read_memory(...)`, then `data` itself is returned.
- **Guard applicability:** no `IsEmpty()`/`env.IsExceptionPending()` check appears anywhere near the call -- an unguarded real site, matching this contract's `VALUE_ACQUISITION_GUARD_MISSING` shape if the site is otherwise recognized.

This is a genuinely APPLICABLE site by every criterion above -- unlike node-canvas, this is not an out-of-contract overload. A minimally-stubbed, statement-faithful fixture
(`study/resource_guard_r02/raw_case_cartesi_readmemory/fixture_source.cpp`, `Machine::ReadMemory`'s own statements preserved verbatim) was built modeling node-addon-api's real
`namespace Napi { ... }` structure (including `Env`'s real implicit `operator napi_env() const` conversion), compiled successfully with a real C++17 compiler before being run through
the same real Joern v4.0.608 pipeline, then run (step E) against the FROZEN `REAL_CONTRACTS` exactly as committed -- md5s reconfirmed unchanged immediately before and after this run.

**Recorded result:**

```json
{"classification": {"ACQUISITION_NAME_MATCH_CANDIDATE": 2, "ACQUISITION_SIGNATURE_UNRECOGNIZED": 2},
 "contract_pool": "real", "findings": [], "schema": "resource-guard-verdict-r02/0.1"}
```

Zero findings again -- but for a THIRD, DIFFERENT, precisely-isolated reason than either of node-canvas's two. Decoding the real exported facts shows the `Buffer::New` call's
`methodFullName` DID resolve cleanly this time (`Napi.Buffer.New:Napi.Buffer(napi_env__*,long)` -- 2 parameters, matching the curated `result_mfn_prefixes`), and the acquired object's
own declared type resolved to bare `Buffer` (`locals.tsv`: `['...', 'data', 'Napi::Buffer<unsigned char> data', 'Buffer', '99']` -- c2cpg strips the namespace from a plain
`type_full_name`, unlike a call's `methodFullName`), exactly matching `result_type: "Buffer"`. The SOLE reason this call is rejected is the qualified-prefix check:
`REAL_CONTRACTS["Napi::Buffer"]["qualifier_type"]` is `"Buffer"`, so the algorithm requires `mfn.startswith("Buffer.New:")` -- but the real, correctly-resolved mfn is
`"Napi.Buffer.New:Napi.Buffer(napi_env__*,long)"`, which starts with `"Napi.Buffer.New:"`, not `"Buffer.New:"`. (The second `ACQUISITION_NAME_MATCH_CANDIDATE`/`_UNRECOGNIZED` pair is
`Napi::RangeError::New(...)` -- also named `New`, correctly rejected on the same qualified-prefix check, the same discrimination control 12 exercises.)

**Root cause, stated precisely, and why it was not visible before this run:** the `REAL_CONTRACTS["Napi::Buffer"]` entry was originally authored and verified (per the Freeze section)
against a probe fixture (`npm_mining/probe/probe1.cpp`, scratchpad-only, not committed) that declared `Buffer`/`Env` at GLOBAL scope, with no `namespace Napi { ... }` wrapper -- an
unfaithful simplification of node-addon-api's real structure, which genuinely wraps everything in `namespace Napi`. c2cpg qualifies a call's `methodFullName` with its enclosing
namespace (confirmed directly in this run's own facts: `Napi.Env`, `Napi.RangeError`, `Napi.CallbackInfo`, `Napi.Buffer` are all namespace-prefixed), but does NOT include the namespace
in a variable's plain `type_full_name` (`data`'s type is bare `Buffer`, not `Napi.Buffer`) -- an asymmetry the original probe never exercised, because it never modeled the namespace at
all. This is a real, disclosed CURATION gap in the frozen contract's `qualifier_type` field -- not an R02 algorithm defect (the qualified-prefix check itself is doing exactly what
control 12 requires of it) and not a defect in this candidate site (it satisfies every required property).

**Per the standing instruction, R02 is NOT modified in response to this finding.** `resource_guard_verdict_r02.py` and `resource_contracts_r02.py` remain byte-identical to the Freeze
section's recorded md5s (reconfirmed above). This section records what was found -- including the specific, narrow fix that a namespace-aware `qualifier_type` (e.g. `"Napi.Buffer"`
instead of `"Buffer"`) would need to be curated as, if that widening is deliberately chosen later -- without applying it.

**What THIS blind test establishes, and what it does not:**

- It confirms, on a SECOND independent real site, that R02 abstains (zero findings) rather than fabricating a verdict when a real call falls outside its curated contract's exact
  matching text -- the same non-guessing discipline as blind test #1, now demonstrated for a structurally different reason (namespace-qualification, not overload arity).
- It does NOT establish cross-contract structural portability on applicable real code: this site satisfies every one of the five required properties above, and STILL was not detected,
  because of a contract-curation gap unrelated to any of those five properties. The claim "cross-contract structural portability NOT yet established on applicable real code" (from blind
  test #1's corrected write-up) still stands after this result, for a newly-precise reason.
- It does NOT establish cross-project vulnerability generalization. `Machine::ReadMemory` remains a real, unguarded call satisfying every property this contract cares about, but R02 as
  frozen did not flag it -- reporting a detection here would be false, exactly as with node-canvas.
- It DOES narrow the open question considerably: the blocking issue here is one specific, well-understood field (`qualifier_type`'s missing namespace prefix), not an unresolved mix of
  overload/type-shape mismatches as with node-canvas. Whether to widen `REAL_CONTRACTS["Napi::Buffer"]["qualifier_type"]` to account for the real `Napi::` namespace -- and re-run this
  exact site to see whether it then correctly resolves to `VALUE_ACQUISITION_GUARD_MISSING` -- is a deliberate, separate decision left open here, not taken as part of this blind test.
