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

A real, unguarded acquisition -- `buf` is used immediately, with no `IsEmpty()`/
`IsExceptionPending()` check anywhere in the function. A minimally-stubbed, statement-
faithful fixture (`study/resource_guard_r02/raw_case_node_canvas_streampdf/fixture_source.cpp`,
real TODO comment preserved) was compiled through the same real Joern v4.0.608 pipeline as
every other fixture in this project (`c2cpg.sh` -> `export_c_cpp_facts_v03.sc`), and run
(step E) against the FROZEN `REAL_CONTRACTS` exactly as committed -- no edits to
`resource_guard_verdict_r02.py` or `resource_contracts_r02.py` before or during this run
(md5s unchanged from the Freeze section above, re-checked immediately before running).

**Recorded result** (`expected_output.json` in that directory):

```json
{"classification": {"ACQUISITION_NAME_MATCH_CANDIDATE": 1, "ACQUISITION_SIGNATURE_UNRECOGNIZED": 1},
 "contract_pool": "real", "findings": [], "schema": "resource-guard-verdict-r02/0.1"}
```

Zero findings. R02 **correctly abstained** rather than guessing -- this is not a null
result to be explained away, it is the algorithm doing exactly what it is designed to do
when a real site does not match its curated contract. Inspecting the real exported facts
(`calls.tsv`, decoded) shows why, and reveals THREE independent, honestly-disclosed reasons,
not one:

1. **The c2cpg frontend itself never resolves the call.** The real `Buffer<uint8_t>::New(...)`
   call's own exported `methodFullName` is `<unresolvedNamespace>.New:<unresolvedSignature>(3)`
   -- not `Buffer.New:Buffer(napi_env__*,unsigned long)`. Joern's C++ frontend could not
   resolve this templated static-factory call at all (a frontend/template-resolution
   limitation, not an R02 logic defect) -- there is no qualified `Buffer.New:` prefix for
   R02 to match against in the first place. The tool still matched the call by NAME first
   (`ACQUISITION_NAME_MATCH_CANDIDATE`), then correctly rejected it once the qualified-prefix
   check failed (`ACQUISITION_SIGNATURE_UNRECOGNIZED`) -- exactly the same code path exercised
   by control 12 (`raw_r02c12_unrelated_class`), doing its job on a real site.
2. **Real overload arity mismatch, independent of (1).** This call site uses the 3-argument
   external-data overload (`Buffer<T>::New(napi_env, T* data, size_t length)`), not the
   2-argument allocating overload (`Buffer<T>::New(napi_env, size_t length)`) curated in
   `REAL_CONTRACTS["Napi::Buffer"]["result_mfn_prefixes"]` before this test was run. Even if
   (1) had resolved cleanly, the param-count check would still reject this call as
   `VALUE_ACQUISITION_SEMANTICS_UNRESOLVED` (`ACQUISITION_SIGNATURE_PARAM_COUNT_UNRECOGNIZED`)
   -- the exact behavior control 13 (`raw_r02c13_no_size_argument`) exercises.
3. **Real base-class-typed LHS, independent of (1) and (2).** The real code declares
   `Napi::Value buf = ...` -- `buf`'s exported declared type is `Value` (confirmed in
   `locals.tsv`: `['...', 'buf', 'Value buf', 'Value', '64']`), not `Buffer` (the contract's
   `result_type`). Even with (1) and (2) both resolved, RESOURCE-OBJ-ID-R02's `type_matches()`
   requires an EXACT `result_type` match and has no notion of base-class widening/upcast --
   this would independently block object-identity binding to the failure predicate and the
   downstream use.

Each of these was identified as a real possibility BEFORE running the pipeline (see the
prior "select a package" reasoning); all three are now confirmed against the real exported
facts, not assumed. None was fixed before this result was recorded, per the required
sequence (step F: do not modify R02 in response to the package result until the result is
recorded) -- this section documents that unmodified result.

**What this establishes, and what it does not:**

- It does NOT establish cross-project vulnerability generalization. node-canvas's `streamPDF`
  remains a genuine, real, still-unguarded acquisition site (worth reporting to that project
  independently of this exercise), but R02 as frozen did not detect it -- reporting a
  detection here would be false.
- It DOES establish that R02, faced with a real site outside its curated contract's exact
  scope, abstains cleanly (zero findings, explicit `_UNRECOGNIZED` classification) rather
  than fabricating a verdict -- the same non-guessing discipline R01's own controls enforce
  (e.g. R01's `ACQUISITION_SIGNATURE_UNRECOGNIZED` behavior), now confirmed to hold on a
  real, un-curated, real-world call site, not just on synthetic negative controls.
- Reason (1) (frontend template-resolution) is a boundary of the underlying Joern export,
  not of R02's own reasoning -- worth naming explicitly so it isn't mistaken for an R02 gap.
- Reasons (2) and (3) are real, disclosed SCOPE limitations of `REAL_CONTRACTS["Napi::Buffer"]`
  as curated: it covers exactly one overload and exactly one declared-type shape, both
  narrower than real node-addon-api usage in the wild. Widening the contract to cover the
  3-argument overload and/or base-class-typed results is a legitimate follow-up, but it is a
  SEPARATE, explicitly-labeled step from this blind test, not a silent retune of this
  result -- and per (1), it would likely not even help this specific call site, since the
  frontend never resolves its methodFullName regardless of which overload signature is
  curated.

This blind test's honest outcome is therefore: **cross-contract structural portability
established** (the 16 controls), **safe/unsafe real-pattern recognition NOT established on
this real site** (frontend resolution + contract scope both fell short, independently and
for named reasons), and **no cross-project vulnerability generalization claim is made**.
