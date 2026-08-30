#!/usr/bin/env python3
"""RESOURCE-CONTRACT-R02: extends R01's curated-contract mechanism to acquisitions that are
NOT direct C++ constructor-call syntax. R01's `resource_contracts.py`/`resource_guard_
verdict.py` are UNCHANGED by this file -- R02 is a separate, additive algorithm
(`resource_guard_verdict_r02.py`) with its own contract schema, not a modification of R01.

Why R02 exists: mining for a second, independent RESOURCE_GUARD contract (see
RESOURCE_GUARD_R01.md's "Mining beyond Hermes") found that direct-constructor-syntax
fallible-resource classes (R01's exact shape) are the MINORITY real-world pattern. The
dominant real pattern -- confirmed independently in both Chromium Embedded Framework
(`region.Map()` / `IsValid()`, rejected as a different property, see R01's Pass 3) and
node-addon-api (`Napi::Buffer<T>::New(env, size)` / `IsEmpty()`, this file's real contract)
-- is a STATIC FACTORY METHOD returning the fallible object, not a constructor. R01's schema
conflates "the call that identifies acquisition" with "the resulting object's type" into one
`class_name` field, which works ONLY when both are the same string (true for constructor
syntax, false for `Type::Method(...)` factory syntax, where the call's own name is the
method name, not the type name). Confirmed empirically (not assumed): a real
`node-addon-api`-shaped probe fixture shows the constructed value's declared type ("Buffer")
and the acquisition call's own name ("New") are DIFFERENT strings, and arguments.tsv indexes
a static factory call's arguments starting at 1 (no implicit receiver/`this` slot at index
0, unlike a constructor-init call) -- both real, load-bearing differences from R01's shape.

Schema fields (every entry requires ALL of these; `resource_guard_verdict_r02.py` never
infers identity from code text -- it binds the acquisition's ASSIGNMENT RESULT, by real
CPG facts, to the object used by the failure predicate and by downstream operations):

  acquisition_kind  -- one of "CONSTRUCTOR" (R01's own shape, reproduced here as a
                        supported kind for completeness -- not otherwise exercised by R02's
                        own controls, which target the two kinds below), "STATIC_FACTORY"
                        (a call like `Type::Method(...)`, no receiver argument -- the call
                        node's own `name` is the METHOD name, matched together with the
                        result type via the call's `methodFullName` prefix), or
                        "INSTANCE_FACTORY" (a call like `obj.Method(...)` on an existing,
                        already-acquired receiver object -- has a receiver argument at
                        index 0, unlike STATIC_FACTORY).
  acquisition_call  -- the call node's own `name` (calls.tsv) that performs acquisition --
                        e.g. "New", NOT the class name, for a STATIC_FACTORY/INSTANCE_FACTORY
                        contract.
  result_type       -- the type_full_name of the value the acquisition produces, used for
                        ALL identity binding: the assignment LHS that receives the
                        acquisition result, alias resolution, the failure predicate's own
                        receiver, and downstream-use receivers. Deliberately SEPARATE from
                        `acquisition_call` -- this is the field R01's single `class_name`
                        conflated, and the fix for that conflation.
  result_mfn_prefixes -- tuple of exact, citation-backed methodFullName strings for each
                        curated overload (mirrors R01's own field of the same intent) --
                        matched by PARAMETER COUNT (see R01's own RESOURCE-CTOR-TYPEINFER-R01
                        note on why exact type text is unsound: a literal argument's own
                        c2cpg-inferred type can silently differ from the true declared
                        parameter type).
  size_arg_index    -- argument index (arguments.tsv's own indexing) of the size/count
                        parameter, IF the acquisition call has one. CONSTRUCTOR-kind and
                        INSTANCE_FACTORY-kind calls reserve index 0 for an implicit
                        receiver/`this`; STATIC_FACTORY calls do not (confirmed empirically,
                        see module docstring above) -- this field's value must already
                        reflect that per-kind difference; the algorithm does not add or
                        subtract an offset for you.
  failure_predicate -- method name (calls.tsv `name`) called on the RESULT object
                        (`result_type`-typed) that reports acquisition failure.
  failure_polarity  -- "true_means_invalid" or "true_means_valid" (mirrors R01's
                        `predicate_true_means_invalid`, renamed for clarity alongside the
                        new fields).
  applicable_exception_configuration -- a DISCLOSED, NEVER-DETECTED assumption: which C++
                        exception build configuration this contract's failure signature
                        (an empty/invalid RESULT OBJECT, checked via `failure_predicate`)
                        actually applies under. Real node-addon-api semantics (see
                        RESOURCE_GUARD_R02.md's citations): under an exceptions-ENABLED
                        build, the SAME acquisition call instead throws a C++ exception on
                        failure, and a missing `failure_predicate` check is not the same
                        defect (control flow never reaches the use on failure at all). The
                        exported CPG facts this project consumes (calls/cfg_edges/locals/...)
                        carry NO representation of preprocessor state or of try/catch AST
                        structure at all -- R02 CANNOT determine, per call site, which
                        configuration was compiled, and does not pretend to: every R02
                        finding discloses this field's value as a stated assumption, not a
                        verified fact.
  proven_unsafe_uses -- citation-backed list of what's actually unsafe about touching an
                        invalid result object (e.g. `.Data()`/indexing into an empty
                        Buffer) -- documentation only, not consulted by the matching logic.
  citation          -- the real source/documentation backing every field above.

Verdict-class distinction from R01 (per explicit instruction, not a detection-logic change):
`IsEmpty()` proves HANDLE validity, not buffer CAPACITY -- R02 findings are classified
`FALLIBLE_VALUE_ACQUISITION`, never `FALLIBLE_BOUNDED_RESOURCE`/CWE-787, and never carry a
`cwe_hint` unless a SEPARATE piece of downstream capacity evidence is established (which
this contract's own semantics do not provide -- see the module docstring for
`resource_guard_verdict_r02.py`).
"""

# Neutral-named synthetic contract used ONLY by gate_resource_guard_r02.py's 16 required
# controls -- deliberately decoupled from node-addon-api's real naming, so passing these
# controls demonstrates the ALGORITHM generalizes on its own terms, not that it was tuned
# to recognize "Buffer"/"New"/"IsEmpty" specifically. Not citation-backed against any real
# library (it is fictional, built to exercise STATIC_FACTORY structurally) -- never used
# for the real blind test.
SYNTHETIC_CONTRACTS = {
    "FactoryResource": {
        "acquisition_kind": "STATIC_FACTORY",
        "acquisition_call": "Acquire",
        "result_type": "FactoryResource",
        # STATIC_FACTORY: qualifier_type == result_type (the static method belongs to the
        # class it constructs) -- see the INSTANCE_FACTORY entry below for the contrast.
        "qualifier_type": "FactoryResource",
        "result_mfn_prefixes": (
            "FactoryResource.Acquire:FactoryResource(Context*,unsigned long)",
        ),
        # STATIC_FACTORY indexing (no implicit receiver at index 0 -- see module
        # docstring): Acquire(ctx, size) -> ctx=index 1, size=index 2. Verified against
        # this project's own r02c14_zero_length_valid fixture facts (arguments.tsv: idx 1
        # kind IDENTIFIER code ctx, idx 2 kind LITERAL code 0) after an earlier authoring
        # mistake (size_arg_index=1, i.e. `ctx`) let 15/16 controls pass BY ACCIDENT --
        # ctx is also a non-literal parameter, so the wrong-argument size check still
        # traced to *a* parameter, just the wrong one (evidence said "ctx", not "size").
        # Caught only by r02c14 actually exercising a literal at the real size position.
        "size_arg_index": 2,
        "failure_predicate": "isInvalid",
        "failure_polarity": "true_means_invalid",
        "applicable_exception_configuration": "n/a -- synthetic control fixture, not a real "
                                               "library; exists to exercise the STATIC_FACTORY "
                                               "matching/identity/dominance machinery only.",
        "proven_unsafe_uses": ["n/a -- synthetic control fixture"],
        "citation": "Fictional, structural-test-only contract -- see gate_resource_guard_r02.py.",
    },
    "Factory.Make": {
        "acquisition_kind": "INSTANCE_FACTORY",
        "acquisition_call": "Make",
        "result_type": "FactoryResource",
        # RESOURCE-ACQ-KIND-R02 (qualifier differs by kind): a STATIC_FACTORY call's own
        # methodFullName is qualified by the RESULT's class (`Buffer.New:...` -- the static
        # method belongs to the type it constructs). An INSTANCE_FACTORY call's
        # methodFullName is qualified by the RECEIVER's class instead (`Factory.Make:...`,
        # confirmed empirically against this project's own r02c16_instance_factory fixture
        # facts -- `f->Make(ctx, size)`'s mfn is "Factory.Make:FactoryResource(...)", not
        # "FactoryResource.Make:..."). `qualifier_type` is that qualifying class, checked in
        # its own right; `result_type` still drives ALL object-identity/alias/predicate/use
        # binding, unchanged.
        "qualifier_type": "Factory",
        "result_mfn_prefixes": (
            "Factory.Make:FactoryResource(Context*,long)",
        ),
        "size_arg_index": 2,
        "failure_predicate": "isInvalid",
        "failure_polarity": "true_means_invalid",
        "applicable_exception_configuration": "n/a -- synthetic control fixture, not a real "
                                               "library; exists to exercise the "
                                               "INSTANCE_FACTORY matching machinery only.",
        "proven_unsafe_uses": ["n/a -- synthetic control fixture"],
        "citation": "Fictional, structural-test-only contract -- see gate_resource_guard_r02.py.",
    },
}

# Real, citation-backed contract, added ONLY after R02's algorithm and all 16 synthetic
# controls were frozen (see RESOURCE_GUARD_R02.md's "Freeze" section for the recorded hash)
# -- used ONLY for the blind test against a real npm package, never for tuning.
REAL_CONTRACTS = {
    "Napi::Buffer": {
        "acquisition_kind": "STATIC_FACTORY",
        "acquisition_call": "New",
        "result_type": "Buffer",
        "qualifier_type": "Buffer",
        "result_mfn_prefixes": (
            "Buffer.New:Buffer(napi_env__*,unsigned long)",
        ),
        "size_arg_index": 2,
        "failure_predicate": "IsEmpty",
        "failure_polarity": "true_means_invalid",
        "applicable_exception_configuration": (
            "exceptions_disabled -- per node-addon-api's own official documentation "
            "(doc/error_handling.md, 'Handling Errors With Maybe Type and C++ Exceptions "
            "Disabled' / 'Handling Errors Without C++ Exceptions'): when C++ exceptions are "
            "DISABLED at compile time, a node-addon-api call that would otherwise throw "
            "instead raises a pending JavaScript exception and returns an EMPTY Napi::Value "
            "(napi.h ~line 515: 'a method with a Value return type may return an empty value "
            "to indicate a pending exception... callers should check whether the value is "
            "empty before attempting to use it'). Under an exceptions-ENABLED build, the SAME "
            "failure instead throws a C++ exception of type Napi::Error directly (doc/"
            "error_handling.md, 'Handling Errors With C++ Exceptions') -- code after the "
            "acquisition call is simply never reached on failure, and a missing IsEmpty() "
            "check is not the same defect. R02 cannot determine which configuration a given "
            "call site was compiled under (no preprocessor state, no try/catch AST, is "
            "exported by this project's Joern facts) -- every finding against this contract "
            "discloses this assumption explicitly rather than silently assuming it."
        ),
        "proven_unsafe_uses": [
            "napi.h's own Buffer<T>::Data()/operator[] documentation and the class's real "
            "implementation dereference the underlying napi_value's data pointer without an "
            "internal empty-check; calling Data() (or any Uint8Array/TypedArray/Value method "
            "requiring a valid underlying napi_value) on an empty Buffer is undefined "
            "behavior at the Node-API layer, not merely 'returns a default value'.",
        ],
        "citation": (
            "nodejs/node-addon-api (pinned to the `main` branch source read for this mining "
            "pass): include-equivalent napi.h (Value::IsEmpty(), Buffer<T>::New(napi_env, "
            "size_t)) and doc/buffer.md, doc/error_handling.md (official documentation of "
            "both exception configurations)."
        ),
    },
}
