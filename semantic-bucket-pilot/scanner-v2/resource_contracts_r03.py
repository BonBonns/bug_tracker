#!/usr/bin/env python3
"""RESOURCE-CONTRACT-R03: a NARROW, disclosed CONTRACT-CURATION CORRECTION on top of R02.

R02 (`resource_contracts_r02.py`/`resource_guard_verdict_r02.py`) is UNCHANGED by this file
-- not imported, not modified, still byte-identical to its own recorded Freeze-section
hashes. R02's own blind-test result against cartesi/rollups-ts's `@cartesi/machine`
(`Machine::ReadMemory`, see RESOURCE_GUARD_R02.md's "Blind test #2") is NOT rewritten as a
success here -- it stands, permanently, as R02's own recorded, frozen, zero-finding
abstention. R03 is a SEPARATE algorithm surface with its own contract file and its own
verdict script (`resource_guard_verdict_r03.py`), so R02's artifacts never change.

Why R03 exists: RESOURCE_GUARD_R02.md's Blind test #2 diagnosed the EXACT, ISOLATED cause of
that abstention -- not an algorithm defect, not a property-definition defect, but a
CONTRACT-CURATION error. `REAL_CONTRACTS["Napi::Buffer"]["qualifier_type"]` was authored as
`"Buffer"` against a probe fixture (`npm_mining/probe/probe1.cpp`, scratchpad-only, never
committed) that declared `Buffer`/`Env` at GLOBAL scope, never modeling node-addon-api's real
`namespace Napi { ... }` wrapper. Real node-addon-api genuinely wraps every one of these
types in `namespace Napi`, and c2cpg qualifies a CALL's own `methodFullName` with its
enclosing namespace (confirmed directly, repeatedly, in real Joern facts: `Napi.Env`,
`Napi.RangeError`, `Napi.CallbackInfo`, `Napi.Buffer` are all namespace-prefixed) -- so the
real, correctly-resolved `Napi::Buffer<T>::New(...)` call's `methodFullName` is
`"Napi.Buffer.New:Napi.Buffer(...)"`, which the old, unnamespaced `qualifier_type: "Buffer"`
can never match. The fix is EXACTLY that one field's exact canonical form, verified against
real Joern output (see the namespace-discrimination controls in `gate_resource_guard_r03.py`)
-- not a loose suffix/substring match (a `Foo.Napi.Buffer.New:...`-style nested/prefixed
namespace, or a lookalike class like `NapiBuffer` with no namespace separator at all, must
still be REJECTED; see controls B and E), and not a change to `result_type`, which was
already confirmed correct: c2cpg's `type_full_name` for an EXPLICITLY-typed local (e.g.
`Napi::Buffer<uint8_t> data = ...`, the real cartesi and node-addon-api declaration style)
resolves to the bare, unqualified `"Buffer"` -- unlike a call's `methodFullName`, which stays
namespace-qualified. (An `auto`-deduced local, by contrast, resolves NAMESPACE-QUALIFIED --
`"Napi.Buffer"` -- a real, confirmed, load-bearing asymmetry discovered while building this
file's own controls; every R03 fixture uses an explicit declared type, matching real
node-addon-api/cartesi usage, never `auto`, so `result_type` stays correctly the bare
`"Buffer"` throughout.)

What changed vs. `resource_contracts_r02.py`, and what did not:

  CHANGED:   REAL_CONTRACTS["Napi::Buffer"]["qualifier_type"]: "Buffer" -> "Napi.Buffer"
             (and result_mfn_prefixes' documentation string updated to the real, observed
             namespace-qualified form for consistency -- still consulted only for its
             PARAMETER COUNT, per R01/R02's own RESOURCE-CTOR-TYPEINFER-R01 rationale, never
             for exact text).
  ADDED:     SYNTHETIC_CONTRACTS["Buffer"] -- a NEW, separate, deliberately UNNAMESPACED
             synthetic entry (qualifier_type "Buffer", decoupled from the real contract),
             added ONLY so control R03C ("an unqualified synthetic Buffer::New still matches
             its own, explicitly separate synthetic contract, never the real one") has a
             contract to match against in the SYNTHETIC pool. Never used outside
             gate_resource_guard_r03.py's own controls.
  UNCHANGED: every other field of REAL_CONTRACTS["Napi::Buffer"] (acquisition_kind,
             acquisition_call, result_type, size_arg_index, failure_predicate,
             failure_polarity, applicable_exception_configuration, proven_unsafe_uses,
             citation), and both of R02's original SYNTHETIC_CONTRACTS entries
             (`FactoryResource`, `Factory.Make`) -- carried over byte-for-byte so R02's own
             16 original controls, re-run against R03's algorithm+contracts as a PARITY
             check (gate_resource_guard_r03.py), reproduce identical verdicts, proving this
             correction touched nothing beyond the one field above.

See `resource_contracts_r02.py`'s own module docstring for the full schema field
documentation (acquisition_kind, acquisition_call, result_type, qualifier_type,
result_mfn_prefixes, size_arg_index, failure_predicate, failure_polarity,
applicable_exception_configuration, proven_unsafe_uses, citation) -- unchanged here, not
reproduced a second time.
"""

# Carried over byte-for-byte from resource_contracts_r02.py's SYNTHETIC_CONTRACTS, so R02's
# own 16 original controls reproduce identical verdicts when re-run against R03 as a parity
# check (see gate_resource_guard_r03.py) -- proving this file's correction is scoped to
# exactly the one field documented above.
SYNTHETIC_CONTRACTS = {
    "FactoryResource": {
        "acquisition_kind": "STATIC_FACTORY",
        "acquisition_call": "Acquire",
        "result_type": "FactoryResource",
        "qualifier_type": "FactoryResource",
        "result_mfn_prefixes": (
            "FactoryResource.Acquire:FactoryResource(Context*,unsigned long)",
        ),
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
    # NEW in R03, added ONLY to give control R03C ("an unqualified synthetic Buffer::New
    # matches its own, explicitly SEPARATE synthetic contract, never REAL_CONTRACTS'
    # namespace-qualified one") something to match in the SYNTHETIC pool. Deliberately
    # shares acquisition_call/failure_predicate names with the real contract (that is the
    # whole point of the control -- proving pool separation still holds even under a
    # name collision) but is otherwise fictional and unnamespaced; never used outside
    # gate_resource_guard_r03.py's own namespace-discrimination controls.
    "Buffer": {
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
        "applicable_exception_configuration": "n/a -- synthetic control fixture, not a real "
                                               "library; exists ONLY to prove that an "
                                               "unqualified/unnamespaced Buffer::New call "
                                               "matches this SEPARATE synthetic contract, "
                                               "never REAL_CONTRACTS' namespace-qualified "
                                               "Napi::Buffer entry, and vice versa.",
        "proven_unsafe_uses": ["n/a -- synthetic control fixture"],
        "citation": "Fictional, structural-test-only contract -- see gate_resource_guard_r03.py "
                    "(namespace-discrimination control R03C).",
    },
}

# The ONE narrow correction this file exists to make: qualifier_type is now the real,
# empirically-observed, namespace-qualified canonical form ("Napi.Buffer", not "Buffer") --
# confirmed directly against real Joern facts (gate_resource_guard_r03.py's control R03A and
# RESOURCE_GUARD_R02.md's Blind test #2 write-up: the real, correctly-resolved mfn for
# `Napi::Buffer<uint8_t>::New(...)` is "Napi.Buffer.New:Napi.Buffer(napi_env__*,long)").
# Matched by EXACT PREFIX (`mfn.startswith(qualifier_type + "." + acquisition_call + ":")`,
# unchanged algorithm logic in resource_guard_verdict_r03.py) -- deliberately NOT a suffix or
# substring check, so a nested/prefixed namespace (e.g. "Foo.Napi.Buffer.New:...") or an
# unrelated lookalike class name (e.g. "NapiBuffer.New:...", no namespace separator) is still
# correctly REJECTED (see controls R03B and R03E) rather than accepted by a loose match.
REAL_CONTRACTS = {
    "Napi::Buffer": {
        "acquisition_kind": "STATIC_FACTORY",
        "acquisition_call": "New",
        "result_type": "Buffer",
        "qualifier_type": "Napi.Buffer",  # <-- the R03 correction (was "Buffer" in R02)
        "result_mfn_prefixes": (
            "Napi.Buffer.New:Napi.Buffer(napi_env__*,unsigned long)",
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
            "check is not the same defect. R03 cannot determine which configuration a given "
            "call site was compiled under (no preprocessor state, no try/catch AST, is "
            "exported by this project's Joern facts) -- every finding against this contract "
            "discloses this assumption explicitly rather than silently assuming it. UNCHANGED "
            "from R02 -- this correction touches only qualifier_type, not this field."
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
            "both exception configurations). qualifier_type's namespace-qualified form is "
            "additionally confirmed directly against real Joern v4.0.608 c2cpg output (see "
            "RESOURCE_GUARD_R02.md's Blind test #2 and this file's own module docstring)."
        ),
    },
}
