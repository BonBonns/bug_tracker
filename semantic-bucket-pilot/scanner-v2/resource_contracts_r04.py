#!/usr/bin/env python3
"""RESOURCE-CONTRACT-R04: adds APPLICABILITY ENFORCEMENT on top of R03 -- NOT a change to
R03's contract data, matching logic, or verdict categories for the applicable case. R03
(`resource_contracts_r03.py`/`resource_guard_verdict_r03.py`) is UNCHANGED by this file --
not imported, not modified, still byte-identical to its own recorded Freeze-section hashes.
R03's own blind-test result against `@julusian/jpeg-turbo` (`DecompressInner`, see
RESOURCE_GUARD_R03.md's "R03 blind test") is NOT rewritten -- its recorded
`VALUE_ACQUISITION_GUARD_MISSING` finding stands, permanently, as R03's own output. What R04
adds is a documented, disclosed CORRECTION TO THE INTERPRETATION of that result (see
RESOURCE_GUARD_R03.md's own "Reclassification" addendum) and a new, separate algorithm layer
that would have produced the CORRECT classification had it existed at the time.

Why R04 exists: R03's own blind test against jpeg-turbo revealed a real problem, not a
successful generalization. jpeg-turbo most likely builds with C++ exceptions ENABLED (no
`NAPI_DISABLE_CPP_EXCEPTIONS` anywhere in its real build config, and node-addon-api's own
real default-resolution logic enables exceptions absent an explicit compiler-level opt-out --
independently confirmed against node-addon-api's real `napi.h`). Per node-addon-api's own
official documentation (`doc/value.md`: empty values represent a failure specifically when
C++ exceptions are DISABLED; `doc/error_handling.md`: with exceptions ENABLED, a failure
instead throws a C++ exception directly, and a missing `IsEmpty()` check is not the same
defect), R03's `Napi::Buffer::New()`/`IsEmpty()` contract simply DOES NOT APPLY to a call
site under an exceptions-enabled build -- yet R03 (and R02 before it) only ever CARRIED this
as a disclosed, never-enforced ASSUMPTION (`applicable_exception_configuration`) on every
finding, and applied the contract's guard-missing logic regardless of whether that assumption
actually held. jpeg-turbo's `VALUE_ACQUISITION_GUARD_MISSING` finding is therefore a
CONFIGURATION-DRIVEN FALSE POSITIVE: real cross-project SYNTACTIC/graph-shape recognition
(the algorithm correctly found the acquisition, the qualifier, the object identity, the
downstream use, and the absence of a guard) but NOT cross-contract SEMANTIC portability (the
contract's own applicability precondition -- an exceptions-disabled build -- was never
actually verified, and in this case does not hold).

R04's one narrow addition: contract applicability must be ESTABLISHED, per real,
citation-backed BUILD-CONFIGURATION EVIDENCE, BEFORE a MISSING/ESTABLISHED verdict is
reported at all. This evidence CANNOT come from the exported CPG facts (which carry no
preprocessor state, confirmed repeatedly since R02) -- it must come from a separate,
explicitly curated, per-run manifest (see `resource_guard_verdict_r04.py`'s own module
docstring for the `build_config.json` schema and loading rules) built from real,
independently-verified build files (binding.gyp, CMakeLists.txt, compiler flags, package
build scripts, node-addon-api configuration macros, or an explicit trusted build manifest) --
never inferred from the ABSENCE of a try/catch in the source (a source-level signal
unrelated to the actual compiled build configuration), and never silently defaulted to
"disabled" when unresolved.

Schema fields: EVERYTHING from `resource_contracts_r03.py` (see that file's own module
docstring for the full field list: acquisition_kind, acquisition_call, result_type,
qualifier_type, result_mfn_prefixes, size_arg_index, failure_predicate, failure_polarity,
proven_unsafe_uses, citation) is UNCHANGED here, carried over byte-for-byte. The one field
whose ROLE changes: `applicable_exception_configuration` remains present on every contract as
DOCUMENTATION/citation text (what this contract's failure signature means, and under which
configuration) -- but it is NO LONGER what gates the verdict. That job moves entirely to the
external, per-run `build_config.json` evidence `resource_guard_verdict_r04.py` requires (see
that file). A contract's own `applicable_exception_configuration` string is never consulted
by R04's matching/gating logic; it exists only so a human reading a contract's own citation
still sees the semantics it was written against.

New verdict categories introduced (per explicit instruction; not otherwise a change to R03's
own MISSING/ESTABLISHED categories or the logic that produces them for an applicable site):
`CONTRACT_NOT_APPLICABLE` (exceptions established enabled -- acquisition failure throws, a
missing `IsEmpty()` is not a defect under this contract), `BUILD_CONFIGURATION_UNRESOLVED`
(no usable evidence either way), `BUILD_CONFIGURATION_CONFLICT` (contradictory evidence,
e.g. both `NAPI_CPP_EXCEPTIONS` and `NAPI_DISABLE_CPP_EXCEPTIONS` defined for the same
build). None of these three claims a memory-safety defect, a CWE, or a vulnerability -- they
are applicability/abstention classifications, exactly as `ACQUISITION_SIGNATURE_UNRECOGNIZED`
and `VALUE_ACQUISITION_SEMANTICS_UNRESOLVED` already are in R02/R03.
"""

# Carried over byte-for-byte from resource_contracts_r03.py's SYNTHETIC_CONTRACTS, unchanged
# -- R04 does not touch matching/dominance/tracing logic or contract data, only adds the
# separate build-configuration applicability gate (resource_guard_verdict_r04.py).
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

# Carried over byte-for-byte from resource_contracts_r03.py's REAL_CONTRACTS -- the
# namespace-qualified qualifier_type correction stands unchanged. R04 adds NO new contract
# fields here; applicability now comes entirely from the external build_config.json evidence
# resource_guard_verdict_r04.py requires per run (see that file and this file's own module
# docstring). applicable_exception_configuration below is retained as documentation/citation
# text ONLY -- it is never read by R04's gating logic.
REAL_CONTRACTS = {
    "Napi::Buffer": {
        "acquisition_kind": "STATIC_FACTORY",
        "acquisition_call": "New",
        "result_type": "Buffer",
        "qualifier_type": "Napi.Buffer",
        "result_mfn_prefixes": (
            "Napi.Buffer.New:Napi.Buffer(napi_env__*,unsigned long)",
        ),
        "size_arg_index": 2,
        "failure_predicate": "IsEmpty",
        "failure_polarity": "true_means_invalid",
        "applicable_exception_configuration": (
            "exceptions_disabled -- per node-addon-api's own official documentation "
            "(doc/value.md: an empty value represents a failure specifically when C++ "
            "exceptions are DISABLED at compile time; doc/error_handling.md, 'Handling "
            "Errors With Maybe Type and C++ Exceptions Disabled' / 'Handling Errors Without "
            "C++ Exceptions'): when C++ exceptions are DISABLED, a node-addon-api call that "
            "would otherwise throw instead raises a pending JavaScript exception and returns "
            "an EMPTY Napi::Value. Under an exceptions-ENABLED build, the SAME failure "
            "instead throws a C++ exception of type Napi::Error directly (doc/"
            "error_handling.md, 'Handling Errors With C++ Exceptions') -- code after the "
            "acquisition call is simply never reached on failure, and a missing IsEmpty() "
            "check is not the same defect. DOCUMENTATION ONLY as of R04 -- this field is "
            "never consulted by the gating logic; resource_guard_verdict_r04.py requires "
            "real, per-run build_config.json evidence instead of assuming this value holds."
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
            "size_t)) and doc/buffer.md, doc/value.md, doc/error_handling.md (official "
            "documentation of both exception configurations, including the value.md passage "
            "confirming empty-value failure representation is specific to the "
            "exceptions-disabled configuration). qualifier_type's namespace-qualified form is "
            "additionally confirmed directly against real Joern v4.0.608 c2cpg output (see "
            "RESOURCE_GUARD_R02.md's Blind test #2 and resource_contracts_r03.py's own "
            "module docstring)."
        ),
    },
}
