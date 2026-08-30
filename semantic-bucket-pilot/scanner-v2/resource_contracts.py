#!/usr/bin/env python3
"""RESOURCE-CONTRACT-R01: curated summaries for classes whose CONSTRUCTOR receives a
size/count and may fail to fully acquire the requested resource, exposing a PREDICATE
method the caller must check before using the object. This is the ONLY way
resource_guard_verdict.py learns that a class is a "fallible bounded resource" -- it never
infers this from a class merely being RAII-shaped, nor from a method merely being NAMED
like a validity check (overflowed()/isValid()/failed()/ok()). Both were explicitly
rejected: an isValid()-named method proves nothing about what the constructor actually
does, and an unguarded RAII object whose constructor cannot fail (no size parameter, no
predicate at all) is not this pattern either. Every entry below is citation-backed against
a real header at a real revision -- never a guess about what a class "probably" does.

Fields:
  class_name                     -- the C++ class/struct's simple name, matched against a
                                     constructor CALL node's own `name`.
  ctor_method_full_name_prefixes -- tuple of FULL real methodFullName signatures (one per
                                     curated overload) -- kept as exact, citation-backed
                                     documentation of what was verified against real Joern
                                     facts. resource_guard_verdict.py does NOT string-match
                                     against these directly: it matches on PARAMETER COUNT
                                     alone (derived from these strings at load time).
                                     RESOURCE-CTOR-MATCH-R01/RESOURCE-CTOR-TYPEINFER-R01: a
                                     same-named call with a DIFFERENT param count is not
                                     this contract's constructor (covers an unrelated free
                                     function sharing the class's name, and an unexpected/
                                     uncurated overload) -- but exact TYPE TEXT is
                                     deliberately not required, because c2cpg's fuzzy call
                                     resolution infers a literal argument's OWN apparent
                                     type (e.g. `int` for a bare integer literal) rather
                                     than the true declared parameter type (`unsigned
                                     int`) when synthesizing methodFullName -- confirmed
                                     real via a synthetic control (gate_resource_guard.py,
                                     "attacker-independent size": passing a literal `4`
                                     changed the recorded methodFullName's 2nd parameter
                                     from `unsigned int` to `int`, all else identical).
                                     Both cases fall through to RESOURCE_SEMANTICS_
                                     UNRESOLVED when param count doesn't match, never
                                     guessed.
  size_arg_index                 -- argument index, in THIS PROJECT's arguments.tsv
                                     indexing (which counts the implicit receiver/`this`
                                     temp at index 0 for a member/init call -- verified
                                     empirically against real Joern facts, see
                                     study/js_c_transition/raw_case_hermes_apply), of the
                                     parameter receiving the acquisition size/count.
  predicate_method                -- the method name (calls.tsv `name`) whose call on
                                     THIS SAME object, after construction, reports whether
                                     acquisition succeeded.
  predicate_true_means_invalid    -- True if predicate()==true means "acquisition failed,
                                     object must not be used" (overflowed(), failed(),
                                     hasError()); False for the inverse polarity
                                     (isValid(), ok(), succeeded()).
  citation                        -- the real source citation backing every field above.
"""

CONTRACTS = {
    "ScopedNativeCallFrame": {
        "class_name": "ScopedNativeCallFrame",
        # RESOURCE-CTOR-MATCH-R01: the FULL real signature, not merely "class name
        # repeated" -- a coarse "ScopedNativeCallFrame.ScopedNativeCallFrame:" prefix
        # would match ANY constructor of this class regardless of parameter list,
        # silently accepting an unrecognized overload. Verified against real Joern facts
        # (study/js_c_transition/raw_case_hermes_apply's calls.tsv, methodFullName
        # column) for both the 5-arg (HermesValue callee) and 4-arg (Callable* callee)
        # real overloads Runtime.h declares.
        "ctor_method_full_name_prefixes": (
            "ScopedNativeCallFrame.ScopedNativeCallFrame:void(Runtime*,unsigned int,"
            "HermesValue,HermesValue,HermesValue)",
            "ScopedNativeCallFrame.ScopedNativeCallFrame:void(Runtime*,unsigned int,"
            "Callable*,bool,HermesValue)",
        ),
        "size_arg_index": 2,
        "predicate_method": "overflowed",
        "predicate_true_means_invalid": True,
        "citation": (
            "facebook/hermes include/hermes/VM/Runtime.h, revision 82f0f971 (the "
            "CVE-2020-1896 vulnerable revision) / 86543ac4 (its fix, unchanged in this "
            "respect): ScopedNativeCallFrame's constructor computes registersNeeded from "
            "argCount (this project's arguments.tsv index 2, counting the implicit "
            "receiver/`this` temp at index 0 -- see resource_guard_verdict.py's own "
            "object-identity resolution) and calls runtimeCanAllocateFrame() against the "
            "runtime's bounded register stack; on failure it sets overflowed_=true and "
            "returns WITHOUT constructing frame_. overflowed() returns that flag "
            "verbatim. operator-> asserts !overflowed() in debug builds -- using the "
            "frame without checking is a real, not hypothetical, use of a resource whose "
            "acquisition may not have happened."
        ),
    },
}
