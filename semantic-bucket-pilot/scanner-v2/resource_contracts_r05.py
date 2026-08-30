#!/usr/bin/env python3
"""RESOURCE-CONTRACT-R05: a NARROW, disclosed ADDITION on top of R04 -- structured-evidence
RECOVERY contracts for calls c2cpg leaves as `<unresolvedNamespace>.<name>:
<unresolvedSignature>(N)`, confirmed real and corpus-wide (FINDINGS_REVIEW.md,
HDR_FIX_STATUS.md, `study/resource_guard_r05/AB_FIXTURE_RESULT.md`).

`resource_contracts_r04.py`/`REAL_CONTRACTS`/`SYNTHETIC_CONTRACTS` are UNCHANGED by this file
-- not imported, not modified. R04's own matching path (a call whose methodFullName already
resolves and starts with `qualifier_type.acquisition_call:`) is handled by
`resource_guard_verdict_r05.py` exactly as R04 handles it -- byte-for-byte reused logic, not
duplicated with drift. This file adds a SEPARATE table, `RECOVERY_CONTRACTS`, consulted ONLY
by the new recovery path `resource_guard_verdict_r05.py` adds, for calls R04's own path would
otherwise abstain on as `ACQUISITION_SIGNATURE_UNRECOGNIZED`.

See `study/resource_guard_r05/R05_DESIGN.md` for the full evidence chain and its real,
Joern-verified basis. Summary of this table's fields, all consulted structurally (never via
code-string matching -- see the design doc for the precise per-field justification):

  acquisition_kind, failure_predicate, failure_polarity, applicable_exception_configuration,
  proven_unsafe_uses, citation: SAME meaning as R01-R04's contract fields (see
  `resource_contracts_r02.py`'s own docstring for the base schema).
  acquisition_call:        the call's own `name` field (decoded, not methodFullName) that
                            must match for this contract to even be considered.
  result_type_forms:       a TUPLE of every real, independently-confirmed typeFullName form
                            the acquired object's LOCAL declaration resolves to for this
                            class (plural, unlike R01-R04's single `result_type`/
                            `qualifier_type` string, because c2cpg itself represents the same
                            real type inconsistently across real sites -- see
                            AB_FIXTURE_RESULT.md; matched by EXACT set membership, never a
                            prefix or substring, preserving R03's own no-loose-matching
                            discipline).
  required_arity:          the exact real argument count (from `arguments.tsv`, not from
                            `_param_count(mfn)`, which is meaningless for an unresolved
                            signature -- see the design doc) the curated ALLOCATING overload
                            takes. A different arity (e.g. Buffer::New's real 3-arg
                            external-data overload) is a DIFFERENT, out-of-scope overload and
                            is correctly left unrecovered by this single exact-arity check --
                            no separate exclusion list is needed.
  size_arg_index:           SAME meaning/convention as R01-R04 (the argument index, under
                            this project's 1-based-real-parameter indexing for a
                            STATIC_DISPATCH call with no receiver argument, that carries the
                            fallible allocation's size).
  arg0_env_type_forms:      the set of real typeFullName forms accepted for argument index 1
                            (the first real parameter -- the environment handle), the ONE
                            argument-role check this pass curates; matched by exact set
                            membership, same discipline as result_type_forms.

Scope boundary, stated up front (see R05_DESIGN.md's own "Scope boundaries" section for the
full account): only `Napi::Buffer::New`'s 2-arg allocating overload is curated here, matching
R02/R03/R04's own existing `REAL_CONTRACTS` scope exactly (New only, not Copy/NewOrCopy, and
not ArrayBuffer/External<T>/TypedArrayOf<T> -- the same recovery mechanism could extend to
those in future work, not attempted in this pass).
"""

RECOVERY_CONTRACTS = {
    "Napi::Buffer": {
        "acquisition_kind": "STATIC_FACTORY",
        "acquisition_call": "New",
        "result_type_forms": ("Buffer", "Napi.Buffer"),
        "required_arity": 2,
        "size_arg_index": 2,
        "arg0_env_type_forms": ("Napi.Env", "Env"),
        "failure_predicate": "IsEmpty",
        "failure_polarity": "true_means_invalid",
        "applicable_exception_configuration": (
            "IDENTICAL premise and identical disclosed limitation as "
            "resource_contracts_r03.py's REAL_CONTRACTS['Napi::Buffer']['applicable_"
            "exception_configuration'] -- see that file for the full, unedited text. Not "
            "reproduced a second time here; this is the SAME real node-addon-api class, "
            "recovered via a different evidence path, not a different premise."
        ),
        "proven_unsafe_uses": [
            "SAME as resource_contracts_r03.py's REAL_CONTRACTS['Napi::Buffer']['proven_"
            "unsafe_uses'] -- see that file. Recovery changes how the acquisition call is "
            "IDENTIFIED, not what using an empty Buffer's Data()/operator[] does.",
        ],
        "citation": (
            "SAME real node-addon-api source as resource_contracts_r03.py's REAL_CONTRACTS "
            "entry. This table's own contribution is the result_type_forms/required_arity/"
            "arg0_env_type_forms evidence, confirmed directly against real Joern facts from "
            "two independent real corpus packages (Cartesi, @appthreat/sqlite3) and the "
            "committed r05_controls fixture -- see study/resource_guard_r05/R05_DESIGN.md "
            "and AB_FIXTURE_RESULT.md."
        ),
    },
}
