#!/usr/bin/env python3
"""NAN CAPABILITY -- contract table for the two Nan Buffer-allocation entry points found by
`study/nan_prevalence_study/PREVALENCE_STUDY.md` to be the corpus's largest uncovered family
(38 packages / 104 call sites, larger than R05/R06's existing `Napi::Buffer<T>::New` coverage).

STANDALONE from the R04-R06/FIX01I lineage on purpose -- imports NOTHING from
resource_contracts_r04/r05.py or resource_guard_verdict_r04/r05/r06.py. In particular this
capability does NOT reuse R04-R06's exceptions-enabled/disabled build-configuration
applicability gate: `PREVALENCE_STUDY.md` Section 4 read `nan@2.28.0`'s (and 2.14.2's and
2.26.2's -- see NAN_CAPABILITY_DESIGN.md's version table, all three real, resolved versions
every development/control package in this capability actually declares) own real source and
confirmed `Nan::NewBuffer`/`Nan::CopyBuffer` return `v8::MaybeLocal<v8::Object>`, whose
`.ToLocalChecked()` (the ONLY pattern used by every real corpus call site read for this
capability) fatally aborts the process on an empty result -- a V8-level fatal-error path, not
a C++ exception and not a `napi_status` a caller branches on. There is no Nan-side equivalent
of "exceptions disabled"; R04-R06's whole applicability axis is a structural non sequitur here.

Two contracts, matching the exact scope the user asked this capability to cover:

  NAN_NEWBUFFER_UNBOUNDED_ALLOCATION -- `Nan::NewBuffer(...)`'s allocation LENGTH is JS-
    argument-controlled (via a real `info[N]` chain, real registration, real linked JS call --
    see `resource_guard_verdict_nan.py`'s promotion logic) with no structurally-detected
    application-level upper-bound check between the JS-argument read and the acquisition call.

  NAN_COPYBUFFER_SOURCE_CAPACITY -- `Nan::CopyBuffer(...)`'s copy LENGTH is JS-argument-
    controlled AND a real, local allocation site for the SOURCE pointer was found whose OWN
    size is structurally independent of (not the same traced identifier/expression as) that
    length -- i.e. a real, local, structural capacity/length MISMATCH, never inferred merely
    from "length is JS-controlled and I couldn't find where the source came from" (that case
    is NAN_COPYBUFFER_SOURCE_CAPACITY_UNRESOLVED, an abstention, not this verdict).

Every real Nan::NewBuffer/CopyBuffer call c2cpg resolves to the SAME
`<unresolvedNamespace>.<Name>:<unresolvedSignature>(N)` shape R05 already found for
`Napi::Buffer::New` (confirmed empirically on a real synthetic fixture run through the real
c2cpg/joern export pipeline -- see NAN_CAPABILITY_DESIGN.md Section 2) -- so, like R05's own
RECOVERY_CONTRACTS, matching is done by CALL NAME + the unresolved-shape marker, with arity
read directly from the call's own real `arguments.tsv` rows (never from signature text, which
carries only the raw argument COUNT for this shape, not a parenthesized type list).

Real, confirmed (same fixture run) per-arity argument layout -- Nan has NO `env` argument
(unlike every `Napi::` static factory), so `size_arg_index` is NOT a fixed constant here the
way it is for R04/R05's Napi contracts; it genuinely varies by which real overload matched:

  NewBuffer(char* data, size_t length, FreeCallback cb, void* hint)  -- arity 4, size @ index 2
  NewBuffer(uint32_t size)                                            -- arity 1, size @ index 1
  NewBuffer(char* data, uint32_t size)                                -- arity 2, size @ index 2
  CopyBuffer(const char* data, uint32_t size)                         -- arity 2, size @ index 2,
                                                                          source @ index 1
"""

UNRESOLVED_MFN_PREFIX = "<unresolvedNamespace>."
UNRESOLVED_SIG_MARKER = ":<unresolvedSignature>("

# The real, canonical Nan N-API-callback parameter type -- confirmed empirically (NOT assumed
# from the `Napi::CallbackInfo` analogy, which is a DIFFERENT literal string): c2cpg does not
# macro-expand `NAN_METHOD_ARGS_TYPE`/`NAN_METHOD`, so a real `NAN_METHOD(Name)`-declared
# method's own `info` parameter shows up in `parameters.tsv` with `typeFullName` exactly
# `Nan.NAN_METHOD_ARGS_TYPE` (Joern's dot-qualified rendering of `Nan::NAN_METHOD_ARGS_TYPE`).
# Matched as a substring for the same real, disclosed whitespace/qualification-variance reason
# R06's own `JS_CALLBACK_ORIGIN_TYPES` is.
JS_CALLBACK_ORIGIN_TYPES = ("Nan.NAN_METHOD_ARGS_TYPE", "Nan::NAN_METHOD_ARGS_TYPE")

NAN_NEWBUFFER_CONTRACT = {
    "contract_id": "NAN_NEWBUFFER_UNBOUNDED_ALLOCATION",
    "acquisition_call": "NewBuffer",
    "citation": "nan@2.28.0/2.26.2/2.14.2 nan.h -- Nan::NewBuffer(...), all real overloads "
                "wrap node::Buffer::New(...) and return v8::MaybeLocal<v8::Object>; every real "
                "corpus call site found by PREVALENCE_STUDY.md calls .ToLocalChecked() on the "
                "result (fatal V8-level abort on empty, not a catchable exception).",
    # arity -> 1-based index (matching arguments.tsv's own real, confirmed convention) of the
    # SIZE/LENGTH argument for that real overload. Any other arity is NOT a recognized
    # NewBuffer shape under this contract (abstain, never guess).
    "size_arg_index_by_arity": {1: 1, 2: 2, 4: 2},
}

NAN_COPYBUFFER_CONTRACT = {
    "contract_id": "NAN_COPYBUFFER_SOURCE_CAPACITY",
    "acquisition_call": "CopyBuffer",
    "citation": "nan@2.28.0/2.26.2/2.14.2 nan.h -- Nan::CopyBuffer(const char *data, "
                "uint32_t size) wraps node::Buffer::Copy(...), returns v8::MaybeLocal<v8::"
                "Object>; every real corpus call site calls .ToLocalChecked().",
    # Nan only exposes ONE real CopyBuffer overload (arity 2: data, size) -- confirmed reading
    # nan.h directly, not assumed. Any other arity is not a recognized shape.
    "size_arg_index_by_arity": {2: 2},
    "source_arg_index_by_arity": {2: 1},
}

CONTRACTS = {
    "NAN_NEWBUFFER_UNBOUNDED_ALLOCATION": NAN_NEWBUFFER_CONTRACT,
    "NAN_COPYBUFFER_SOURCE_CAPACITY": NAN_COPYBUFFER_CONTRACT,
}
