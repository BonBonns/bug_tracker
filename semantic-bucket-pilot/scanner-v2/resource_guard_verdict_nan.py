#!/usr/bin/env python3
"""NAN CAPABILITY -- verdict engine for the two contracts in `resource_contracts_nan.py`.

STANDALONE, new code: imports NOTHING from resource_guard_verdict_r04/r05/r06.py,
resource_contracts_r04/r05.py, or promote_via_js_linkage.py. In particular this file does NOT
carry R04-R06's exceptions-enabled/disabled build-configuration applicability gate -- that
gate's whole premise (a checkable `IsEmpty()`-style failure predicate on the acquired object)
does not hold for `Nan::NewBuffer`/`Nan::CopyBuffer`'s real `.ToLocalChecked()` idiom (see
`resource_contracts_nan.py`'s module docstring and NAN_CAPABILITY_DESIGN.md Section 3 for the
real, version-verified semantics this file's own evidence notes are built from).

Every real structural technique below (the unresolved-call-shape matching, the CallbackInfo-
index backward trace, the registration extraction, the upper-bound-check detector, the
CopyBuffer source-capacity resolver) was designed against REAL raw facts from a REAL c2cpg/
jssrc2cpg run over a purpose-built synthetic fixture -- see
`study/nan_capability/controls/comprehensive_fixture/` for the fixture source and
`NAN_CAPABILITY_DESIGN.md` Section 2 for the real facts that shaped each decision (e.g. c2cpg
does NOT macro-expand `NAN_METHOD_ARGS_TYPE`; a chained method call's receiver IS represented
as argument index 0; `Nan::SetPrototypeMethod`/`Nan::SetMethod`'s function-reference argument
is a real `METHOD_REF` node whose own `code` is the bare function name, a simpler and MORE
reliable shape than R06/FIX01I's own `InstanceMethod<&Class::Method>` text-regex fallback).

Findings are STATIC CANDIDATES, never vulnerability or CWE claims -- see each finding's own
`evidence_note` and NAN_CAPABILITY_DESIGN.md's "reachable security consequence" section for
why: an unbounded, JS-argument-controlled `Nan::NewBuffer`/`CopyBuffer` call has two real,
disclosed, structurally-grounded consequences (excessive memory consumption / integer-overflow
risk on success, or a fatal V8-level process abort via `.ToLocalChecked()` on failure) -- this
file establishes JS-argument control and (for NewBuffer) the absence of a detected bound, or
(for CopyBuffer) a structural capacity/length mismatch; it does NOT evaluate exploitability,
does NOT assert a CWE, and NEVER infers an out-of-bounds read merely from "length is
JS-controlled and I could not resolve where the source came from" -- that case is a separate,
explicit `NAN_COPYBUFFER_SOURCE_CAPACITY_UNRESOLVED` abstention.

Usage: resource_guard_verdict_nan.py CPP_RAW_DIR JS_RAW_DIR OUT.json
  JS_RAW_DIR may be "-" if no JS facts are available for this run (every finding that would
  otherwise require JS-call confirmation is then reported as NAN_JS_CALL_UNRESOLVED, an
  abstention -- registration alone is never treated as proof a real JS call reaches it).
"""
import base64
import json
import sys
from collections import defaultdict

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from resource_contracts_nan import (
    CONTRACTS, JS_CALLBACK_ORIGIN_TYPES, UNRESOLVED_MFN_PREFIX, UNRESOLVED_SIG_MARKER)


def dec(s):
    if not s:
        return ""
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except Exception:
        return s


def rows(path, n):
    out = []
    for ln in open(path):
        ln = ln.rstrip("\n")
        if not ln.strip():
            continue
        xs = ln.split("\t")
        if len(xs) != n:
            raise ValueError(f"{path}: expected {n} cols, got {len(xs)}: {ln!r}")
        out.append(xs)
    return out


def _is_js_callback_origin_type(type_full_name):
    t = type_full_name or ""
    return any(marker in t for marker in JS_CALLBACK_ORIGIN_TYPES)


def _is_unresolved_shape(mfn):
    return (mfn or "").startswith(UNRESOLVED_MFN_PREFIX) and UNRESOLVED_SIG_MARKER in (mfn or "")


# --- Raw C++ fact loading (11-column calls.tsv/8-column arguments.tsv/7-column
# parameters.tsv/10-column methods.tsv -- same real schema resource_guard_verdict_r04-r06.py's
# own `rows()` calls expect; loaded independently here, not imported). -------------------------
def load_cpp_raw(raw_dir):
    methods = {}       # id -> {"name","full_name","is_external","line_start","line_end"}
    for r in rows(f"{raw_dir}/methods.tsv", 10):
        methods[int(r[0])] = {"name": dec(r[1]), "full_name": dec(r[2]),
                               "is_external": r[9].strip().lower() == "true",
                               "line_start": r[5], "line_end": r[6]}

    calls = {}
    calls_by_method = defaultdict(list)
    for r in rows(f"{raw_dir}/calls.tsv", 11):
        cid, owner = int(r[0]), int(r[1])
        calls[cid] = {"id": cid, "owner": owner, "name": dec(r[2]), "mfn": dec(r[3]),
                      "code": dec(r[6]), "line": r[8]}
        calls_by_method[owner].append(cid)

    args_by_call = defaultdict(dict)
    for r in rows(f"{raw_dir}/arguments.tsv", 8):
        call_id, idx = int(r[1]), int(r[2])
        args_by_call[call_id][idx] = {"kind": dec(r[3]), "code": dec(r[4]),
                                       "name": dec(r[5]), "type": dec(r[6]),
                                       "node_id": int(r[0])}

    params_by_method = defaultdict(set)
    param_types_by_method = defaultdict(dict)
    for r in rows(f"{raw_dir}/parameters.tsv", 7):
        owner = int(r[1])
        pname = dec(r[3])
        params_by_method[owner].add(pname)
        param_types_by_method[owner][pname] = dec(r[5])

    cfg_next = defaultdict(list)
    try:
        for r in rows(f"{raw_dir}/cfg_edges.tsv", 3):
            owner, frm, to = int(r[0]), int(r[1]), int(r[2])
            cfg_next[(owner, frm)].append(to)
    except FileNotFoundError:
        pass

    return {"methods": methods, "calls": calls, "calls_by_method": calls_by_method,
            "args_by_call": args_by_call, "params_by_method": params_by_method,
            "param_types_by_method": param_types_by_method, "cfg_next": cfg_next}


# --- Raw JS fact loading (real neutral-frontend schema -- see NEUTRAL_IR.md; confirmed
# empirically to be the SAME 8-col arguments.tsv / (10 or 11)-col calls.tsv shape, 1-based
# argument indexing with index 0 reserved for the call's own receiver). ------------------------
def load_js_raw(js_raw_dir):
    if not js_raw_dir or js_raw_dir == "-":
        return None
    calls = {}
    calls_by_name = defaultdict(list)
    for ln in open(f"{js_raw_dir}/calls.tsv"):
        ln = ln.rstrip("\n")
        if not ln.strip():
            continue
        xs = ln.split("\t")
        if len(xs) < 9:
            continue
        cid, name = int(xs[0]), dec(xs[2])
        calls[cid] = {"id": cid, "name": name, "code": dec(xs[6])}
        calls_by_name[name].append(cid)

    args_by_call = defaultdict(dict)
    for ln in open(f"{js_raw_dir}/arguments.tsv"):
        ln = ln.rstrip("\n")
        if not ln.strip():
            continue
        xs = ln.split("\t")
        if len(xs) < 6:
            continue
        call_id, idx = int(xs[1]), int(xs[2])
        args_by_call[call_id][idx] = {"kind": dec(xs[3]), "code": dec(xs[4])}

    return {"calls": calls, "calls_by_name": calls_by_name, "args_by_call": args_by_call}


# NAN-REPLAY-TASK4 addition: an adapter from the NORMALIZED js_facts.json shape (the only JS-side
# artifact the 100-package evidence bundles ever preserve -- evidence_bundle.py's own module
# docstring never keeps the raw jssrc2cpg TSV export `load_js_raw()` above reads) into the SAME
# `{"calls", "calls_by_name", "args_by_call"}` dict shape `load_js_raw()` returns. This is a real
# adapter, not a reimplementation: confirmed directly against a real bundle
# (node-libcurl@5.1.2's own js_facts.json) that js_facts.json's own `calls` array already carries
# per-call `id`/`name`/`code` and per-argument `call_id`/`index`/`kind`/`code` -- the exact same
# neutral-frontend schema `load_js_raw()`'s own module comment already documents (8-col
# arguments.tsv / 10-11-col calls.tsv, 1-based argument indexing, index 0 reserved for the
# receiver), just already parsed into JSON instead of raw TSV rows, because js_facts.json IS the
# normalized form of the same raw jssrc2cpg export -- not a different, lossy summary of it for
# the fields this file actually reads (name, code, arguments/index/kind/code). Every downstream
# consumer of the returned dict (`is_native_module_directly_exported`, `find_js_call_confirming_
# index`) only ever reads exactly these fields, confirmed by direct code inspection above.
def load_js_raw_from_facts_json(js_facts_path):
    if not js_facts_path or js_facts_path == "-":
        return None
    with open(js_facts_path) as f:
        facts = json.load(f)
    calls = {}
    calls_by_name = defaultdict(list)
    args_by_call = defaultdict(dict)
    for c in facts.get("calls", []):
        cid = int(c["id"])
        name = c.get("name") or ""
        calls[cid] = {"id": cid, "name": name, "code": c.get("code") or ""}
        calls_by_name[name].append(cid)
        for a in c.get("arguments", []):
            idx = a.get("index")
            if idx is None:
                continue
            args_by_call[cid][int(idx)] = {"kind": a.get("kind") or "", "code": a.get("code") or ""}
    return {"calls": calls, "calls_by_name": calls_by_name, "args_by_call": args_by_call}


# RESOURCE-GUARD-NAN real-corpus fix (found via direct user challenge to node-snap7's own real
# `Upload`/`FullUpload` abstentions, then independently verified against real facts, not
# conceded on principle alone): requiring a CONFIRMED real JS call site (the strongest
# evidence, kept as the primary tier below) is too strict when the package's own JS entry
# point unconditionally re-exports the ENTIRE native binding object -- real, confirmed via
# node-snap7's own actual source: `module.exports = snap7 = require('bindings')
# ('node_snap7.node')` (its own `lib/node-snap7.js:8`) is the SAME `target` object the C++
# side attaches `S7Client` onto (`Nan::Set(target, "S7Client", Nan::GetFunction(tpl)...)`,
# `node_snap7_client.cpp:697`) -- meaning EVERY `Nan::SetPrototypeMethod`-registered method on
# that class, including `Upload`/`FullUpload` (which the package's own bundled convenience
# wrapper happens never to call), is directly, unconditionally callable by ANY consumer of the
# package with ANY arguments the caller supplies. A package's own internal wrapper choosing
# not to call a method says nothing about whether external code can -- Cartesi's own real case
# (this project's precedent for requiring a confirmed call) was different IN KIND: there, the
# real PUBLISHED package's JS entry point was a WASM bundle that never even required the
# native binding at all, so nothing was exported, confirmed or otherwise. Real, narrow,
# structural check for the "whole native module is unconditionally re-exported" idiom (NOT a
# general receiver-provenance resolver -- that would be reusing R06/FIX01I's own
# `resolve_loader_provenance`/`native_binding_receiver_evidence`, deliberately not done here to
# keep this capability standalone; this is a narrower, sufficient, independently-written check
# for one specific, real, common shape): does a real `module.exports = ...`/`exports = ...`
# assignment's own captured `code` text contain a `require(<loader package>)(...)` invocation?
# `LOADER_PACKAGES` reuses the same real, frozen vocabulary `link_napi_facts.py`'s own
# `NATIVE_LOADER_PACKAGES` already established (`{'bindings', 'node-gyp-build'}`) -- the
# de facto standard native-addon loaders, not a value invented for this file.
import re as _re
LOADER_PACKAGES = ("bindings", "node-gyp-build")
LOADER_INVOCATION_RE = _re.compile(
    r"require\(\s*['\"](" + "|".join(LOADER_PACKAGES) + r")['\"]\s*\)\s*\(")


def is_native_module_directly_exported(js):
    """True iff real JS facts show `module.exports`/`exports` assigned (directly, or via one
    level of chained/aliased assignment in the SAME statement -- confirmed real on node-snap7's
    own `module.exports = snap7 = require(...)(...)` shape, where Joern's own captured `code`
    for the OUTER assignment already contains the full RHS text) from a real
    `require(<loader>)(...)` invocation. A package that instead selectively re-exports specific
    names (`exports.Foo = binding.Foo`) will NOT match this -- correctly: only an
    UNCONDITIONAL, WHOLE-MODULE re-export justifies treating every registered method as public
    without a confirmed call, and this check does not claim to establish anything for a
    package that does something narrower."""
    if js is None:
        return False
    for c in js["calls"].values():
        if c["name"] != "<operator>.assignment":
            continue
        code = c.get("code") or ""
        if not (code.startswith("module.exports") or code.startswith("exports")):
            continue
        if LOADER_INVOCATION_RE.search(code):
            return True
    return False


# --- Registration extraction: Nan::SetPrototypeMethod(tpl, "name", Class::Method) /
# Nan::SetMethod(target, "name", Fn) -- confirmed real, IDENTICAL structural shape for both
# idioms (see NAN_CAPABILITY_DESIGN.md Section 2): a real, `<unresolvedNamespace>.<Set...>
# Method>:<unresolvedSignature>(3)` call whose 3rd argument is a real METHOD_REF node carrying
# the bare, unqualified function name as its own `code` -- simpler and more reliable than
# R06/FIX01I's own `InstanceMethod<&Class::Method>` text-regex fallback (no template-argument
# text parsing needed at all here). ------------------------------------------------------------
REGISTRATION_CALL_NAMES = ("SetPrototypeMethod", "SetMethod")


def _class_prefix(full_name):
    """`Class.Method:Sig(...)` -> `"Class"`; a free function's own full_name has no such
    prefix (`Method:Sig(...)`) -> `None`. Joern's own real dot-qualified convention, same one
    R06/FIX01I's own `extract_instancemethod_bindings` relies on for its own class/method
    split."""
    head = full_name.split(":", 1)[0]
    return head.rsplit(".", 1)[0] if "." in head else None


def extract_registrations(cpp):
    """Returns ({js_name: [function_id, ...]}, audit_list).

    RESOURCE-GUARD-NAN real-corpus fix (found running this file against node-snap7's own real
    facts, not assumed): a GLOBAL bare-name candidate match is too broad -- node-snap7's own
    real `ReadArea` bare name resolves to 5 real distinct method nodes (confirmed via a real
    run: the header's own declaration, the .cpp's own out-of-line definition, and c2cpg
    parsing artifacts around the class's real namespace nesting all count as real,
    non-external nodes sharing the bare name `ReadArea`). Disambiguation is now CLASS-SCOPED
    first: the registration call's own ENCLOSING method (e.g. `S7Client::Init`) supplies a
    real class prefix (`S7Client`) via `_class_prefix`; only candidate functions whose OWN
    `full_name` starts with that SAME `{prefix}.{fn_name}:` are considered -- exactly the
    qualified-prefix convention R04/R05 already use for contract matching, applied here to
    registration matching instead. When the registration call itself has NO class prefix (a
    free-function `Init`, matching `Nan::SetMethod`'s own real free-function idiom), candidates
    are restricted the same way to functions with NO class prefix of their own. If more than
    one real candidate remains even after class-scoping (e.g. a real header declaration AND
    its own out-of-line definition, both in the SAME class), a second, real, structural
    tiebreak applies: prefer the ONE candidate whose own `line_end` differs from its own
    `line_start` (a real function BODY spanning multiple lines) when exactly one such candidate
    exists among the class-scoped set -- a declaration-only prototype has no body to span.
    Still never a guess: if ambiguity survives both real, structural narrowing steps, the
    registration is skipped (audited, not silently accepted)."""
    fns_by_name = defaultdict(list)
    for fid, m in cpp["methods"].items():
        if not m["is_external"]:
            fns_by_name[m["name"]].append(fid)

    def resolve_candidates(fn_name, class_prefix):
        raw = fns_by_name.get(fn_name, [])
        if class_prefix is not None:
            scoped = [fid for fid in raw
                      if _class_prefix(cpp["methods"][fid]["full_name"]) == class_prefix]
        else:
            scoped = [fid for fid in raw
                      if _class_prefix(cpp["methods"][fid]["full_name"]) is None]
        if len(scoped) == 1:
            return scoped, None
        if len(scoped) <= 1:
            return scoped, "no class-scoped candidate"
        with_body = [fid for fid in scoped
                     if cpp["methods"][fid]["line_start"] != cpp["methods"][fid]["line_end"]]
        if len(with_body) == 1:
            return with_body, "resolved via has-a-real-body tiebreak among " \
                               f"{len(scoped)} class-scoped candidates"
        return scoped, f"{len(scoped)} class-scoped candidates remain ambiguous even after " \
                        "the body-presence tiebreak"

    table = defaultdict(list)
    audit = []
    for cid, c in cpp["calls"].items():
        if c["name"] not in REGISTRATION_CALL_NAMES:
            continue
        if not _is_unresolved_shape(c["mfn"]):
            continue
        args = cpp["args_by_call"].get(cid, {})
        if len(args) != 3:
            audit.append({"call": cid, "skipped": f"arity {len(args)}, expected 3"})
            continue
        name_arg, fn_arg = args.get(2), args.get(3)
        if not name_arg or name_arg["kind"] != "LITERAL":
            audit.append({"call": cid, "skipped": "arg 2 is not a string literal"})
            continue
        if not fn_arg or fn_arg["kind"] != "METHOD_REF":
            audit.append({"call": cid, "skipped": "arg 3 is not a METHOD_REF"})
            continue
        js_name = name_arg["code"].strip().strip('"')
        fn_name = fn_arg["code"].strip()
        enclosing = cpp["methods"].get(c["owner"])
        class_prefix = _class_prefix(enclosing["full_name"]) if enclosing else None
        cands, why = resolve_candidates(fn_name, class_prefix)
        if len(cands) != 1:
            audit.append({"call": cid, "name": js_name, "fn": fn_name,
                          "class_prefix": class_prefix,
                          "skipped": why or f"{len(cands)} candidates for {fn_name!r}"})
            continue
        table[js_name].append(cands[0])
        audit.append({"call": cid, "name": js_name, "fn": fn_name,
                      "class_prefix": class_prefix, "linked_function_id": cands[0]})
    return dict(table), audit


# --- CallbackInfo[index] backward trace ---------------------------------------------------
# Two real, DIFFERENT structural shapes checked, both starting from the acquisition call's own
# SIZE argument and walking backward through assignment-RHS chains and CALL-argument chains
# (including argument index 0 -- confirmed empirically to be a chained call's own real
# RECEIVER, e.g. `Nan::To<int32_t>(info[3]).FromJust()`'s `FromJust()` call has
# `Nan::To<int32_t>(info[3])` as its own index-0 argument):
#
#  (a) DIRECT-CHAIN (confirmed real on every corpus site read for this capability -- node-
#      snap7's own `Nan::To<int32_t>(info[3]).FromJust()` idiom): the walk visits a CALL that
#      is ITSELF `<operator>.indirectIndexAccess` on an identifier of a real CallbackInfo-typed
#      parameter, with a literal integer index.
#  (b) OUT-PARAMETER (the shape FIX01I's own `find_callback_info_index_source` models for
#      node-addon-api's `get_u64(env, info[N], "name", &var)` idiom -- included here for
#      structural parity/future-proofing, NOT because any real Nan corpus site read for this
#      capability used it; disclosed, not fabricated as confirmed-real for Nan specifically):
#      a call whose OWN arguments include both an `info[N]`-shaped indirectIndexAccess AND an
#      `<operator>.addressOf` on the traced variable's name.
def _callback_info_params(cpp, method_id):
    return {pname for pname, ptype in cpp["param_types_by_method"].get(method_id, {}).items()
            if _is_js_callback_origin_type(ptype)}


# RESOURCE-GUARD-NAN real-corpus fix (found running this file against libpq's own real facts,
# not assumed): the walk below chases EVERY argument of every visited call, which is sound for
# argument index 0 (a chained method call's own real RECEIVER -- `X.Method()` genuinely
# operates on `X`, confirmed empirically on node-snap7's own `.FromJust()`/`.To()` chains) but
# is NOT sound for a NON-receiver argument of an arbitrary, opaque, project-defined function --
# nothing static guarantees that function's RETURN VALUE derives from that specific argument.
# Real, confirmed false trace this caused before the fix: libpq's `Nan::NewBuffer(buffer,
# length, ...)` where `length = PQgetCopyData(self->pq, &buffer, async)` -- the walk chased
# `async` (`PQgetCopyData`'s own 3rd argument, wholly unrelated to what `length` actually is:
# libpq's own internal count of bytes read) all the way back through
# `async = info[0]->IsTrue() ? 1 : 0` to a real `info[0]` access, and reported `length` as
# JS-argument-controlled -- true for `async`, false for `length`, and `length` is what
# actually matters here. Fix: non-zero-index arguments of a visited call are only chased when
# that call's own name is in this explicit, narrow, disclosed allowlist of Nan/V8 conversion
# helpers CONFIRMED (nan.h read directly) to derive their return value from that argument --
# index-0 receiver chasing remains unconditional (a structurally different, sound pattern).
# This is a real, disclosed under-approximation, not a guess in the other direction: a value
# passed as a non-receiver argument to an ordinary project-local helper (e.g. node-snap7's own
# `GetByteCountFromWordLen(Nan::To<int32_t>(info[4]).FromJust())`) will not be traced through
# that helper -- reported SOURCE_BOUNDARY_UNRESOLVED for that specific identifier rather than
# guessed, exactly the same abstain-when-uncertain discipline as the rest of this project.
KNOWN_VALUE_DERIVING_CALLS = {"To"}  # Nan::To<T>(value) -- confirmed real: nan.h's own
                                       # implementation returns a Maybe<T> derived directly
                                       # from `value`, its own real, single meaningful argument.


def _direct_chain_index(cpp, call_id, callback_info_params):
    c = cpp["calls"].get(call_id)
    if c is None or c["name"] != "<operator>.indirectIndexAccess":
        return None
    a = cpp["args_by_call"].get(call_id, {})
    base, idx = a.get(1), a.get(2)
    if not base or base["kind"] != "IDENTIFIER" or base["code"].strip() not in callback_info_params:
        return None
    if not idx or idx["kind"] != "LITERAL":
        return None
    try:
        return int(idx["code"])
    except ValueError:
        return None


def _out_param_index(cpp, method_id, var_name, callback_info_params):
    def is_info_index_access(cid):
        return _direct_chain_index(cpp, cid, callback_info_params)

    def is_address_of(cid, name):
        c = cpp["calls"].get(cid)
        if c is None or c["name"] != "<operator>.addressOf":
            return False
        a = cpp["args_by_call"].get(cid, {}).get(1)
        return bool(a and a["kind"] == "IDENTIFIER" and a["code"].strip() == name)

    for cid in cpp["calls_by_method"].get(method_id, ()):
        args = cpp["args_by_call"].get(cid, {})
        found_index, found_addr = None, False
        for a in args.values():
            if a["kind"] != "CALL":
                continue
            n = is_info_index_access(a["node_id"])
            if n is not None:
                found_index = n
            if is_address_of(a["node_id"], var_name):
                found_addr = True
        if found_index is not None and found_addr:
            return found_index
    return None


def find_js_index_source_for_value(cpp, method_id, start_arg, depth=10):
    """Backward walk from `start_arg` (a raw argument dict). Returns
    {"callback_info_index": N, "visited_names": {...}} on a real match (checking BOTH direct-
    chain and out-parameter shapes at every call/identifier visited, not only the walk's final
    terminal name -- the same real lesson FIX01I's own docstring records: Cartesi's own
    `length = 0` default-initializer would silently dead-end a final-name-only check), else
    None. `visited_names` is every identifier name the walk crossed -- handed to the
    upper-bound-check detector so a guard on an INTERMEDIATE name (e.g. `amount`, not only the
    final `size`) is still recognized."""
    callback_info_params = _callback_info_params(cpp, method_id)
    if not callback_info_params:
        return None
    calls_by_method = cpp["calls_by_method"]
    args_by_call = cpp["args_by_call"]

    seen_names, seen_calls = set(), set()
    visited_names = set()
    frontier = ([("call", start_arg["node_id"], 0)] if start_arg["kind"] == "CALL"
                else [("name", start_arg["code"].strip(), 0)])
    while frontier:
        kind, val, hops = frontier.pop(0)
        if hops > depth:
            continue
        if kind == "name":
            if val in seen_names:
                continue
            seen_names.add(val)
            visited_names.add(val)
            oi = _out_param_index(cpp, method_id, val, callback_info_params)
            if oi is not None:
                return {"callback_info_index": oi, "visited_names": visited_names,
                        "shape": "out_parameter"}
            for cid in calls_by_method.get(method_id, ()):
                c = cpp["calls"][cid]
                if c["name"] != "<operator>.assignment":
                    continue
                a = args_by_call.get(cid, {})
                lhs, rhs = a.get(1), a.get(2)
                if not lhs or not rhs or lhs["code"].strip() != val:
                    continue
                if rhs["kind"] == "IDENTIFIER":
                    frontier.append(("name", rhs["code"].strip(), hops + 1))
                elif rhs["kind"] == "CALL":
                    frontier.append(("call", rhs["node_id"], hops + 1))
        else:
            if val in seen_calls:
                continue
            seen_calls.add(val)
            di = _direct_chain_index(cpp, val, callback_info_params)
            if di is not None:
                return {"callback_info_index": di, "visited_names": visited_names,
                        "shape": "direct_chain"}
            call_name = cpp["calls"][val]["name"]
            # Real operators (`<operator>.multiplication` etc.) use 1-based OPERAND indexing
            # with no index-0 "receiver" at all (confirmed real: `<operator>.multiplication`'s
            # own `amount * byteCount` has "amount" at index 1, "byteCount" at index 2) --
            # ALL of an operator's own operands genuinely determine its result, a
            # structurally different and sound case from an opaque named function call's
            # non-receiver arguments. Only a plain, non-operator call name is restricted.
            is_operator = call_name.startswith("<operator>.")
            for idx, oa in args_by_call.get(val, {}).items():
                if not is_operator and idx != 0 and call_name not in KNOWN_VALUE_DERIVING_CALLS:
                    continue  # do not chase an arbitrary non-receiver argument of an opaque
                              # call -- see KNOWN_VALUE_DERIVING_CALLS's own comment
                if oa["kind"] == "IDENTIFIER":
                    frontier.append(("name", oa["code"].strip(), hops + 1))
                elif oa["kind"] == "CALL":
                    frontier.append(("call", oa["node_id"], hops + 1))
    return None


# --- Upper-bound check detector -------------------------------------------------------------
# Confirmed real, necessary filter (see NAN_CAPABILITY_DESIGN.md Section 2): c2cpg mis-lexes
# unresolved C++ template angle brackets (`v8::Local<v8::Object> ret`) as
# `<operator>.greaterThan`/`<operator>.lessThan` CALLS -- a real, confirmed parser artifact,
# not a hypothetical risk. A comparison call is only treated as a real bound check when one of
# its own operands is an IDENTIFIER whose code EXACTLY matches a name the size-trace walk
# actually visited -- the spurious template-mislex operands (`v8::Local<v8::Object`, `<unknown>
# ret`) never match a real traced identifier name, so this filter rejects them structurally,
# not via a fragile blocklist.
COMPARISON_OPS = ("<operator>.greaterThan", "<operator>.greaterEqualsThan",
                  "<operator>.lessThan", "<operator>.lessEqualsThan")


def find_upper_bound_check(cpp, method_id, size_chain_names):
    for cid in cpp["calls_by_method"].get(method_id, ()):
        c = cpp["calls"][cid]
        if c["name"] not in COMPARISON_OPS:
            continue
        args = cpp["args_by_call"].get(cid, {})
        for a in args.values():
            if a["kind"] == "IDENTIFIER" and a["code"].strip() in size_chain_names:
                return {"comparison_call_id": cid, "operator": c["name"], "code": c["code"],
                       "line": c["line"], "matched_identifier": a["code"].strip()}
    return None


# --- CopyBuffer source-capacity resolver ----------------------------------------------------
def resolve_source_allocation(cpp, method_id, source_arg):
    """Returns {"resolved": True, "alloc_size_arg": {...}, "allocation_call_id": ...} when the
    SOURCE argument is a plain local identifier with a real, local `new T[K]`-shaped allocation
    site in the SAME method; else {"resolved": False, "reason": "..."}. A non-identifier source
    (a field/member/index-access chain -- confirmed real on node-snap7's own
    `self->areaMap[index].pBuffer` shape) has no local variable to search at all, so it is
    UNRESOLVED immediately -- never guessed at."""
    if source_arg is None:
        return {"resolved": False, "reason": "NO_SOURCE_ARGUMENT"}
    if source_arg["kind"] != "IDENTIFIER":
        return {"resolved": False,
                "reason": "SOURCE_NOT_A_SIMPLE_LOCAL_IDENTIFIER -- e.g. a struct/map field or "
                          "pointer chain with no local variable to trace an allocation for"}
    var_name = source_arg["code"].strip()
    for cid in cpp["calls_by_method"].get(method_id, ()):
        c = cpp["calls"][cid]
        if c["name"] != "<operator>.assignment":
            continue
        a = cpp["args_by_call"].get(cid, {})
        lhs, rhs = a.get(1), a.get(2)
        if not lhs or lhs["code"].strip() != var_name or not rhs or rhs["kind"] != "CALL":
            continue
        new_call = cpp["calls"].get(rhs["node_id"])
        if not new_call or new_call["name"] != "<operator>.new":
            continue
        # <operator>.new wraps <operator>.alloc as its own index-1 argument (confirmed real,
        # NAN_CAPABILITY_DESIGN.md Section 2); <operator>.alloc's own index-2 argument is the
        # real size operand (index-1 is the allocated TYPE, e.g. "char").
        new_args = cpp["args_by_call"].get(rhs["node_id"], {})
        inner = new_args.get(1)
        if not inner or inner["kind"] != "CALL":
            continue
        alloc_call = cpp["calls"].get(inner["node_id"])
        if not alloc_call or alloc_call["name"] != "<operator>.alloc":
            continue
        alloc_args = cpp["args_by_call"].get(inner["node_id"], {})
        alloc_size_arg = alloc_args.get(2)
        if alloc_size_arg is None:
            continue
        return {"resolved": True, "alloc_size_arg": alloc_size_arg,
                "allocation_call_id": rhs["node_id"]}
    return {"resolved": False, "reason": "NO_LOCAL_ALLOCATION_SITE_FOUND -- the source pointer "
                                          "is never locally allocated in this method (e.g. it "
                                          "comes from a function parameter, an out-parameter, "
                                          "or a native-library return)"}


def compare_capacity_to_length(alloc_size_arg, copy_size_arg):
    """Narrow, structural, disclosed comparison -- never a numeric proof. Returns "MATCHES"
    only on an EXACT same-identifier-name or same-literal-value match (capacity established
    safe by construction); "MISMATCH" only when both are directly comparable (IDENTIFIER or
    LITERAL) and clearly different; "INCONCLUSIVE" otherwise (e.g. either side is itself a
    CALL/expression this file does not evaluate) -- INCONCLUSIVE is treated as unresolved, the
    same as no allocation site found at all, never silently folded into either verdict."""
    if alloc_size_arg["kind"] == "IDENTIFIER" and copy_size_arg["kind"] == "IDENTIFIER":
        return "MATCHES" if alloc_size_arg["code"].strip() == copy_size_arg["code"].strip() \
            else "MISMATCH"
    if alloc_size_arg["kind"] == "LITERAL" and copy_size_arg["kind"] == "LITERAL":
        return "MATCHES" if alloc_size_arg["code"].strip() == copy_size_arg["code"].strip() \
            else "MISMATCH"
    if alloc_size_arg["kind"] in ("IDENTIFIER", "LITERAL") and \
       copy_size_arg["kind"] in ("IDENTIFIER", "LITERAL"):
        return "MISMATCH"  # one identifier, one literal -- structurally different by construction
    return "INCONCLUSIVE"


# --- JS-side call confirmation ---------------------------------------------------------------
def find_js_call_confirming_index(js, js_name, required_js_index):
    """Returns the first real JS call by that name supplying a real argument at
    `required_js_index` (1-based, index 0 reserved for the receiver -- confirmed real and
    necessary via this capability's own fixture: `info[N]` corresponds to JS schema index
    `N + 1`, same off-by-one FIX01I's own development caught for node-addon-api). Returns None
    if `js` facts are unavailable, no call by that name exists, or none supplies enough real
    arguments -- an explicit abstention (`NAN_JS_CALL_UNRESOLVED`), never treated as
    equivalent to a confirmed real call."""
    if js is None:
        return None
    for cid in js["calls_by_name"].get(js_name, ()):
        args = js["args_by_call"].get(cid, {})
        if required_js_index in args:
            return cid
    return None


NON_VULN_DISCLAIMER = (
    "STATIC CANDIDATE, not a vulnerability or CWE claim. This finding establishes: (1) the "
    "allocation length is demonstrably JS-argument-controlled via a real registration + "
    "info[N] chain + confirmed JS call; (2) no structural upper-bound check was found on that "
    "value before the acquisition call. It does NOT evaluate runtime reachability of any "
    "specific consequence. Two real, disclosed, structurally-grounded consequences are "
    "possible depending on the value supplied and the platform's available memory -- "
    "(a) node::Buffer::New/Copy internally rejects an oversized or failed allocation, and "
    ".ToLocalChecked() on that empty MaybeLocal triggers V8's own fatal-error path, "
    "terminating the process (a real denial-of-service shape, not a crash-safety guess -- see "
    "NAN_CAPABILITY_DESIGN.md Section 3, confirmed by reading nan.h's own source); "
    "(b) a successful allocation of attacker-influenced size with no detected application-"
    "level cap risks excessive memory consumption, and where the size is computed as a "
    "product of two JS-controlled factors (as in the ReadArea-shaped case), integer overflow "
    "could yield a SMALL allocated size while a later native call still writes the FULL "
    "uncapped amount -- a real, disclosed, but NOT independently verified-in-this-pass "
    "downstream write-mismatch risk; this file does not trace the downstream native write "
    "call to confirm it actually happens.")

NON_VULN_DISCLAIMER_COPY = (
    "STATIC CANDIDATE, not a vulnerability or CWE claim. This finding establishes: (1) the "
    "copy length is demonstrably JS-argument-controlled (same evidence chain as the NewBuffer "
    "contract); (2) a real, LOCAL allocation site for the source pointer was found in this "
    "same method whose own size is structurally different from the traced copy length (not "
    "merely 'unresolved' -- a genuine mismatch between a known capacity and an independent "
    "length). This is a real, disclosed OUT-OF-BOUNDS-READ SHAPE (Nan::CopyBuffer reads "
    "`size` bytes starting at `data`), not a confirmed OOB read -- this file does not evaluate "
    "whether the mismatch is actually reachable with a length exceeding the real allocated "
    "capacity, only that the two values are structurally independent.")


def compute_findings(cpp, js):
    """The full verdict loop, factored out of main() (NAN-REPLAY-TASK4) so a caller with
    already-loaded facts (e.g. a bundle replay using `load_js_raw_from_facts_json()` instead of
    `load_js_raw()`) can reuse the EXACT SAME logic main() uses -- never a second, drifting copy.
    Byte-for-byte the same code that lived inline in main() before this refactor; behavior
    verified unchanged via check_nan_integration.py's own 23 synthetic + real live-smoke
    controls, all still passing after this extraction. Returns
    (registrations, registration_audit, classification, findings)."""
    registrations, registration_audit = extract_registrations(cpp)
    js_name_by_function = {}
    for name, fids in registrations.items():
        for fid in fids:
            js_name_by_function.setdefault(fid, []).append(name)

    findings = []
    classification = defaultdict(int)

    for method_id, call_ids in cpp["calls_by_method"].items():
        for cid in call_ids:
            c = cpp["calls"][cid]
            for contract in CONTRACTS.values():
                cname = contract["contract_id"]
                if c["name"] != contract["acquisition_call"] or not _is_unresolved_shape(c["mfn"]):
                    continue
                classification[f"{cname}_NAME_MATCH_CANDIDATE"] += 1

                args = cpp["args_by_call"].get(cid, {})
                arity = len(args)
                size_idx = contract["size_arg_index_by_arity"].get(arity)
                base_evidence = {"method_id": method_id, "method_name": cpp["methods"].get(
                    method_id, {}).get("name"), "acquisition_call_id": cid,
                    "acquisition_code": c["code"], "acquisition_line": c["line"],
                    "contract_id": cname, "contract_citation": contract["citation"],
                    "arity": arity}
                if size_idx is None:
                    classification[f"{cname}_ARITY_UNRECOGNIZED"] += 1
                    findings.append({**base_evidence, "verdict": f"{cname}_ARITY_UNRECOGNIZED",
                                     "reason": f"arity {arity} is not a recognized real "
                                               f"{contract['acquisition_call']} overload"})
                    continue
                size_arg = args.get(size_idx)
                if size_arg is None:
                    classification[f"{cname}_ARITY_UNRECOGNIZED"] += 1
                    continue
                if size_arg["kind"] == "LITERAL":
                    classification[f"{cname}_SIZE_LITERAL_NOT_APPLICABLE"] += 1
                    continue

                trace = find_js_index_source_for_value(cpp, method_id, size_arg)
                if trace is None:
                    classification[f"{cname}_SOURCE_BOUNDARY_UNRESOLVED"] += 1
                    findings.append({**base_evidence,
                                     "verdict": f"{cname}_SOURCE_BOUNDARY_UNRESOLVED",
                                     "reason": "no real info[N] source found reachable from "
                                               "the size argument -- not promoted"})
                    continue

                js_names = js_name_by_function.get(method_id, [])
                if not js_names:
                    classification[f"{cname}_NOT_JS_REGISTERED"] += 1
                    findings.append({**base_evidence, "verdict": f"{cname}_NOT_JS_REGISTERED",
                                     "reason": "a real info[N] source was found, but this "
                                               "method is never registered via "
                                               "SetPrototypeMethod/SetMethod -- not JS-"
                                               "reachable, not promoted",
                                     "callback_info_index": trace["callback_info_index"]})
                    continue

                required_js_index = trace["callback_info_index"] + 1
                js_call_id = None
                js_name_used = None
                for jn in js_names:
                    hit = find_js_call_confirming_index(js, jn, required_js_index)
                    if hit is not None:
                        js_call_id, js_name_used = hit, jn
                        break
                if js_call_id is None:
                    # No confirmed real call supplies the required argument. Before
                    # abstaining, check the WEAKER but still real "whole native module
                    # unconditionally re-exported" tier (see is_native_module_directly_exported's
                    # own docstring -- found and fixed via a real, direct challenge to
                    # node-snap7's own Upload/FullUpload abstentions, confirmed against real
                    # facts, not conceded on principle): once the registration's ENCLOSING
                    # module is shown to unconditionally re-export its whole native binding,
                    # a registered method is public API regardless of whether the package's
                    # own bundled JS ever calls it -- registration + real info[N] dataflow
                    # already establishes the JS boundary in that case.
                    if is_native_module_directly_exported(js):
                        js_evidence = {"js_call_id": None, "js_name": js_names[0],
                                       "callback_info_index": trace["callback_info_index"],
                                       "js_argument_index": required_js_index,
                                       "js_linkage_shape": trace["shape"],
                                       "source_boundary": "JS_ARGUMENT_CONTROLLED",
                                       "js_reachability_tier": "exported_registration",
                                       "js_reachability_evidence": (
                                           "no specific real JS call observed supplying "
                                           f"argument {required_js_index}, but the package's "
                                           "own JS entry point unconditionally re-exports its "
                                           "whole native binding (module.exports = require("
                                           "<loader>)(...) shape) -- registration alone "
                                           "establishes public reachability with an "
                                           "attacker-chosen argument at this index; weaker "
                                           "than a confirmed call, still real and disclosed "
                                           "as such, never silently equated with it")}
                    else:
                        classification[f"{cname}_JS_CALL_UNRESOLVED"] += 1
                        findings.append({**base_evidence,
                                         "verdict": f"{cname}_JS_CALL_UNRESOLVED",
                                         "reason": "real registration exists (js name(s): "
                                                   f"{js_names}), but no confirmed real JS "
                                                   f"call supplies an argument at the "
                                                   f"required index {required_js_index} "
                                                   f"(info[{trace['callback_info_index']}]), "
                                                   "and the package does not unconditionally "
                                                   "re-export its whole native binding either",
                                         "callback_info_index": trace["callback_info_index"],
                                         "js_names": js_names})
                        continue
                else:
                    js_evidence = {"js_call_id": js_call_id, "js_name": js_name_used,
                                   "callback_info_index": trace["callback_info_index"],
                                   "js_argument_index": required_js_index,
                                   "js_linkage_shape": trace["shape"],
                                   "source_boundary": "JS_ARGUMENT_CONTROLLED",
                                   "js_reachability_tier": "confirmed_call"}

                if cname == "NAN_NEWBUFFER_UNBOUNDED_ALLOCATION":
                    bound = find_upper_bound_check(cpp, method_id, trace["visited_names"])
                    if bound is not None:
                        classification[f"{cname}_UPPER_BOUND_CHECK_PRESENT"] += 1
                        findings.append({**base_evidence, **js_evidence,
                                         "verdict": f"{cname}_UPPER_BOUND_CHECK_PRESENT",
                                         "reason": "JS-argument-controlled, but a structural "
                                                   "comparison against a traced identifier was "
                                                   "found before the acquisition call -- "
                                                   "correctly NOT promoted (this does not "
                                                   "evaluate whether the bound is SUFFICIENT, "
                                                   "only that one exists)",
                                         "bound_check_evidence": bound})
                        continue
                    classification[cname] += 1
                    findings.append({**base_evidence, **js_evidence, "verdict": cname,
                                     "evidence_note": NON_VULN_DISCLAIMER})
                else:  # NAN_COPYBUFFER_SOURCE_CAPACITY
                    source_idx = contract["source_arg_index_by_arity"][arity]
                    source_arg = args.get(source_idx)
                    cap = resolve_source_allocation(cpp, method_id, source_arg)
                    if not cap["resolved"]:
                        classification[f"{cname}_UNRESOLVED"] += 1
                        findings.append({**base_evidence, **js_evidence,
                                         "verdict": f"{cname}_UNRESOLVED",
                                         "reason": cap["reason"],
                                         "evidence_note": "length is JS-argument-controlled, "
                                                           "but source capacity could not be "
                                                           "structurally established -- NOT "
                                                           "inferred as an OOB read"})
                        continue
                    cmp_result = compare_capacity_to_length(cap["alloc_size_arg"], size_arg)
                    if cmp_result == "MATCHES":
                        classification[f"{cname}_CAPACITY_MATCHES_ALLOCATION"] += 1
                        continue
                    if cmp_result == "INCONCLUSIVE":
                        classification[f"{cname}_UNRESOLVED"] += 1
                        findings.append({**base_evidence, **js_evidence,
                                         "verdict": f"{cname}_UNRESOLVED",
                                         "reason": "COMPARISON_INCONCLUSIVE -- allocation size "
                                                   "and copy length are not both directly "
                                                   "comparable (identifier/literal) values",
                                         "allocation_call_id": cap["allocation_call_id"]})
                        continue
                    classification[cname] += 1
                    findings.append({**base_evidence, **js_evidence, "verdict": cname,
                                     "allocation_call_id": cap["allocation_call_id"],
                                     "alloc_size_arg_code": cap["alloc_size_arg"]["code"],
                                     "copy_size_arg_code": size_arg["code"],
                                     "evidence_note": NON_VULN_DISCLAIMER_COPY})

    return registrations, registration_audit, dict(classification), findings


def main():
    cpp_raw_dir, js_raw_dir, outp = sys.argv[1], sys.argv[2], sys.argv[3]
    cpp = load_cpp_raw(cpp_raw_dir)
    js = load_js_raw(js_raw_dir)
    registrations, registration_audit, classification, findings = compute_findings(cpp, js)

    json.dump({"schema": "resource-guard-verdict-nan/0.1",
               "registrations": {k: v for k, v in registrations.items()},
               "registration_audit": registration_audit,
               "classification": classification,
               "findings": findings}, open(outp, "w"), indent=1, sort_keys=True)
    print(f"classification: {classification}")
    print(f"findings: {len(findings)}")


if __name__ == "__main__":
    main()
