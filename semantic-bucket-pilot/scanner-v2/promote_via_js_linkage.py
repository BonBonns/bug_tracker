#!/usr/bin/env python3
"""R06/FIX01I INTEGRATION (item 3) -- promotes a R06 finding's `SOURCE_BOUNDARY_UNRESOLVED`
(or untraced, `source_boundary_evidence: null`) evidence to attacker-controlled ONLY when a
REAL JS argument demonstrably reaches the traced native size, established by combining:

  1. R06's own real facts (`resource_guard_verdict_r06.py`, `claude/r06-precision-fix`,
     UNCHANGED -- imported, not modified).
  2. FIX01I's own real cross-language call linking (`link_napi_facts.py`,
     `claude/crosslang-linker-fix`, UNCHANGED -- imported, not modified).
  3. A NEW real, structural check this file adds: does the traced native value actually
     originate from `info[N]` (a `Napi::CallbackInfo` index access -- N-API's own real,
     only mechanism for a native function to read a JS-caller-supplied argument) via an
     OUT-PARAMETER helper call (`get_u64(env, info[N], "name", &var)`-shaped: one argument
     is the `info[N]` index access, another is `&var` where `var` is the traced identifier)?
     This is a REAL, additional dataflow shape neither R06's own `backward_attacker_trace`
     nor FIX01I's own call-linking models -- found by direct, real investigation of Cartesi's
     own cached raw facts (`/tmp/cartesi_raw`) during this integration's own development (see
     R06_FIX01I_INTEGRATION.md for the full account): Cartesi's real `length` value comes
     from exactly `get_u64(env, info[1], "length", &length)`, which is why R06's own identifier/
     assignment-RHS walk alone traces it to `None` -- not a bug in that walk, a real, different
     dataflow shape it was never designed to follow.

Both frozen branches this integrates are kept COMPLETELY UNTOUCHED -- everything here is NEW
code, on the isolated `claude/r06-fix01i-integration` branch only, importing (never editing)
`resource_guard_verdict_r06.py` and `link_napi_facts.py` as-is.

REGISTRATION SCOPE (real, disclosed extension, also new code, never edited into the frozen
linker): `link_napi_facts.py`'s own `extract_napi_bindings()` only recognizes the
`exports.Set(Napi::String::New(env,"X"), Napi::Function::New(env, Fn))` idiom. Cartesi's own
real registration idiom is DIFFERENT: `Napi::ObjectWrap<Machine>::DefineClass(env, "Machine",
{ InstanceMethod<&Machine::ReadMemory>("readMemory"), ... })` -- confirmed real via direct
inspection of Cartesi's own cpp_raw facts. `extract_instancemethod_bindings()` below adds
real, structural (never a substring/loose match) recognition for exactly this idiom, unioned
with `extract_napi_bindings()`'s own table, via `link_calls_extended()` -- a NEW function that
reuses `link_napi_facts.py`'s own real `JsCallIndex`/`native_binding_receiver_evidence`/
`OFFSET`, replicating its `main()`'s per-call linking loop rather than editing that file.

REAL, HONEST RESULT (see R06_FIX01I_INTEGRATION.md for the full account, not glossed over):
Cartesi's own currently-PUBLISHED npm package (`@cartesi/machine@1.0.0-alpha.1`) ships a
WASM/bundled `dist/index.cjs` as its real JS entry point -- direct inspection of its real,
captured JS facts (`/tmp/smoke_test_cartesi/work/js_raw`) found ZERO real JS calls naming
`readMemory` or any other InstanceMethod-registered name anywhere in the package. The
REGISTRATION half of this integration (structural DefineClass/InstanceMethod recognition) is
real and does find Cartesi's own real registrations; the JS-CALL-SITE half is NOT established
by Cartesi's own real, currently-available facts -- so a REAL run against Cartesi's real data
does NOT promote its findings, which is the CORRECT, non-fabricated outcome, not a bug. The
full promotion chain (registration + real out-parameter/info[N] structural match + real JS
call supplying a real argument at the matching index) is instead proven end-to-end against a
DISCLOSED SYNTHETIC control built to Cartesi's own exact real C++ shape
(`study/r06_fix01i_integration/controls/cartesi_shape_positive/`) -- clearly labeled as
synthetic, never presented as a real Cartesi corpus finding.
"""
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from resource_guard_verdict_r06 import dec, rows, _is_js_callback_origin_type  # noqa: E402

_POLYGLOT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(_HERE)), "tchecker-research-complete",
    "portable-engine-full-review-package", "frontends", "polyglot")
sys.path.insert(0, _POLYGLOT_DIR)
from link_napi_facts import (  # noqa: E402
    extract_napi_bindings, JsCallIndex, native_binding_receiver_evidence, offset_ids, OFFSET)

INSTANCE_METHOD_RE = re.compile(r"InstanceMethod\s*<\s*&\s*([A-Za-z_]\w*)::([A-Za-z_]\w*)\s*>\s*\(")


# --- Registration extension: DefineClass/InstanceMethod idiom (real, new, never edited into
# the frozen link_napi_facts.py -- see module docstring). ---------------------------------
def extract_instancemethod_bindings(cpp):
    """binding name -> (function_id, full_name), for the Napi::ObjectWrap<Class>::DefineClass
    / InstanceMethod<&Class::Method>("jsName") idiom. Real, structural, but a DIFFERENT and
    somewhat WEAKER guarantee than extract_napi_bindings()'s own AST-verified single-candidate
    match: the class/method reference is only available as VERBATIM SOURCE TEXT inside the
    InstanceMethod call's own `code` field (`InstanceMethod<&Machine::ReadMemory>(...)`) --
    Joern's own C++ frontend does not expose a template argument as a structured node -- so
    this parses that text with INSTANCE_METHOD_RE (a real, disclosed, narrow, non-greedy
    pattern; never a broad substring search) rather than reading a resolved id directly.
    Confirmed real and necessary via direct inspection of Cartesi's own real facts: this
    shape is real, not synthetic. Still requires an EXACT, single-candidate match on the
    real function's own `Class.Method`-prefixed `full_name` (Joern's own dot-qualified
    convention, confirmed real) -- never a guess when zero or multiple real functions match."""
    fns_by_full_name_prefix = {}
    for f in cpp["functions"]:
        if f["is_external"]:
            continue
        prefix = f["full_name"].split(":", 1)[0]  # "Class.Method" part, before the signature
        fns_by_full_name_prefix.setdefault(prefix, []).append(f)

    table, audit = {}, []
    for c in cpp["calls"]:
        if c["name"] != "InstanceMethod":
            continue
        m = INSTANCE_METHOD_RE.search(c.get("code") or "")
        if not m:
            audit.append({"call": c["id"], "skipped": "InstanceMethod call, but code does "
                                                         "not match the real <&Class::Method> shape"})
            continue
        class_name, method_name = m.group(1), m.group(2)
        # Real schema note: cpp_facts.json's own `arguments` is a real, ORDERED list (0-based
        # `index`, confirmed real -- InstanceMethod's own single string-name argument is at
        # list position 0, NOT 1) -- positional access here matches extract_napi_bindings()'s
        # own established convention for this same normalized json shape (`c['arguments'][0]`),
        # never the raw-TSV 1-based dict-by-index convention resource_guard_verdict_r06.py
        # uses for a DIFFERENT (unnormalized) fact format.
        if not c["arguments"] or c["arguments"][0]["kind"] != "LITERAL":
            audit.append({"call": c["id"], "skipped": "no real string-literal JS name argument"})
            continue
        js_name = (c["arguments"][0].get("code") or "").strip().strip('"')
        qualified = f"{class_name}.{method_name}"
        cands = fns_by_full_name_prefix.get(qualified, [])
        if len(cands) != 1:
            audit.append({"call": c["id"], "class": class_name, "method": method_name,
                          "skipped": f"{len(cands)} candidate functions for {qualified!r} "
                                     "(need exactly 1)"})
            continue
        table[js_name] = (cands[0]["id"], cands[0]["full_name"])
        audit.append({"call": c["id"], "name": js_name, "class": class_name,
                      "method": method_name, "linked_function_id": cands[0]["id"]})
    return table, audit


def link_calls_extended(js, cpp, js_receiver="bindings"):
    """Real replication of link_napi_facts.py's own main()'s per-call linking LOOP (not its
    CLI/file-I/O), reusing its own real, unmodified extract_napi_bindings/JsCallIndex/
    native_binding_receiver_evidence/OFFSET -- the ONLY new logic is unioning
    extract_napi_bindings()'s table with extract_instancemethod_bindings()'s own. Returns
    (table, linked, unlinked) -- same real shapes link_napi_facts.py's own main() produces."""
    table, _audit1 = extract_napi_bindings(cpp)
    table2, _audit2 = extract_instancemethod_bindings(cpp)
    for name, entry in table2.items():
        table.setdefault(name, entry)  # exports.Set idiom wins on a real name collision (rare)

    js_index = JsCallIndex(js)
    linked, unlinked = [], []
    for c in js["calls"]:
        receiver_matched, tier, _reason = native_binding_receiver_evidence(c, js_index)
        is_candidate = ((c.get("receiver_name") == js_receiver or receiver_matched)
                         and c["resolution"] != "EXACT")
        if not is_candidate:
            continue
        if c["name"] in table:
            fid, full = table[c["name"]]
            linked.append({"js_call": c["id"], "name": c["name"], "cpp_function_id": fid + OFFSET,
                           "js_arguments": c.get("arguments", []),
                           "evidence_tier": tier or "js_receiver_name"})
        else:
            unlinked.append({"js_call": c["id"], "name": c["name"],
                             "reason": "no mechanically exact registration"})
    return table, linked, unlinked


# --- The real, structural CallbackInfo-index + out-parameter check -----------------------
def find_callback_info_index_source(raw_dir, method_id, var_name):
    """Real, structural search (NOT a re-run of R06's own identifier/assignment-RHS walk --
    a genuinely different dataflow shape, see module docstring): within `method_id`'s own
    real calls, finds a call C such that (a) one of C's own arguments is a real
    `<operator>.indirectIndexAccess` call on an IDENTIFIER referring to a real
    `Napi::CallbackInfo`-typed parameter of `method_id`, with a real LITERAL integer index N
    (i.e. `info[N]`), AND (b) another of C's own arguments is a real `<operator>.addressOf`
    call on an IDENTIFIER whose own code is exactly `var_name` (i.e. `&var_name`). Returns
    `{"helper_call_id", "helper_call_name", "js_argument_index": N}` on a real match, else
    `None`. Requires BOTH conditions on the SAME call -- confirmed real and necessary via
    Cartesi's own actual `get_u64(env, info[1], "length", &length)` shape."""
    params_by_method = {}
    param_types_by_method = {}
    for r in rows(f"{raw_dir}/parameters.tsv", 7):
        owner = int(r[1])
        pname = dec(r[3])
        params_by_method.setdefault(owner, set()).add(pname)
        param_types_by_method.setdefault(owner, {})[pname] = dec(r[5])

    callback_info_params = {
        pname for pname, ptype in param_types_by_method.get(method_id, {}).items()
        if _is_js_callback_origin_type(ptype)
    }
    if not callback_info_params:
        return None

    calls = {}
    calls_by_method = {}
    for r in rows(f"{raw_dir}/calls.tsv", 11):
        cid, owner = int(r[0]), int(r[1])
        calls[cid] = {"id": cid, "owner": owner, "name": dec(r[2])}
        calls_by_method.setdefault(owner, []).append(cid)

    args_by_call = {}
    for r in rows(f"{raw_dir}/arguments.tsv", 8):
        call_id, idx = int(r[1]), int(r[2])
        args_by_call.setdefault(call_id, {})[idx] = {
            "kind": dec(r[3]), "code": dec(r[4]), "node_id": int(r[0])}

    def is_info_index_access(call_id):
        c = calls.get(call_id)
        if c is None or c["name"] != "<operator>.indirectIndexAccess":
            return None
        a = args_by_call.get(call_id, {})
        base, idx = a.get(1), a.get(2)
        if not base or base["kind"] != "IDENTIFIER" or base["code"] not in callback_info_params:
            return None
        if not idx or idx["kind"] != "LITERAL":
            return None
        try:
            return int(idx["code"])
        except ValueError:
            return None

    def is_address_of(call_id, name):
        c = calls.get(call_id)
        if c is None or c["name"] != "<operator>.addressOf":
            return False
        a = args_by_call.get(call_id, {}).get(1)
        return bool(a and a["kind"] == "IDENTIFIER" and a["code"] == name)

    for cid in calls_by_method.get(method_id, ()):
        args = args_by_call.get(cid, {})
        found_index = None
        found_addr = False
        for a in args.values():
            if a["kind"] != "CALL":
                continue
            n = is_info_index_access(a["node_id"])
            if n is not None:
                found_index = n
            if is_address_of(a["node_id"], var_name):
                found_addr = True
        if found_index is not None and found_addr:
            return {"helper_call_id": cid, "helper_call_name": calls[cid]["name"],
                    "js_argument_index": found_index}
    return None


def find_callback_info_index_source_for_acquisition(raw_dir, method_id, acquisition_call_id,
                                                       size_arg_index=2, depth=8):
    """Real, bounded walk from the acquisition call's own SIZE argument (index
    `size_arg_index`, `2` for every real contract in this project -- `env` is 1, `size` is 2,
    confirmed via `resource_contracts_r04.py`/`resource_contracts_r05.py`'s own real
    `size_arg_index` field, consistent across every entry), checking
    `find_callback_info_index_source` at EVERY identifier name the walk visits -- not only
    R06's own `backward_attacker_trace`'s FINAL terminal name. This matters in practice, not
    just in theory: Cartesi's own real chain is `Buffer::New(env, static_cast<size_t>(length))`
    -> `static_cast`'s own arg is IDENTIFIER `length` -> `length`'s own default assignment
    (`length = 0`, a LITERAL) is where R06's OWN walk silently dead-ends (a LITERAL RHS isn't
    added to that walk's frontier at all) -- but `length` ITSELF, visited along the way, IS
    the real variable `get_u64(env, info[1], "length", &length)` populates. A walk that only
    checked the FINAL name would miss this entirely."""
    calls = {}
    calls_by_method = {}
    for r in rows(f"{raw_dir}/calls.tsv", 11):
        cid, owner = int(r[0]), int(r[1])
        calls[cid] = {"id": cid, "owner": owner, "name": dec(r[2])}
        calls_by_method.setdefault(owner, []).append(cid)

    args_by_call = {}
    for r in rows(f"{raw_dir}/arguments.tsv", 8):
        call_id, idx = int(r[1]), int(r[2])
        args_by_call.setdefault(call_id, {})[idx] = {
            "kind": dec(r[3]), "code": dec(r[4]), "node_id": int(r[0])}

    size_arg = args_by_call.get(acquisition_call_id, {}).get(size_arg_index)
    if size_arg is None:
        return None

    seen_names, seen_calls = set(), set()
    frontier = ([("call", size_arg["node_id"], 0)] if size_arg["kind"] == "CALL"
                else [("name", size_arg["code"].strip(), 0)])
    while frontier:
        kind, val, hops = frontier.pop(0)
        if hops > depth:
            continue
        if kind == "name":
            if val in seen_names:
                continue
            seen_names.add(val)
            hit = find_callback_info_index_source(raw_dir, method_id, val)
            if hit is not None:
                return hit
            for cid in calls_by_method.get(method_id, ()):
                c = calls[cid]
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
            for oa in args_by_call.get(val, {}).values():
                if oa["kind"] == "IDENTIFIER":
                    frontier.append(("name", oa["code"].strip(), hops + 1))
                elif oa["kind"] == "CALL":
                    frontier.append(("call", oa["node_id"], hops + 1))
    return None


# --- Promotion: combine everything above ---------------------------------------------------
def promote_findings(r06_findings, raw_dir, linked_calls):
    """For every R06 finding whose own `source_boundary_evidence` does NOT already establish
    `attacker_controlled: True` (i.e. `SOURCE_BOUNDARY_UNRESOLVED` or untraced/`None`),
    checks whether it can be promoted via REAL evidence: (1)
    `find_callback_info_index_source_for_acquisition` walks the finding's own real
    `acquisition_call_id` (the SAME starting point R06's own `backward_attacker_trace` used,
    re-derived directly from raw facts rather than re-implementing that walk's own contract-
    matching logic) looking for a real `info[N]`-via-out-parameter source at ANY identifier
    name visited along the way -- not only R06's own walk's final terminal name, which is
    exactly what let Cartesi's own real `length = 0` default-initializer silently dead-end
    that walk (see `find_callback_info_index_source_for_acquisition`'s own docstring); (2) a
    REAL entry in `linked_calls` (from `link_calls_extended`) whose `cpp_function_id - OFFSET`
    equals this finding's own `method_id`; (3) that linked JS call's own real `js_arguments`
    includes a real argument at index `js_argument_index` (i.e. the JS caller actually
    supplied that many arguments -- `info[N]` is populated with a REAL JS value, not
    undefined). All three must hold; each finding's own promotion (or non-promotion, with the
    real reason) is returned, never silently dropped."""
    linked_by_method = {}
    for l in linked_calls:
        linked_by_method.setdefault(l["cpp_function_id"] - OFFSET, []).append(l)

    results = []
    for finding in r06_findings:
        sbe = finding.get("source_boundary_evidence") or {}
        if sbe.get("attacker_controlled") is True:
            results.append({"finding": finding, "promoted": False,
                            "reason": "already attacker_controlled -- nothing to promote"})
            continue
        method_id = finding["method_id"]
        src = find_callback_info_index_source_for_acquisition(
            raw_dir, method_id, finding["acquisition_call_id"])
        if src is None:
            results.append({"finding": finding, "promoted": False,
                            "reason": f"no real info[N]-via-out-parameter source found "
                                      f"reachable from acquisition_call_id "
                                      f"{finding['acquisition_call_id']} in method {method_id}"})
            continue
        candidates = linked_by_method.get(method_id, [])
        if not candidates:
            results.append({"finding": finding, "promoted": False,
                            "reason": "real out-parameter source found, but NO real FIX01I "
                                      "registration/link exists for this method -- "
                                      "e.g. a libcurl-invoked callback, never JS-reachable"})
            continue
        # Real index-convention conversion, confirmed via direct inspection of Cartesi's own
        # real js_facts_adapted.json: a JS call's own `arguments` list is 1-based with index 0
        # reserved for the receiver/base (`require(...)` itself shows index 0 = "this", index
        # 1 = the real first argument) -- so C++'s own `info[N]` (0-based: `info[0]` is the
        # JS caller's FIRST real argument) corresponds to JS schema index `N + 1`, never `N`
        # directly. Getting this wrong would let a call supplying only `info[N]`'s own real
        # first N JS arguments (but NOT the N+1'th) be mismatched against a real argument that
        # is actually one position off -- confirmed as a real, not theoretical, bug during this
        # integration's own development (caught by a dedicated regression, see
        # tests/test_promote_via_js_linkage.py).
        required_js_index = src["js_argument_index"] + 1
        promoted_via = None
        for l in candidates:
            js_args = {a.get("index"): a for a in l.get("js_arguments", [])}
            if required_js_index in js_args:
                promoted_via = l
                break
        if promoted_via is None:
            results.append({"finding": finding, "promoted": False,
                            "reason": f"real JS linkage exists, but no linked call supplies a "
                                      f"real argument at index {required_js_index} "
                                      f"(info[{src['js_argument_index']}])"})
            continue
        results.append({
            "finding": finding, "promoted": True,
            "reason": "JS_ARGUMENT_VIA_CALLBACKINFO_INDEX",
            "evidence": {
                "js_call_id": promoted_via["js_call"],
                "js_call_name": promoted_via["name"],
                "callback_info_index": src["js_argument_index"],
                "js_argument_index": required_js_index,
                "helper_call_id": src["helper_call_id"],
                "helper_call_name": src["helper_call_name"],
            },
        })
    return results
