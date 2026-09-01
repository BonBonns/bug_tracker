#!/usr/bin/env python3
"""REACH-TIER-R01 (task #32): tiered JS/native reachability classification for LOCK_BALANCE,
PROTECTED_FIELD, and every OOB_* property's own findings/candidates.

WHY THIS IS SEPARATE FROM RESOURCE GUARD'S OWN REACHABILITY WORK: `promote_via_js_linkage.py`
(tasks #21/#22) already answers a NARROWER, Resource-Guard-specific question -- "is THIS
finding's own traced size ATTACKER-CONTROLLED", via a real `info[N]`-via-out-parameter dataflow
chase that only makes sense for R04/R05's own acquisition-call model. LOCK_BALANCE,
PROTECTED_FIELD, and the OOB_* properties ask a DIFFERENT, more basic question that R04/R05
never needed to ask on its own: is the native FUNCTION the finding sits inside even reachable
from this package's own bundled JS at all -- independent of whether any particular argument is
attacker-controlled. This module answers exactly that, tiered rather than binary, and does not
touch R04/R05's own reachability fields.

FIVE REAL TIERS, never a guess between them:
  TIER_JS_CALL_PROVEN          -- the enclosing function is registered as a real N-API binding
                                   AND a real call in this package's OWN bundled JS resolves to
                                   it (`native_binding_receiver_evidence`, reused verbatim from
                                   `link_napi_facts.py` -- the same real dominance/closure-
                                   capture proof machinery FIX01G-I built).
  TIER_REGISTERED_NOT_JS_CALLED -- the function IS a real registered export (so an external
                                   caller of the addon COULD invoke it by name), but no real call
                                   in this package's own bundled JS was found to reach it. Not
                                   proof of unreachability -- a consumer of the package could
                                   still call it directly -- only proof this package's own JS
                                   doesn't demonstrate the reach itself.
  TIER_TRANSITIVELY_CALLED_FROM_REGISTERED (task #34's own rejection-funnel analysis, reopening
                                   this module's own previously-disclosed scope limit below) --
                                   the function is NOT itself registered, but a real, CLEAN
                                   native call-graph path exists from some registered export to
                                   it, walked over `cpp['calls']`'s own already-resolved
                                   `candidate_target_ids` edges. "Clean" is load-bearing: an edge
                                   is used ONLY when its own call resolves to EXACTLY ONE real
                                   target id -- confirmed real and NOT vanishingly rare (6 of
                                   508,350 real calls sampled across 20 corpus packages carry
                                   MORE than one candidate_target_ids entry, e.g. a virtual
                                   dispatch through several real derived-class overrides) --
                                   never a guess among several candidates, per direct
                                   instruction ("promote only if every edge resolves by node
                                   identity"). The real path (every hop's own caller/callee
                                   id+name and the real call site) is attached as
                                   `reachability_evidence` -- never asserted without it.
  TIER_INTERNAL_UNREGISTERED    -- the function is not a registered export under any real
                                   registration idiom this module recognizes, AND no clean
                                   transitive call-graph path from a registered export reaches
                                   it either (a genuinely ambiguous-only path, per the tier
                                   above, does NOT count -- it stays here). Real, but the
                                   WEAKEST tier: a bug here is only reachable if some OTHER,
                                   registered function calls it through a path this module could
                                   not cleanly resolve, or a path that genuinely doesn't exist
                                   in this package's own real call graph -- honest scope limit,
                                   not a claim of unreachability, exactly as decodevv_add's own
                                   nested-index case was left explicitly unsupported in task #44
                                   rather than silently flattened.
  REACHABILITY_UNRESOLVED       -- the JS or C++ facts needed to decide are themselves absent or
                                   empty (fails closed, never guesses; the same code/label
                                   `resource_guard_verdict_r06.py` already established).

TASK #32 REOPENED (task #34's own rejection-funnel analysis found: staged_enablement.py's
allowlist only ever recognized the first two tiers above, leaving three tiers -- transitive
call, callback/worker, module-load -- this module's OWN earlier docstring had already disclosed
as an honest, un-implemented scope limit, not a closed question). Direct instruction on how to
close it: validate the transitive-call tier structurally (every edge single-target-resolved,
per direct instruction) and promote ONLY it into staged_enablement.py's own allowlist by exact
name -- never by loosening its "any non-internal tier" logic into something broader. The
callback/worker and module-load heuristics (`study/task34_replay/reachability_deep_dive.py`'s
own `CALLBACK_OR_WORKER_HEURISTIC`/`MODULE_LOAD_EXECUTION_HEURISTIC` buckets) stay OUT of this
module and OUT of `staged_enablement.py`'s allowlist -- explicitly deferred, per direct
instruction, pending their own dedicated positive/negative/ambiguity controls, not built here.

THREE REAL REGISTRATION IDIOMS, unioned (never one substituting for another):
  1. `exports.Set(Napi::String::New(env,"X"), Napi::Function::New(env, Fn))` -- reused verbatim
     via `link_napi_facts.extract_napi_bindings` (the frozen, gated FIX01I linker).
  2. `Napi::ObjectWrap<Class>::DefineClass(env, "Class", { InstanceMethod<&Class::Method>("js
     Name") })` -- `extract_instancemethod_bindings()` below is a SELF-CONTAINED port of the
     same real, structural (never substring) recognition `promote_via_js_linkage.py` (task #22)
     already built and verified against Cartesi's own real facts -- ported here rather than
     imported because that file's own top-level import of `resource_guard_verdict_r06` (task
     #41, not yet merged into this lineage) would otherwise be dragged in for no reason; this
     copy needs and uses NOTHING from that module (confirmed: only `cpp['functions']`/
     `cpp['calls']`, no raw-TSV `dec`/`rows` helpers).
  3. `Nan::SetPrototypeMethod(tpl, "name", Fn)` / `Nan::Export(target, "name", Fn)` --
     `extract_nan_bindings()` below, added AFTER discovering the first real-corpus smoke test
     of this module (against re2's own real facts, from the overnight-diagnostic-100 run's own
     evidence bundle) found re2 registers ALL of its methods (`test`, `exec`, `match`, `replace`,
     `search`, `split`, `toString`, `getUtf8Length`, `getUtf16Length`) via NAN -- the older,
     still heavily-used native-addon binding library that predates N-API -- and ZERO via either
     idiom above. Without this third idiom, EVERY real NAN-based native function would have been
     wrongly bucketed into the weakest tier (TIER_INTERNAL_UNREGISTERED) purely because this
     module didn't yet recognize its real registration call, not because it truly isn't exported
     -- confirmed as a real, not theoretical, gap task #25's own contract-family prevalence study
     already flagged NAN as one of the dominant binding families in this corpus. Structural match
     (never a substring/regex guess): the call's own name is `SetPrototypeMethod` or `Export`,
     it has EXACTLY 3 real arguments, argument[1] is a real LITERAL string and argument[2] is a
     real METHOD_REF whose own `code` is the bare function name -- shape confirmed directly
     against re2's own real facts (10 real `SetPrototypeMethod` calls + 2 real `Export` calls,
     every one matching this exact shape). `Nan::SetMethod` (the same family's own static-
     function variant) is a known, documented NAN API call but was NOT observed in this
     project's own real corpus data during this module's development -- deliberately left
     unrecognized here rather than guessed at; a real future sighting should add it the same
     way, not be assumed now.

Deliberately does NOT decide reportability or applicability -- provenance.py's own formula
(task #35) remains the sole authority on that question; this module only classifies and attaches
evidence.
"""
import os
import re
import sys
from collections import deque

_HERE = os.path.dirname(os.path.abspath(__file__))
_POLYGLOT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(_HERE)), "tchecker-research-complete",
    "portable-engine-full-review-package", "frontends", "polyglot")
sys.path.insert(0, _POLYGLOT_DIR)
from link_napi_facts import extract_napi_bindings, JsCallIndex, native_binding_receiver_evidence  # noqa: E402

TIER_JS_CALL_PROVEN = "TIER_JS_CALL_PROVEN"
TIER_REGISTERED_NOT_JS_CALLED = "TIER_REGISTERED_NOT_JS_CALLED"
TIER_TRANSITIVELY_CALLED_FROM_REGISTERED = "TIER_TRANSITIVELY_CALLED_FROM_REGISTERED"
TIER_INTERNAL_UNREGISTERED = "TIER_INTERNAL_UNREGISTERED"
REACHABILITY_UNRESOLVED = "REACHABILITY_UNRESOLVED"

# Real preference order among native_binding_receiver_evidence's own real tiers, strongest
# first -- used only to pick which linked call is reported as the SAMPLE evidence when more
# than one real JS call reaches the same function; every tier here is already a real, gated
# proof (never a guess), so this is a reporting choice, not a soundness one.
_EVIDENCE_TIER_RANK = {"dominance_proven": 0, "closure_capture_proven": 1, "build_path": 2,
                        "fallback_marker_regex": 3, "js_receiver_name": 4}

_INSTANCE_METHOD_RE = re.compile(r"InstanceMethod\s*<\s*&\s*([A-Za-z_]\w*)::([A-Za-z_]\w*)\s*>\s*\(")


def extract_instancemethod_bindings(cpp):
    """binding name -> (function_id, full_name), for the Napi::ObjectWrap<Class>::DefineClass /
    InstanceMethod<&Class::Method>("jsName") idiom. Self-contained port of
    `promote_via_js_linkage.py`'s own function of the same name (task #22, verified real against
    Cartesi's own facts) -- see this module's own docstring for why it is a copy rather than an
    import. Requires an EXACT, single-candidate match on the real function's own
    `Class.Method`-prefixed `full_name` -- never a guess when zero or multiple real functions
    match."""
    fns_by_full_name_prefix = {}
    for f in cpp["functions"]:
        if f["is_external"]:
            continue
        prefix = f["full_name"].split(":", 1)[0]
        fns_by_full_name_prefix.setdefault(prefix, []).append(f)

    table, audit = {}, []
    for c in cpp["calls"]:
        if c["name"] != "InstanceMethod":
            continue
        m = _INSTANCE_METHOD_RE.search(c.get("code") or "")
        if not m:
            audit.append({"call": c["id"], "skipped": "InstanceMethod call, but code does "
                                                         "not match the real <&Class::Method> shape"})
            continue
        class_name, method_name = m.group(1), m.group(2)
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


_NAN_REGISTRATION_CALL_NAMES = ("SetPrototypeMethod", "Export")


def extract_nan_bindings(cpp):
    """binding name -> (function_id, full_name) for the `Nan::SetPrototypeMethod(tpl, "name",
    Fn)` / `Nan::Export(target, "name", Fn)` idiom -- see module docstring for why this exists
    and the real re2 evidence it's confirmed against. Requires an EXACT structural match: the
    call's own name is one of `_NAN_REGISTRATION_CALL_NAMES`, it has exactly 3 real arguments,
    argument[1] is a real LITERAL and argument[2] is a real METHOD_REF -- never a substring/
    regex guess, and never a positional fallback for a differently-shaped call that merely
    shares one of these names."""
    fns_by_name = {}
    for f in cpp["functions"]:
        if not f["is_external"]:
            fns_by_name.setdefault(f["name"], []).append(f)
    table, audit = {}, []
    for c in cpp["calls"]:
        if c["name"] not in _NAN_REGISTRATION_CALL_NAMES:
            continue
        args = c.get("arguments") or []
        if len(args) != 3:
            audit.append({"call": c["id"], "skipped": f"{c['name']}: {len(args)} arguments "
                                                        "(need exactly 3)"})
            continue
        name_arg, fn_arg = args[1], args[2]
        if name_arg.get("kind") != "LITERAL" or fn_arg.get("kind") != "METHOD_REF":
            audit.append({"call": c["id"], "skipped": "shape not mechanically exact"})
            continue
        js_name = (name_arg.get("code") or "").strip().strip('"')
        fn_name = (fn_arg.get("code") or "").strip()
        if not js_name or not fn_name:
            audit.append({"call": c["id"], "skipped": "empty name/function reference"})
            continue
        cands = fns_by_name.get(fn_name, [])
        if len(cands) != 1:
            audit.append({"call": c["id"], "name": js_name, "fn": fn_name,
                          "skipped": f"{len(cands)} candidate functions (need exactly 1)"})
            continue
        table[js_name] = (cands[0]["id"], cands[0]["full_name"])
        audit.append({"call": c["id"], "name": js_name, "fn": fn_name,
                      "linked_function_id": cands[0]["id"]})
    return table, audit


def build_registration_table(cpp):
    """Union of all three real registration idioms this module recognizes. On a real name
    collision, exports.Set wins over InstanceMethod (matches
    `promote_via_js_linkage.link_calls_extended`'s own precedent), then NAN -- rare in practice,
    since a real addon uses one binding library consistently, never a mix on the same name."""
    table, _audit1 = extract_napi_bindings(cpp)
    table2, _audit2 = extract_instancemethod_bindings(cpp)
    table3, _audit3 = extract_nan_bindings(cpp)
    for name, entry in table2.items():
        table.setdefault(name, entry)
    for name, entry in table3.items():
        table.setdefault(name, entry)
    return table


def link_js_calls(js, cpp, table, js_receiver="bindings"):
    """Real per-call linking loop -- same real shape as `link_napi_facts.py`'s own `main()`
    loop and `promote_via_js_linkage.link_calls_extended`, but working entirely in the
    UNMERGED, pre-OFFSET id space (this module never calls `offset_ids`): `table`'s own
    function ids are already real cpp function ids, exactly what OOB_*/LOCK_BALANCE/
    PROTECTED_FIELD findings carry as their own `function_id`/`method_id` -- no id-space
    translation needed. Returns (linked, unlinked), each a list of real per-call evidence
    dicts -- never silently dropped."""
    js_index = JsCallIndex(js)
    linked, unlinked = [], []
    for c in js.get("calls", []):
        receiver_matched, tier, reason = native_binding_receiver_evidence(c, js_index)
        is_candidate = ((c.get("receiver_name") == js_receiver or receiver_matched)
                         and c.get("resolution") != "EXACT")
        if not is_candidate:
            continue
        if c["name"] in table:
            fid, full_name = table[c["name"]]
            linked.append({"js_call": c["id"], "name": c["name"], "cpp_function_id": fid,
                           "cpp_full_name": full_name, "evidence_tier": tier or "js_receiver_name"})
        else:
            unlinked.append({"js_call": c["id"], "name": c["name"],
                             "reason": reason or "no mechanically exact registration"})
    return linked, unlinked


def build_clean_call_edges(cpp):
    """caller_function_id -> [(callee_function_id, call_id, call_name), ...], using ONLY calls
    whose own `candidate_target_ids` resolves to EXACTLY ONE real function id. An edge from a
    call with MORE than one candidate (a real, confirmed-not-rare shape -- 6 of 508,350 real
    calls sampled across 20 real corpus packages, e.g. a virtual dispatch resolving to several
    real derived-class overrides) is excluded entirely, never included as a clean edge even
    though its own real target id technically sits inside the union -- per direct instruction,
    a transitive claim is promoted "only if every edge resolves by node identity.\""""
    edges = {}
    for c in cpp.get("calls", []):
        targets = c.get("candidate_target_ids") or []
        if len(targets) != 1:
            continue
        edges.setdefault(c.get("enclosing_function_id"), []).append(
            (targets[0], c.get("id"), c.get("name")))
    return edges


def find_clean_transitive_path(clean_edges, registered_ids, function_id):
    """Real BFS shortest path, over ONLY clean_call_edges, from any id in `registered_ids` to
    `function_id`. Returns the real path as a list of {caller_id, caller_name, callee_id,
    callee_name, call_id, call_site_name} hop dicts (needs `cpp['functions']` for names -- see
    caller), or None if no such clean path exists. `function_id` itself being in
    `registered_ids` is the caller's own responsibility to check first (this function does not
    special-case it)."""
    parent = {}
    seen = set(registered_ids)
    q = deque(registered_ids)
    while q:
        cur = q.popleft()
        for callee, call_id, call_name in clean_edges.get(cur, ()):
            if callee in seen:
                continue
            seen.add(callee)
            parent[callee] = (cur, call_id, call_name)
            if callee == function_id:
                path = []
                node = callee
                while node in parent:
                    p, cid, cname = parent[node]
                    path.append({"caller_id": p, "callee_id": node,
                                 "call_id": cid, "call_site_name": cname})
                    node = p
                path.reverse()
                return path
            q.append(callee)
    return None


def classify_function_reachability(function_id, table, linked, facts_available,
                                    clean_edges=None, fn_names=None):
    """Core tier decision for ONE native function id. `table` (from
    `build_registration_table`), `linked` (from `link_js_calls`), and `facts_available` (False
    iff the package's own js/cpp facts were themselves too thin to classify at all -- e.g. no
    real `functions`/`calls` at all on either side) are all real, already-computed inputs; this
    function makes no I/O decisions of its own. `clean_edges` (from `build_clean_call_edges`)
    and `fn_names` (function_id -> full_name, for real evidence, never required -- both default
    to empty/None so existing callers that only care about the first three tiers keep working
    unchanged) enable the TIER_TRANSITIVELY_CALLED_FROM_REGISTERED check (task #32's reopened
    scope). Returns {"reachability_status", "reachability_evidence"} -- the latter is None for
    the tiers that carry no additional real evidence beyond the tier itself."""
    if not facts_available:
        return {"reachability_status": REACHABILITY_UNRESOLVED, "reachability_evidence": None}

    registered_ids = {fid for fid, _full in table.values()}
    if function_id not in registered_ids:
        if clean_edges is not None:
            path = find_clean_transitive_path(clean_edges, registered_ids, function_id)
            if path is not None:
                fn_names = fn_names or {}
                for hop in path:
                    hop["caller_name"] = fn_names.get(hop["caller_id"])
                    hop["callee_name"] = fn_names.get(hop["callee_id"])
                root_id = path[0]["caller_id"]
                root_binding_name = next(
                    (name for name, (fid, _f) in table.items() if fid == root_id), None)
                return {"reachability_status": TIER_TRANSITIVELY_CALLED_FROM_REGISTERED,
                        "reachability_evidence": {
                            "root_registered_function_id": root_id,
                            "root_js_binding_name": root_binding_name,
                            "path_length_hops": len(path), "path": path}}
        return {"reachability_status": TIER_INTERNAL_UNREGISTERED, "reachability_evidence": None}

    matches = [l for l in linked if l["cpp_function_id"] == function_id]
    if not matches:
        binding_name = next((name for name, (fid, _f) in table.items() if fid == function_id), None)
        return {"reachability_status": TIER_REGISTERED_NOT_JS_CALLED,
                "reachability_evidence": {"registered_binding_name": binding_name}}

    best = min(matches, key=lambda l: _EVIDENCE_TIER_RANK.get(l["evidence_tier"], 99))
    return {"reachability_status": TIER_JS_CALL_PROVEN,
            "reachability_evidence": {
                "js_call_id": best["js_call"], "js_call_name": best["name"],
                "evidence_tier": best["evidence_tier"],
                "n_real_linked_calls": len(matches)}}


_ID_FIELD_BY_KEY = {
    "lock_balance_findings": "method_id",
    "protected_field_findings": "method_id",
    "oob_write_candidates": "function_id",
    "oob_index_write_candidates": "function_id",
    "oob_read_candidates": "function_id",
    "oob_compare_candidates": "function_id",
}


def classify_record_reachability(record, js, cpp):
    """Attaches `reachability_status`/`reachability_evidence` to every finding/candidate under
    LOCK_BALANCE, PROTECTED_FIELD, and every OOB_* key in `record`, in place. Deliberately does
    NOT touch `r04_findings`/`r05_findings` -- Resource Guard's own reachability question is
    answered separately by `promote_via_js_linkage.py` (task #21/#22), not this module (see
    module docstring). `js`/`cpp` are the package's own real, unmerged program-facts docs (the
    same ones `link_napi_facts.py`'s own CLI takes as its first two positional arguments)."""
    facts_available = bool(js.get("calls")) and bool(cpp.get("functions"))
    table = build_registration_table(cpp) if facts_available else {}
    linked, _unlinked = link_js_calls(js, cpp, table) if facts_available else ([], [])
    clean_edges = build_clean_call_edges(cpp) if facts_available else {}
    fn_names = {f["id"]: f.get("full_name") for f in cpp.get("functions", [])} if facts_available else {}

    for key, id_field in _ID_FIELD_BY_KEY.items():
        for f in record.get(key) or []:
            fid = f.get(id_field)
            if fid is None:
                f["reachability_status"] = REACHABILITY_UNRESOLVED
                f["reachability_evidence"] = None
                continue
            f.update(classify_function_reachability(
                fid, table, linked, facts_available, clean_edges, fn_names))
    return record
