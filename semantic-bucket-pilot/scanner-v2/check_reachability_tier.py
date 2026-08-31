#!/usr/bin/env python3
"""REACH-TIER-R01 (task #32) controls. Covers: real TIER_JS_CALL_PROVEN classification against
the crosslang_link_fix gate's own real, already-verified positive fixture (8/8 registered
functions, real JS calls proven to reach each one); real TIER_INTERNAL_UNREGISTERED against that
SAME fixture's own real `Init` function (the NAPI addon entry point itself -- never registered
via exports.Set, a real never-exported function, not synthetic); a disclosed SYNTHETIC
TIER_REGISTERED_NOT_JS_CALLED case (the real fixture's own registration set happens to have 100%
JS-call coverage, so no real corpus example of "registered but uncalled" exists in this
fixture -- built to the exact same real exports.Set shape rather than left untested);
REACHABILITY_UNRESOLVED on empty facts; the InstanceMethod/DefineClass idiom recognized
correctly (unit-level, same real shape task #22 verified against Cartesi); and
classify_record_reachability() never touching r04_findings/r05_findings.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import reachability_tier as rt

ok = tot = 0
def ck(name, cond):
    global ok, tot
    tot += 1
    ok += bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


_HERE = os.path.dirname(os.path.abspath(__file__))
_FIXTURE_DIR = os.path.join(_HERE, "study", "crosslang_link_fix", "controls")
cpp = json.load(open(os.path.join(_FIXTURE_DIR, "cpp_facts", "cpp_facts.json")))
js = json.load(open(os.path.join(_FIXTURE_DIR, "js_facts", "js_facts_adapted.json")))

table = rt.build_registration_table(cpp)
linked, unlinked = rt.link_js_calls(js, cpp, table)

ck("real fixture: all 8 real exports.Set registrations recovered",
   len(table) == 8 and set(table) == {"Foo", "Bar", "Baz", "Qux", "Quux", "Corge", "Grault", "Garply"})
ck("real fixture: all 8 real registered functions have a real linked JS call "
   "(matches the crosslang_link_fix gate's own '8 real positive controls all link')",
   len(linked) == 8)

foo_id = table["Foo"][0]
res = rt.classify_function_reachability(foo_id, table, linked, facts_available=True)
ck("real Foo: TIER_JS_CALL_PROVEN", res["reachability_status"] == rt.TIER_JS_CALL_PROVEN)
ck("real Foo: evidence carries a real js_call_id from the fixture's own linked_calls",
   res["reachability_evidence"]["js_call_id"] is not None)

# real Init function: the NAPI_MODULE init function itself, present in this real fixture's own
# cpp_facts.json, never registered via exports.Set (it IS the function that calls Set) -- a
# real, not synthetic, never-exported function.
init_fn = next(f for f in cpp["functions"] if f["name"] == "Init")
res_init = rt.classify_function_reachability(init_fn["id"], table, linked, facts_available=True)
ck("real Init (the addon's own entry point, never itself exported): TIER_INTERNAL_UNREGISTERED",
   res_init["reachability_status"] == rt.TIER_INTERNAL_UNREGISTERED)

# --- disclosed synthetic: a function registered via the real exports.Set shape, but with NO
# real JS call reaching it (this fixture's own real registration set has 100% coverage, so this
# case is built rather than found) ---
synthetic_cpp = {
    "functions": [{"id": 900001, "name": "NeverCalledFromJs",
                    "full_name": "NeverCalledFromJs:Napi.Value(Napi.CallbackInfo&)",
                    "is_external": False}],
    "calls": [
        {"id": 900010, "name": "New", "receiver_name": None,
         "arguments": [{"index": 1, "value_ref": {"kind": "CONSTANT", "code": "\"env\""}}]},
        {"id": 900011, "name": "New", "receiver_name": None,
         "arguments": [{"index": 1, "code": "NeverCalledFromJs",
                        "value_ref": {"kind": "IDENTIFIER", "code": "NeverCalledFromJs"}}]},
        {"id": 900012, "name": "New", "receiver_name": None,
         "arguments": [{"index": 1, "value_ref": {"kind": "CONSTANT", "code": '"neverCalled"'}}]},
        {"id": 900013, "name": "Set", "receiver_name": "exports",
         "arguments": [
             {"index": 1, "value_ref": {"kind": "CALL", "id": 900012}},
             {"index": 2, "value_ref": {"kind": "CALL", "id": 900011}}]},
    ],
}
syn_table = rt.build_registration_table(synthetic_cpp)
ck("synthetic registration shape parses to a real 1-entry table",
   list(syn_table) == ["neverCalled"])
syn_linked, _ = rt.link_js_calls({"calls": []}, synthetic_cpp, syn_table)
res_syn = rt.classify_function_reachability(900001, syn_table, syn_linked, facts_available=True)
ck("SYNTHETIC (disclosed, not corpus data): registered but never JS-called -> "
   "TIER_REGISTERED_NOT_JS_CALLED",
   res_syn["reachability_status"] == rt.TIER_REGISTERED_NOT_JS_CALLED)
ck("SYNTHETIC: evidence names the real registered binding name",
   res_syn["reachability_evidence"]["registered_binding_name"] == "neverCalled")

# --- REACHABILITY_UNRESOLVED on empty/thin facts ---
res_empty = rt.classify_function_reachability(1, {}, [], facts_available=False)
ck("empty facts: REACHABILITY_UNRESOLVED, no evidence fabricated",
   res_empty["reachability_status"] == rt.REACHABILITY_UNRESOLVED
   and res_empty["reachability_evidence"] is None)

# --- InstanceMethod/DefineClass idiom, unit-level (same real shape as task #22's own Cartesi
# verification) ---
im_cpp = {
    "functions": [{"id": 5, "name": "ReadMemory", "full_name": "Machine.ReadMemory:...",
                    "is_external": False}],
    "calls": [{"id": 50, "name": "InstanceMethod",
               "code": "InstanceMethod<&Machine::ReadMemory>(\"readMemory\")",
               "arguments": [{"index": 0, "kind": "LITERAL", "code": '"readMemory"'}]}],
}
im_table, im_audit = rt.extract_instancemethod_bindings(im_cpp)
ck("InstanceMethod/DefineClass idiom: real structural match recovers readMemory -> function 5",
   im_table.get("readMemory") == (5, "Machine.ReadMemory:..."))

# --- NAN idiom: shape reproduced verbatim from re2's own real facts (overnight-diagnostic-100's
# own evidence bundle, /tmp/re2_smoke this session -- not committed here since the bundle itself
# isn't a durable artifact, so this fixture is a real-shape excerpt, not synthetic invention).
# re2's own real ambiguity (TWO distinct C++ functions both literally named "Test", one per
# wrapped class) is reproduced too, to confirm the SAME real, principled abstention this module
# gives on a genuine name collision.
nan_cpp = {
    "functions": [
        {"id": 700001, "name": "Exec", "full_name": "WrappedRE2.Exec:void(Nan.NAN_METHOD_ARGS_TYPE)",
         "is_external": False},
        {"id": 700002, "name": "Test", "full_name": "WrappedRE2.Test:void(Nan.NAN_METHOD_ARGS_TYPE)",
         "is_external": False},
        {"id": 700003, "name": "Test", "full_name": "MatchObject.Test:void(Nan.NAN_METHOD_ARGS_TYPE)",
         "is_external": False},
    ],
    "calls": [
        {"id": 700010, "name": "SetPrototypeMethod",
         "code": 'Nan::SetPrototypeMethod(tpl, "exec", Exec)',
         "arguments": [
             {"index": 0, "kind": "IDENTIFIER", "code": "tpl"},
             {"index": 1, "kind": "LITERAL", "code": '"exec"'},
             {"index": 2, "kind": "METHOD_REF", "code": "Exec"}]},
        {"id": 700011, "name": "SetPrototypeMethod",
         "code": 'Nan::SetPrototypeMethod(tpl, "test", Test)',
         "arguments": [
             {"index": 0, "kind": "IDENTIFIER", "code": "tpl"},
             {"index": 1, "kind": "LITERAL", "code": '"test"'},
             {"index": 2, "kind": "METHOD_REF", "code": "Test"}]},
        {"id": 700012, "name": "SetPrototypeMethod",
         "code": 'Nan::SetPrototypeMethod(tpl2, "test", Test)',
         "arguments": [
             {"index": 0, "kind": "IDENTIFIER", "code": "tpl2"},
             {"index": 1, "kind": "LITERAL", "code": '"test"'},
             {"index": 2, "kind": "METHOD_REF", "code": "Test"}]},
    ],
}
nan_table, nan_audit = rt.extract_nan_bindings(nan_cpp)
ck("NAN idiom: real SetPrototypeMethod shape recovers exec -> WrappedRE2.Exec (single "
   "candidate)", nan_table.get("exec") == (700001, "WrappedRE2.Exec:void(Nan.NAN_METHOD_ARGS_TYPE)"))
ck("NAN idiom: real name collision (two distinct C++ functions both literally named Test, one "
   "per class) is correctly abstained, not guessed -- 'test' does NOT appear in the table",
   "test" not in nan_table)
ck("NAN idiom: the collision is disclosed in the audit trail, not silently dropped",
   any(a.get("skipped", "").startswith("2 candidate") for a in nan_audit))

# --- classify_record_reachability: applies to the 6 real target keys, never to r04/r05 ---
record = {
    "lock_balance_findings": [{"method_id": init_fn["id"]}],
    "r04_findings": [{"method_id": init_fn["id"]}],
    "r05_findings": [{"method_id": foo_id}],
    "oob_write_candidates": [{"function_id": foo_id}],
}
rt.classify_record_reachability(record, js, cpp)
ck("classify_record_reachability: lock_balance_findings gets a real reachability_status",
   "reachability_status" in record["lock_balance_findings"][0])
ck("classify_record_reachability: oob_write_candidates gets TIER_JS_CALL_PROVEN (real Foo)",
   record["oob_write_candidates"][0]["reachability_status"] == rt.TIER_JS_CALL_PROVEN)
ck("classify_record_reachability: r04_findings is NEVER touched (Resource Guard owns its own "
   "reachability field, task #21/#22)",
   "reachability_status" not in record["r04_findings"][0])
ck("classify_record_reachability: r05_findings is NEVER touched",
   "reachability_status" not in record["r05_findings"][0])

print(f"REACH_TIER_R01_CONTROLS={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
