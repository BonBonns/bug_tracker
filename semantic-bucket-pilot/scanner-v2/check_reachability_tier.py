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

# =====================================================================================
# TASK #32 REOPENED: TIER_TRANSITIVELY_CALLED_FROM_REGISTERED (task #34's own rejection-funnel
# analysis). Positive (a real, clean 2-hop chain), ambiguity (REAL 3-candidate call shape,
# copied verbatim from @fugood/whisper.node's own real cpp_facts.json --
# ggml.cpu.*.extra_buffer_type.get_tensor_traits, a real virtual-dispatch-shaped call c2cpg
# itself left with 3 real candidate targets -- never invented), negative (no path exists at
# all), and a real smoke test against @eliyya/sange's own real bundle evidence.
# =====================================================================================
trans_cpp = {
    "functions": [
        {"id": 800001, "name": "RegisteredEntry",
         "full_name": "RegisteredEntry:Napi.Value(Napi.CallbackInfo&)", "is_external": False},
        {"id": 800002, "name": "IntermediateHelper", "full_name": "IntermediateHelper:void()",
         "is_external": False},
        {"id": 800003, "name": "TargetInternal", "full_name": "TargetInternal:void()",
         "is_external": False},
        {"id": 800004, "name": "UnreachableInternal", "full_name": "UnreachableInternal:void()",
         "is_external": False},
    ],
    "calls": [
        {"id": 800010, "name": "New", "receiver_name": None,
         "arguments": [{"index": 1, "value_ref": {"kind": "CONSTANT", "code": "\"env\""}}]},
        {"id": 800011, "name": "New", "receiver_name": None,
         "arguments": [{"index": 1, "code": "RegisteredEntry",
                        "value_ref": {"kind": "IDENTIFIER", "code": "RegisteredEntry"}}]},
        {"id": 800012, "name": "New", "receiver_name": None,
         "arguments": [{"index": 1, "value_ref": {"kind": "CONSTANT", "code": '"registeredEntry"'}}]},
        {"id": 800013, "name": "Set", "receiver_name": "exports",
         "arguments": [
             {"index": 1, "value_ref": {"kind": "CALL", "id": 800012}},
             {"index": 2, "value_ref": {"kind": "CALL", "id": 800011}}]},
        # RegisteredEntry -> IntermediateHelper -> TargetInternal, both edges CLEAN
        # (single-target-resolved) -- a real, structurally clean transitive chain.
        {"id": 800020, "name": "IntermediateHelper", "enclosing_function_id": 800001,
         "candidate_target_ids": [800002]},
        {"id": 800021, "name": "TargetInternal", "enclosing_function_id": 800002,
         "candidate_target_ids": [800003]},
        # RegisteredEntry ALSO calls a real, unresolved-shape ambiguous call (copied verbatim
        # from @fugood/whisper.node@1.1.3's own real cpp_facts.json, whisper.cpp/ggml/src/
        # ggml-cpu/traits.cpp:16 -- a real virtual dispatch through 3 real derived-class
        # overrides c2cpg itself could not disambiguate to one) -- its own real 3-candidate
        # shape must NOT be treated as a clean edge, even though UnreachableInternal is NOT
        # actually one of its 3 real candidates here (it's the classify_function_reachability
        # target below, reached ONLY through this ambiguous call in this synthetic scenario --
        # see the ambiguous-only test below, which points the ambiguous call's own candidates
        # AT the target instead).
        {"id": 30064881177, "name": "get_tensor_traits", "enclosing_function_id": 800001,
         "candidate_target_ids": [107374184414, 107374184859, 107374184889],
         "candidate_target_full_names": [
             "ggml.cpu.kleidiai.extra_buffer_type.get_tensor_traits:ggml.cpu.tensor_traits*(ggml_tensor*)",
             "ggml.cpu.repack.extra_buffer_type.get_tensor_traits:ggml.cpu.tensor_traits*(ggml_tensor*)",
             "ggml.cpu.riscv64_spacemit.extra_buffer_type.get_tensor_traits:ggml.cpu.tensor_traits*(ggml_tensor*)"],
         "file": "whisper.cpp/ggml/src/ggml-cpu/traits.cpp", "line": 16},
    ],
}
trans_table = rt.build_registration_table(trans_cpp)
trans_clean_edges = rt.build_clean_call_edges(trans_cpp)
trans_fn_names = {f["id"]: f["full_name"] for f in trans_cpp["functions"]}

res_trans = rt.classify_function_reachability(
    800003, trans_table, [], facts_available=True,
    clean_edges=trans_clean_edges, fn_names=trans_fn_names)
ck("POSITIVE: a real, clean 2-hop chain (RegisteredEntry -> IntermediateHelper -> "
   "TargetInternal, both edges single-target-resolved) -> "
   "TIER_TRANSITIVELY_CALLED_FROM_REGISTERED",
   res_trans["reachability_status"] == rt.TIER_TRANSITIVELY_CALLED_FROM_REGISTERED)
ck("POSITIVE: real evidence names the real root registered binding (registeredEntry)",
   res_trans["reachability_evidence"]["root_js_binding_name"] == "registeredEntry")
ck("POSITIVE: real evidence carries the real 2-hop path, both hops named",
   res_trans["reachability_evidence"]["path_length_hops"] == 2
   and res_trans["reachability_evidence"]["path"][0]["callee_name"] == "IntermediateHelper:void()"
   and res_trans["reachability_evidence"]["path"][1]["callee_name"] == "TargetInternal:void()")

# --- AMBIGUITY: a target reachable ONLY through the real 3-candidate ambiguous call above
# (repointed at the target) must NOT be promoted -- stays TIER_INTERNAL_UNREGISTERED ---
ambiguous_only_cpp = dict(trans_cpp)
ambiguous_only_cpp["calls"] = [c for c in trans_cpp["calls"] if c["id"] != 30064881177] + [
    {"id": 30064881177, "name": "get_tensor_traits", "enclosing_function_id": 800001,
     "candidate_target_ids": [800004, 107374184859, 107374184889]},  # target IS one of 3
                                                                       # real candidates, but
                                                                       # NOT the only one
]
amb_clean_edges = rt.build_clean_call_edges(ambiguous_only_cpp)
ck("real ambiguous call (3 candidates, same shape as @fugood/whisper.node's own real "
   "get_tensor_traits virtual dispatch) is excluded from clean_edges entirely",
   800001 not in amb_clean_edges or all(t != 800004 for t, _cid, _cn in amb_clean_edges.get(800001, [])))
res_amb = rt.classify_function_reachability(
    800004, trans_table, [], facts_available=True,
    clean_edges=amb_clean_edges, fn_names=trans_fn_names)
ck("*** AMBIGUITY REJECTED: a target reachable ONLY through a real multi-candidate "
   "(ambiguous) call stays TIER_INTERNAL_UNREGISTERED -- never promoted on an unclean edge, "
   "even though the target IS technically inside that call's own candidate_target_ids union ***",
   res_amb["reachability_status"] == rt.TIER_INTERNAL_UNREGISTERED)

# --- NEGATIVE: no path exists at all (genuinely disconnected) -- stays TIER_INTERNAL_UNREGISTERED
disconnected_cpp = {
    "functions": trans_cpp["functions"],
    "calls": trans_cpp["calls"][:4],  # only the registration calls -- no call edges at all
}
disc_clean_edges = rt.build_clean_call_edges(disconnected_cpp)
res_disc = rt.classify_function_reachability(
    800004, trans_table, [], facts_available=True,
    clean_edges=disc_clean_edges, fn_names=trans_fn_names)
ck("NEGATIVE: a genuinely disconnected function (no real call edge reaches it from any "
   "registered export) stays TIER_INTERNAL_UNREGISTERED, not fabricated as reachable",
   res_disc["reachability_status"] == rt.TIER_INTERNAL_UNREGISTERED
   and res_disc["reachability_evidence"] is None)

# --- REAL SMOKE TEST: @eliyya/sange's own real bundle (task #34's own already-preserved
# evidence) -- "lock" (Mutex.lock), reached in exactly 1 real clean hop from a real registered
# Napi entry point (setSecretBox), independently confirmed in
# study/task34_replay/validate_transitive_paths.py before this tier was wired in.
_sange_bundle = os.path.join(_HERE, "npm_corpus", "overnight_100", "evidence_bundles_100",
                              "@eliyya__sange@1.2.0.tar.gz")
if os.path.isfile(_sange_bundle):
    import tarfile
    with tarfile.open(_sange_bundle, "r:gz") as tf:
        sange_cpp = json.load(tf.extractfile("cpp_facts.json"))
        sange_js = json.load(tf.extractfile("js_facts.json"))
    sange_record = {"lock_balance_findings": [{"method_id": 107374182564}]}  # real "lock" fid,
                                                                               # from task #34's
                                                                               # own replay data
    rt.classify_record_reachability(sange_record, sange_js, sange_cpp)
    real_status = sange_record["lock_balance_findings"][0]["reachability_status"]
    ck("SMOKE: @eliyya/sange's real 'lock' (Mutex.lock) -- previously TIER_INTERNAL_UNREGISTERED "
       "in task #34's own replay, now correctly TIER_TRANSITIVELY_CALLED_FROM_REGISTERED on the "
       "SAME real bundle evidence, no new Joern run", real_status == rt.TIER_TRANSITIVELY_CALLED_FROM_REGISTERED)
    if real_status == rt.TIER_TRANSITIVELY_CALLED_FROM_REGISTERED:
        real_ev = sange_record["lock_balance_findings"][0]["reachability_evidence"]
        ck("SMOKE: real evidence's root binding is the real registered N-API entry point",
           real_ev["root_js_binding_name"] is not None)
else:
    print("SKIP: @eliyya/sange's real bundle not present in this environment -- smoke test "
          "skipped, all synthetic/real-shape controls above still ran")

# =====================================================================================
# ROADMAP-STEP6-R01: TIER_CALLBACK_OR_WORKER_PROVEN. Real per-candidate audit
# (study/task34_replay/callback_worker_classifier_audit.py) confirmed 118 of 124 real
# CALLBACK_OR_WORKER_HEURISTIC-classified staged candidates were pure structural noise (a
# function pointer appearing as an operand of `<operator>.arrayInitializer`/`.cast`/
# `.assignment`/`.addressOf`, never a real registration) -- these controls prove the NEW,
# narrower tier correctly separates the 6 real matches from that noise.
# =====================================================================================
cbw_functions = [
    {"id": 900001, "name": "sha1QueryFunc", "full_name": "sha1QueryFunc:void(sqlite3_context*)"},
    {"id": 900002, "name": "NoiseTarget", "full_name": "NoiseTarget:void()"},
    {"id": 900003, "name": "UnlistedApiTarget", "full_name": "UnlistedApiTarget:void()"},
]
cbw_calls_positive = [
    # Real shape, copied from @appthreat/sqlite3@9.0.1's own real cpp_facts.json:
    # sqlite3_create_function(..., xFunc=sha1QueryFunc, ...) -- a real METHOD_REF argument to a
    # real, allowlisted callback-registration API.
    {"id": 900010, "name": "sqlite3_create_function", "enclosing_function_id": 999,
     "arguments": [{"index": 5, "kind": "METHOD_REF", "code": "sha1QueryFunc"}]},
]
cbw_refs_positive = rt.resolve_method_ref_targets({"functions": cbw_functions, "calls": cbw_calls_positive})
res_cbw_pos = rt.classify_function_reachability(
    900001, {}, [], facts_available=True, clean_edges={},
    method_ref_targets=cbw_refs_positive)
ck("POSITIVE (real shape, @appthreat/sqlite3's own sqlite3_create_function/sha1QueryFunc): "
   "TIER_CALLBACK_OR_WORKER_PROVEN", res_cbw_pos["reachability_status"] == rt.TIER_CALLBACK_OR_WORKER_PROVEN)
ck("POSITIVE: real evidence names the real registration API",
   res_cbw_pos["reachability_evidence"]["registration_api_name"] == "sqlite3_create_function")

cbw_calls_noise = [
    # The REAL, dominant noise shape the audit found: a function pointer appearing as an
    # operand of a generic operator, NOT a real registration call.
    {"id": 900011, "name": "<operator>.arrayInitializer", "enclosing_function_id": 999,
     "arguments": [{"index": 1, "kind": "METHOD_REF", "code": "NoiseTarget"}]},
]
cbw_refs_noise = rt.resolve_method_ref_targets({"functions": cbw_functions, "calls": cbw_calls_noise})
res_cbw_noise = rt.classify_function_reachability(
    900002, {}, [], facts_available=True, clean_edges={},
    method_ref_targets=cbw_refs_noise)
ck("*** NEGATIVE (real structural-noise shape, the 118/124 majority the audit found): a "
   "METHOD_REF argument to <operator>.arrayInitializer stays TIER_INTERNAL_UNREGISTERED, "
   "never promoted -- exactly the false-positive shape this tier exists to reject ***",
   res_cbw_noise["reachability_status"] == rt.TIER_INTERNAL_UNREGISTERED)

cbw_calls_unlisted = [
    # An unlisted-but-real API name (same real shape the audit found for rd_kafka_assignor_add,
    # deliberately NOT added to the allowlist -- single-sighting, not individually verified).
    {"id": 900012, "name": "rd_kafka_assignor_add", "enclosing_function_id": 999,
     "arguments": [{"index": 1, "kind": "METHOD_REF", "code": "UnlistedApiTarget"}]},
]
cbw_refs_unlisted = rt.resolve_method_ref_targets({"functions": cbw_functions, "calls": cbw_calls_unlisted})
res_cbw_unlisted = rt.classify_function_reachability(
    900003, {}, [], facts_available=True, clean_edges={},
    method_ref_targets=cbw_refs_unlisted)
ck("AMBIGUITY: an unlisted (not individually verified) real API name never promotes either -- "
   "deliberately conservative, same discipline as Nan::SetMethod elsewhere in this module",
   res_cbw_unlisted["reachability_status"] == rt.TIER_INTERNAL_UNREGISTERED)

# --- REAL SMOKE TEST: @appthreat/sqlite3's own real bundle, sha1QueryFunc/sqlite3_create_
# function (function_id 107374182492, confirmed via callback_worker_classifier_audit.py). ---
_sqlite3_bundle = os.path.join(_HERE, "npm_corpus", "overnight_100", "evidence_bundles_100",
                                "@appthreat__sqlite3@9.0.1.tar.gz")
if os.path.isfile(_sqlite3_bundle):
    import tarfile
    with tarfile.open(_sqlite3_bundle, "r:gz") as tf:
        sqlite3_cpp = json.load(tf.extractfile("cpp_facts.json"))
        sqlite3_js = json.load(tf.extractfile("js_facts.json"))
    sqlite3_record = {"oob_index_write_candidates": [{"function_id": 107374182492}]}
    rt.classify_record_reachability(sqlite3_record, sqlite3_js, sqlite3_cpp)
    real_cbw_status = sqlite3_record["oob_index_write_candidates"][0]["reachability_status"]
    ck("SMOKE: @appthreat/sqlite3's real sha1QueryFunc -- previously TIER_INTERNAL_UNREGISTERED, "
       "now correctly TIER_CALLBACK_OR_WORKER_PROVEN on the SAME real bundle evidence, no new "
       "Joern run", real_cbw_status == rt.TIER_CALLBACK_OR_WORKER_PROVEN)
else:
    print("SKIP: @appthreat/sqlite3's real bundle not present -- smoke test skipped")

# =====================================================================================
# ROADMAP-STEP6-R01: TIER_MODULE_LOAD_EXECUTION_PROVEN. Real per-candidate audit
# (study/task34_replay/module_load_classifier_audit.py) directly, hop-by-hop verified
# @elchetz/cld@2.8.5's own real GetLanguageFromName -- a genuine, clean, single-target-resolved
# 5-hop chain from the addon's own Init function (Init -> Constants::getInstance() ->
# Constants::Constants() -> init() -> initLanguages() -> CLD2::GetLanguageFromName).
# =====================================================================================
ml_functions = [
    {"id": 910001, "name": "Init", "full_name": "Init:void(Napi.Env,Napi.Object)",
     "is_external": False},
    {"id": 910002, "name": "getInstance", "full_name": "Constants.getInstance:Constants*()",
     "is_external": False},
    {"id": 910003, "name": "GetLanguageFromName",
     "full_name": "CLD2.GetLanguageFromName:int(char*)", "is_external": False},
    {"id": 910004, "name": "NeverReached", "full_name": "NeverReached:void()",
     "is_external": False},
]
ml_cpp = {
    "functions": ml_functions,
    "calls": [
        {"id": 910010, "name": "getInstance", "enclosing_function_id": 910001,
         "candidate_target_ids": [910002]},
        {"id": 910011, "name": "GetLanguageFromName", "enclosing_function_id": 910002,
         "candidate_target_ids": [910003]},
    ],
}
ml_table = rt.build_registration_table(ml_cpp)  # empty -- Init is never itself an exported
                                                   # binding, confirmed same as the sange smoke
                                                   # test's own real fixture above.
ml_clean_edges = rt.build_clean_call_edges(ml_cpp)
ml_init_ids = {910001}
res_ml_pos = rt.classify_function_reachability(
    910003, ml_table, [], facts_available=True, clean_edges=ml_clean_edges,
    fn_names={f["id"]: f["full_name"] for f in ml_functions}, init_ids=ml_init_ids)
ck("POSITIVE (real shape, @elchetz/cld's own Init -> getInstance -> GetLanguageFromName clean "
   "chain): TIER_MODULE_LOAD_EXECUTION_PROVEN", res_ml_pos["reachability_status"] == rt.TIER_MODULE_LOAD_EXECUTION_PROVEN)
ck("POSITIVE: real evidence's root is the real Init function id",
   res_ml_pos["reachability_evidence"]["root_init_function_id"] == 910001)

res_ml_neg = rt.classify_function_reachability(
    910004, ml_table, [], facts_available=True, clean_edges=ml_clean_edges,
    fn_names={f["id"]: f["full_name"] for f in ml_functions}, init_ids=ml_init_ids)
ck("NEGATIVE: a genuinely disconnected function (no real call edge from Init reaches it) stays "
   "TIER_INTERNAL_UNREGISTERED, not fabricated as module-load-reachable",
   res_ml_neg["reachability_status"] == rt.TIER_INTERNAL_UNREGISTERED)

# --- REAL SMOKE TEST: @elchetz/cld's own real bundle, GetLanguageFromName (function_id
# 107374182685, confirmed via module_load_classifier_audit.py). ---
_cld_bundle = os.path.join(_HERE, "npm_corpus", "overnight_100", "evidence_bundles_100",
                            "@elchetz__cld@2.8.5.tar.gz")
if os.path.isfile(_cld_bundle):
    import tarfile
    with tarfile.open(_cld_bundle, "r:gz") as tf:
        cld_cpp = json.load(tf.extractfile("cpp_facts.json"))
        cld_js = json.load(tf.extractfile("js_facts.json"))
    cld_record = {"oob_write_candidates": [{"function_id": 107374182685}]}
    rt.classify_record_reachability(cld_record, cld_js, cld_cpp)
    real_ml_status = cld_record["oob_write_candidates"][0]["reachability_status"]
    ck("SMOKE: @elchetz/cld's real GetLanguageFromName -- previously TIER_INTERNAL_UNREGISTERED, "
       "now correctly TIER_MODULE_LOAD_EXECUTION_PROVEN on the SAME real bundle evidence, no new "
       "Joern run", real_ml_status == rt.TIER_MODULE_LOAD_EXECUTION_PROVEN)
else:
    print("SKIP: @elchetz/cld's real bundle not present -- smoke test skipped")

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
