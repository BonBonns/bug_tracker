#!/usr/bin/env python3
"""Synthetic controls for the FORM-AWARE emission-gap diagnosis (dev branch),
UPDATED for the V1/V2 delegation split.

A recognized memcpy whose destination is non-bare no longer collapses into a
single `required_evidence_absent`. V1's abstention/handoff reason is chosen from
the CPG-resolved FORM of the destination (reference-target / declaration
resolution, never a text regex):

  * identity unresolvable / side-effecting  -> destination_identity_ambiguous
  * identity known, no fixed extent          -> required_evidence_absent
  * fixed extent (array or scalar), ANY offset/width, literal or symbolic
    -> delegated_to_stack_capacity_v2 (REROUTED handoff; V1 attaches the
       CPG-resolved structure -- element type, element count, offset, raw width
       -- and never computes or finalizes a comparison itself)

V2's stack-capacity integration (`oob_runtime_capacity_v2.analyze_operations_v2`)
is the SOLE adjudicator of the delegated records: fits -> deterministic_complete;
exceeds -> proven_oversized (open_candidate, `write_exceeds_stack_capacity`);
symbolic offset/width -> relationship_unresolved
(`capacity_relation_not_established`). This file checks BOTH stages: V1's
delegation shape, and V2's final adjudication of each delegated record.
"""
import json, os, subprocess, sys, tempfile, importlib.util
HERE = os.path.dirname(os.path.abspath(__file__))
SV = os.path.join(HERE, "..", "..")
TOOLS = os.path.join(SV, "..", "..", "tchecker-research-complete",
                     "portable-engine-full-review-package", "tools")
sys.path.insert(0, TOOLS)
sys.path.insert(0, SV)


def _L(n):
    s = importlib.util.spec_from_file_location(n, os.path.join(TOOLS, n + ".py"))
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m


P = _L("oob_runtime_capacity_verdict")
import oob_runtime_capacity_v2 as V2

out = tempfile.mkdtemp()
os.environ.setdefault("REPO", os.path.abspath(os.path.join(SV, "..", "..")))
# Scan the SINGLE consolidated controls file (one id-space; no cross-file id collision).
subprocess.run(["bash", os.path.join(SV, "scan_c_frozen.sh"),
                os.path.join(HERE, "controls.c"), out], capture_output=True, text=True)
cpp = os.path.join(out, "cpp.json")
recs_all = P.analyze_operations(cpp)
by_fn = {}
for r in recs_all:
    by_fn.setdefault((r.get("function") or "").split(".")[-1], []).append(r)

v2_ops, _tr = V2.analyze_operations_v2(cpp)
by_fn_v2 = {}
for r in v2_ops:
    by_fn_v2.setdefault((r.get("function") or "").split(".")[-1], []).append(r)


def one(fn):
    lst = by_fn.get(fn) or []
    return lst[0] if len(lst) == 1 else None


def one_v2(fn):
    lst = by_fn_v2.get(fn) or []
    return lst[0] if len(lst) == 1 else None


# --- STAGE 1: V1's delegation shape --------------------------------------------
# (status, reason_code, destination_form, established_facts-checks-dict-or-None)
EXPECT_V1 = {
    "eg_member":          ("rerouted", "delegated_to_stack_capacity_v2",
                           "fixed_array_member_offset_resolved",
                           {"element_type": "char", "element_count": 16, "offset_elements": 0}),
    "eg_addrof":          ("rerouted", "delegated_to_stack_capacity_v2",
                           "scalar_object_offset_resolved",
                           {"element_type": "int", "element_count": 1, "offset_elements": 0}),
    "eg_ptrarith":        ("abstained", "required_evidence_absent", "pointer_object",
                           {"missing_requirement": "destination_capacity"}),
    "eg_bare_noalloc":    ("abstained", "required_evidence_absent", None,
                           {"missing_requirement": "destination_capacity"}),
    "eg_bare_alloc":      ("deterministic_complete", None, None, None),
    "eg_bare_alloc_open": ("open_candidate", "capacity_relation_not_established", None, None),
    "f_addr_scalar":      ("rerouted", "delegated_to_stack_capacity_v2",
                           "scalar_object_offset_resolved",
                           {"element_type": "int", "element_count": 1, "offset_elements": 0}),
    "f_addr_scalar_sizeof": ("rerouted", "delegated_to_stack_capacity_v2",
                           "scalar_object_offset_resolved",
                           {"element_type": "int", "element_count": 1, "offset_elements": 0}),
    "f_member_fixed":     ("rerouted", "delegated_to_stack_capacity_v2",
                           "fixed_array_member_offset_resolved",
                           {"element_type": "char", "element_count": 16, "offset_elements": 0}),
    "f_member_ptr":       ("abstained", "required_evidence_absent", "pointer_member",
                           {"missing_requirement": "destination_capacity"}),
    "f_arr_litoff":       ("rerouted", "delegated_to_stack_capacity_v2",
                           "fixed_array_object_offset_resolved",
                           {"element_type": "char", "element_count": 64, "offset_elements": 4}),
    "f_arr_symoff":       ("rerouted", "delegated_to_stack_capacity_v2",
                           "fixed_array_object_symbolic_offset",
                           {"element_type": "char", "element_count": 64, "offset_elements": "sym"}),
    "f_arr_lit_lit":      ("rerouted", "delegated_to_stack_capacity_v2",
                           "fixed_array_object_offset_resolved",
                           {"element_type": "char", "element_count": 64, "offset_elements": 4}),
    "f_arr_lit_over":     ("rerouted", "delegated_to_stack_capacity_v2",
                           "fixed_array_object_offset_resolved",
                           {"element_type": "char", "element_count": 16, "offset_elements": 8}),
    "f_cast":             ("abstained", "required_evidence_absent", "pointer_object",
                           {"missing_requirement": "destination_capacity"}),
    "f_sideeffect":       ("abstained", "destination_identity_ambiguous",
                           "side_effecting_expression",
                           {"missing_requirement": "destination_object_identity"}),
}

# --- STAGE 2: V2's final adjudication of each delegated record ----------------
# (analysis_status, reason_code) -- fn's absent here were not delegated (stage 2
# n/a), still checked at stage 1 above.
EXPECT_V2 = {
    "eg_member":      ("open_candidate", "capacity_relation_not_established"),   # width symbolic (n)
    # &obj (int, 1 elem) vs a literal BYTE count "4": compare() correctly refuses
    # to equate "4 bytes" with "1 int" without a sizeof(int) in the width
    # expression -- that would assume sizeof(int)==4 (an ABI fact), which this
    # frozen arithmetic never does. NOT deterministic: this is the exact unit
    # trap the delegation design explicitly guards against ("&scalar capacity is
    # sizeof(type), not an assumed ABI byte count").
    "eg_addrof":      ("open_candidate", "capacity_relation_not_established"),
    "f_addr_scalar":  ("open_candidate", "capacity_relation_not_established"),
    "f_addr_scalar_sizeof": ("deterministic_complete", None),                    # sizeof(int)==int elem: 1<=1 fits
    "f_member_fixed": ("open_candidate", "capacity_relation_not_established"),   # width symbolic
    "f_arr_litoff":   ("open_candidate", "capacity_relation_not_established"),   # width symbolic (n)
    "f_arr_symoff":   ("open_candidate", "capacity_relation_not_established"),   # offset symbolic
    "f_arr_lit_lit":  ("deterministic_complete", None),                          # 8<=64-4=60 fits (char, byte-typed)
    "f_arr_lit_over": ("open_candidate", "write_exceeds_stack_capacity"),        # 32>16-8=8 exceeds
}


ok = True
for fn, (st, rc, form, facts_expect) in EXPECT_V1.items():
    r = one(fn)
    got = ((r.get("analysis_status"), r.get("reason_code"), r.get("destination_form"))
           if r else None)
    p = bool(r) and got == (st, rc, form)
    if p and facts_expect is not None:
        ef = (r.get("established_facts") or [{}])[0] if st == "rerouted" else r
        for k, v in facts_expect.items():
            if ef.get(k) != v:
                p = False
    ok = ok and p
    print(("PASS " if p else "FAIL ") + f"V1 {fn:20} got={got}"
          + ("" if p or not r else f"  facts={r.get('established_facts')}"
             f" missing={r.get('missing_requirement')}"))

for fn, (st, rc) in EXPECT_V2.items():
    r = one_v2(fn)
    got = (r.get("analysis_status"), r.get("reason_code")) if r else None
    p = bool(r) and got == (st, rc)
    ok = ok and p
    print(("PASS " if p else "FAIL ") + f"V2 {fn:20} got={got}")

# --- shadowed same-name bases: ref-target must bind each write to the decl in
# scope. Inner `a` (char[8]) -> element_count 8; outer `a` (char[64]) -> element_count 64.
# A name/nearest-decl heuristic would collapse them. Checked at BOTH stages: V1's
# raw discovery, and V2's final adjudication (inner fits 1+2<=8; outer exceeds 60+8>64).
shadow = by_fn.get("f_shadow") or []
counts = sorted((r.get("established_facts") or [{}])[0].get("element_count")
                for r in shadow if r.get("established_facts"))
shadow_v1_ok = counts == [8, 64]
ok = ok and shadow_v1_ok
print(("PASS " if shadow_v1_ok else "FAIL ")
      + f"V1 {'f_shadow':20} resolved element_counts={counts} (expect [8, 64])")

shadow_v2 = by_fn_v2.get("f_shadow") or []
shadow_v2_statuses = sorted(r.get("analysis_status") for r in shadow_v2)
shadow_v2_ok = shadow_v2_statuses == ["deterministic_complete", "open_candidate"]
ok = ok and shadow_v2_ok
print(("PASS " if shadow_v2_ok else "FAIL ")
      + f"V2 {'f_shadow':20} statuses={shadow_v2_statuses} "
        f"(expect [deterministic_complete, open_candidate] -- inner fits, outer exceeds)")

print("\nALL PASS" if ok else "\nFAILURES PRESENT")
sys.exit(0 if ok else 1)
