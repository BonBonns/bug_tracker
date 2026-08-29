#!/usr/bin/env python3
"""Synthetic controls for the FORM-AWARE emission-gap diagnosis (dev branch).

A recognized memcpy whose destination is non-bare no longer collapses into a
single `required_evidence_absent`. The abstention reason is chosen from the
CPG-resolved FORM of the destination (reference-target / declaration resolution,
never a text regex):

  * identity unresolvable / side-effecting  -> destination_identity_ambiguous
  * identity known, no fixed extent          -> required_evidence_absent
  * fixed extent, symbolic offset/width      -> capacity_relation_not_established
  * fixed extent, literal offset+width, fits -> capacity_relation_not_established
                                                (abstained; comparison attached)
  * fixed extent, literal offset+width, over -> capacity_relation_not_established
                                                (open_candidate; comparison attached)

The heap producer never promotes a non-heap destination to a safe verdict; a
provable overrun is surfaced as an open_candidate, not a hard verdict.
"""
import json, os, subprocess, sys, tempfile, importlib.util
HERE = os.path.dirname(os.path.abspath(__file__))
SV = os.path.join(HERE, "..", "..")
TOOLS = os.path.join(SV, "..", "..", "tchecker-research-complete",
                     "portable-engine-full-review-package", "tools")
sys.path.insert(0, TOOLS)


def _L(n):
    s = importlib.util.spec_from_file_location(n, os.path.join(TOOLS, n + ".py"))
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m


P = _L("oob_runtime_capacity_verdict")
out = tempfile.mkdtemp()
os.environ.setdefault("REPO", os.path.abspath(os.path.join(SV, "..", "..")))
# Scan the SINGLE consolidated controls file (one id-space; no cross-file id collision).
subprocess.run(["bash", os.path.join(SV, "scan_c_frozen.sh"),
                os.path.join(HERE, "controls.c"), out], capture_output=True, text=True)
recs_all = P.analyze_operations(os.path.join(out, "cpp.json"))
by_fn = {}
for r in recs_all:
    by_fn.setdefault((r.get("function") or "").split(".")[-1], []).append(r)


def one(fn):
    lst = by_fn.get(fn) or []
    return lst[0] if len(lst) == 1 else None


# (status, reason_code, destination_form, extra-checks-dict)
EXPECT = {
    # --- originals, now form-aware -----------------------------------------
    "eg_member":          ("abstained", "capacity_relation_not_established",
                           "fixed_array_member_symbolic_relation", {}),
    "eg_addrof":          ("abstained", "capacity_relation_not_established",
                           "scalar_object_write_within_bounds", {"write_fits": True}),
    "eg_ptrarith":        ("abstained", "required_evidence_absent", "pointer_object",
                           {"missing_requirement": "destination_capacity"}),
    "eg_bare_noalloc":    ("abstained", "required_evidence_absent", None,
                           {"missing_requirement": "destination_capacity"}),
    "eg_bare_alloc":      ("deterministic_complete", None, None, {}),
    "eg_bare_alloc_open": ("open_candidate", "capacity_relation_not_established", None, {}),
    # --- form controls ------------------------------------------------------
    "f_addr_scalar":      ("abstained", "capacity_relation_not_established",
                           "scalar_object_write_within_bounds", {"write_fits": True}),
    "f_member_fixed":     ("abstained", "capacity_relation_not_established",
                           "fixed_array_member_symbolic_relation", {}),
    "f_member_ptr":       ("abstained", "required_evidence_absent", "pointer_member",
                           {"missing_requirement": "destination_capacity"}),
    "f_arr_litoff":       ("abstained", "capacity_relation_not_established",
                           "fixed_array_object_symbolic_relation", {}),
    "f_arr_symoff":       ("abstained", "capacity_relation_not_established",
                           "fixed_extent_symbolic_relation", {}),
    "f_arr_lit_lit":      ("abstained", "capacity_relation_not_established",
                           "fixed_array_object_write_within_bounds",
                           {"write_fits": True, "extent": 64, "remaining": 60, "width": 8}),
    "f_arr_lit_over":     ("open_candidate", "capacity_relation_not_established",
                           "fixed_array_object_write_exceeds_bounds",
                           {"write_fits": False, "extent": 16, "remaining": 8, "width": 32}),
    "f_cast":             ("abstained", "required_evidence_absent", "pointer_object",
                           {"missing_requirement": "destination_capacity"}),
    "f_sideeffect":       ("abstained", "destination_identity_ambiguous",
                           "side_effecting_expression",
                           {"missing_requirement": "destination_object_identity"}),
}


def check_extra(r, extra):
    cmp = r.get("capacity_comparison") or {}
    for k, v in extra.items():
        if k == "write_fits":
            if cmp.get("write_fits") != v:
                return False
        elif k == "extent":
            if cmp.get("destination_fixed_extent_bytes") != v:
                return False
        elif k == "remaining":
            if cmp.get("remaining_capacity_bytes") != v:
                return False
        elif k == "width":
            if cmp.get("write_width_bytes") != v:
                return False
        else:
            if r.get(k) != v:
                return False
    return True


ok = True
for fn, (st, rc, form, extra) in EXPECT.items():
    r = one(fn)
    got = ((r.get("analysis_status"), r.get("reason_code"), r.get("destination_form"))
           if r else None)
    p = bool(r) and got == (st, rc, form) and check_extra(r, extra)
    ok = ok and p
    print(("PASS " if p else "FAIL ") + f"{fn:20} got={got}"
          + ("" if p or not r else f"  cmp={r.get('capacity_comparison')} "
             f"missing={r.get('missing_requirement')}"))

# --- shadowed same-name bases: ref-target must bind each write to the decl in
# scope. Inner `a` (char[8]) -> extent 8; outer `a` (char[64]) -> extent 64. A
# name/nearest-decl heuristic would collapse them.
shadow = by_fn.get("f_shadow") or []
extents = sorted((r.get("capacity_comparison") or {}).get("destination_fixed_extent_bytes")
                 for r in shadow if r.get("capacity_comparison"))
shadow_ok = extents == [8, 64]
ok = ok and shadow_ok
print(("PASS " if shadow_ok else "FAIL ")
      + f"{'f_shadow':20} resolved extents={extents} (expect [8, 64])")

print("\nALL PASS" if ok else "\nFAILURES PRESENT")
sys.exit(0 if ok else 1)
