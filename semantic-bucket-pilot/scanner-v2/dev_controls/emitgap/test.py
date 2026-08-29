#!/usr/bin/env python3
"""Synthetic controls for the emission-gap fix (dev branch): a recognized memcpy whose
destination is identifiable but non-bare (member / &obj / ptr-arith), or bare with no
allocation, now emits an explicit abstention naming missing_requirement=destination_capacity
instead of silently dropping. The with-allocation paths are unchanged."""
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
subprocess.run(["bash", os.path.join(SV, "scan_c_frozen.sh"), HERE, out], capture_output=True, text=True)
recs = {(r.get("function") or "").split(".")[-1]: r for r in P.analyze_operations(os.path.join(out, "cpp.json"))}
EXPECT = {
    "eg_member":         ("abstained", "required_evidence_absent", "destination_capacity"),
    "eg_addrof":         ("abstained", "required_evidence_absent", "destination_capacity"),
    "eg_ptrarith":       ("abstained", "required_evidence_absent", "destination_capacity"),
    "eg_bare_noalloc":   ("abstained", "required_evidence_absent", "destination_capacity"),
    "eg_bare_alloc":     ("deterministic_complete", None, None),          # unchanged: n<=n safe
    "eg_bare_alloc_open":("open_candidate", "capacity_relation_not_established", None),  # unchanged
}
ok = True
for fn, (st, rc, mr) in EXPECT.items():
    r = recs.get(fn)
    got = (r.get("analysis_status"), r.get("reason_code"), r.get("missing_requirement")) if r else None
    p = bool(r) and got == (st, rc, mr)
    ok = ok and p
    print(("PASS " if p else "FAIL ") + f"{fn:20} got={got}")
print("\nALL PASS" if ok else "\nFAILURES PRESENT")
sys.exit(0 if ok else 1)
