#!/usr/bin/env python3
"""Capability 3 independent acceptance gate. Aggregates the evidence required to accept
capability 3 (advancing-pointer struct-member walks) under the frozen frontend joern-c2cpg
v4.0.608. Uses Magma/PNG003 as DEVELOPMENT evidence only; never references the frozen
held-out corpus. Emits CAP3_GATE=PASS iff every sub-gate passes.

Usage: gate_capability_3.py   (REPO env + scan_c_frozen.sh + joern 4.0.608)
"""
import os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
os.environ.setdefault("REPO", REPO)

SUBGATES = [
    ("cap3 member-walk model: positive + adversarial controls + PNG003 dev body",
     [sys.executable, os.path.join(HERE, "cap_member_pointer_walk_test.py")], r"^ALL PASS$"),
    ("domain-overlap audit vs frozen cursor producer",
     [sys.executable, os.path.join(HERE, "cap3_domain_audit.py")], r"^CAP3_DOMAIN_AUDIT=PASS$"),
    ("frozen outputs unchanged outside cap3's domain (analysis-record-r01)",
     [sys.executable, os.path.join(REPO, "tchecker-research-complete",
      "portable-engine-full-review-package", "tests", "gates",
      "analysis-record-r01", "gate_analysis_record_r01.py")],
     r"^ANALYSIS_RECORD_R01=(\d+)/\1$"),
]

REQUIRED_FILES = ["cap_member_pointer_walk.py", "cap_member_pointer_walk_test.py"]
HELDOUT_FORBIDDEN = ["secvuleval_full", "study/bigvul", "study/arvo", "study/pooled",
                     "FROZEN_heldout"]


def main():
    ok = True
    for f in REQUIRED_FILES:
        present = os.path.exists(os.path.join(HERE, f))
        print(("PASS" if present else "FAIL"), f"impl file present: {f}")
        ok = ok and present

    leak = False
    for s in ["cap_member_pointer_walk.py", "cap_member_pointer_walk_test.py",
              os.path.join("cap_controls", "cap3_member", "controls.c")]:
        txt = open(os.path.join(HERE, s)).read()
        for bad in HELDOUT_FORBIDDEN:
            if bad in txt:
                print("FAIL", f"{s} references held-out corpus token '{bad}'"); leak = True
    print(("PASS" if not leak else "FAIL"),
          "no held-out corpus (SecVulEval/Big-Vul/ARVO/pooled) referenced by cap3 code/controls")
    ok = ok and not leak

    for label, argv, rx in SUBGATES:
        try:
            out = subprocess.run(argv, capture_output=True, text=True, timeout=1200)
            body = out.stdout + out.stderr
            passed = any(re.match(rx, ln.strip()) for ln in body.splitlines())
        except Exception as e:
            body, passed = str(e), False
        print(("PASS" if passed else "FAIL"), label)
        if not passed:
            print("\n".join("      " + l for l in body.splitlines()[-8:]))
        ok = ok and passed

    print()
    print("CAP3_GATE=PASS" if ok else "CAP3_GATE=FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
