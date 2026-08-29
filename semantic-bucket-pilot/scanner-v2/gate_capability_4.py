#!/usr/bin/env python3
"""Capability 4 independent acceptance gate. Aggregates the evidence required to accept
capability 4 (external decoder contracts) under the frozen frontend joern-c2cpg v4.0.608.
NO model calls. Synthetic controls only; the frozen held-out corpus is NOT referenced
(enforced by grep in the gate). It also re-runs the capability 1/2/3 gates and the frozen
analysis-record-r01 gate to confirm those remain unchanged. Emits CAP4_GATE=PASS iff every
sub-gate passes.

Usage: gate_capability_4.py   (REPO env + scan_c_frozen.sh + joern 4.0.608)
"""
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
os.environ.setdefault("REPO", REPO)
sys.path.insert(0, HERE)

SUBGATES = [
    ("cap4 decoder-contract model: positive + adversarial synthetic controls",
     [sys.executable, os.path.join(HERE, "cap_decoder_contract_test.py")], r"^ALL PASS$"),
    ("capabilities 1-3 unchanged (cap2 gate)",
     [sys.executable, os.path.join(HERE, "gate_capability_2.py")], r"^CAP2_GATE=PASS$"),
    ("capabilities 1-3 unchanged (cap3 gate)",
     [sys.executable, os.path.join(HERE, "gate_capability_3.py")], r"^CAP3_GATE=PASS$"),
    ("capability 1 (address-of indexed) controls unchanged",
     [sys.executable, os.path.join(HERE, "cap_addr_indexed_test.py")], r"^ALL PASS$"),
    ("frozen producers unchanged outside cap4's domain (analysis-record-r01)",
     [sys.executable, os.path.join(REPO, "tchecker-research-complete",
      "portable-engine-full-review-package", "tests", "gates",
      "analysis-record-r01", "gate_analysis_record_r01.py")],
     r"^ANALYSIS_RECORD_R01=(\d+)/\1$"),
]

REQUIRED_FILES = ["cap_decoder_contract.py", "cap_decoder_contract_test.py",
                  os.path.join("cap_controls", "cap4_contracts", "authorities",
                               "PROVENANCE.json")]
HELDOUT_FORBIDDEN = ["secvuleval_full", "study/bigvul", "study/arvo", "study/pooled",
                     "FROZEN_heldout"]


def main():
    ok = True
    for f in REQUIRED_FILES:
        present = os.path.exists(os.path.join(HERE, f))
        print(("PASS" if present else "FAIL"), f"impl file present: {f}")
        ok = ok and present

    # every archived authority excerpt hash-verifies against the registry (provenance intact).
    import cap_decoder_contract as C
    _bn, prov = C.load_contracts()
    prov_ok = len(prov) == 4 and all(p["provenance"] == "ok" for p in prov)
    print(("PASS" if prov_ok else "FAIL"),
          "authoritative-provenance: all decoder contracts bound to a verified archived excerpt")
    ok = ok and prov_ok

    # PROVENANCE.json's recorded excerpt hashes actually match the archived excerpt files.
    man = json.load(open(os.path.join(HERE, "cap_controls", "cap4_contracts",
                                       "authorities", "PROVENANCE.json")))
    adir = os.path.join(HERE, "cap_controls", "cap4_contracts", "authorities")
    man_ok = True
    for a in man["authorities"]:
        for e in a["excerpts"]:
            p = os.path.join(adir, e["excerpt_file"])
            h = hashlib.sha256(open(p, "rb").read()).hexdigest() if os.path.exists(p) else None
            if h != e["excerpt_sha256"]:
                man_ok = False
                print("FAIL", f"manifest hash mismatch for {e['excerpt_file']}")
    print(("PASS" if man_ok else "FAIL"),
          "PROVENANCE.json excerpt hashes match the archived authority files")
    ok = ok and man_ok

    leak = False
    for s in ["cap_decoder_contract.py", "cap_decoder_contract_test.py",
              os.path.join("cap_controls", "cap4_decoder", "controls.c")]:
        txt = open(os.path.join(HERE, s)).read()
        for bad in HELDOUT_FORBIDDEN:
            if bad in txt:
                print("FAIL", f"{s} references held-out corpus token '{bad}'"); leak = True
    print(("PASS" if not leak else "FAIL"),
          "no held-out corpus (SecVulEval/Big-Vul/ARVO/pooled) referenced by cap4 code/controls")
    ok = ok and not leak

    for label, argv, rx in SUBGATES:
        try:
            out = subprocess.run(argv, capture_output=True, text=True, timeout=2400)
            body = out.stdout + out.stderr
            passed = any(re.match(rx, ln.strip()) for ln in body.splitlines())
        except Exception as e:
            body, passed = str(e), False
        print(("PASS" if passed else "FAIL"), label)
        if not passed:
            print("\n".join("      " + l for l in body.splitlines()[-8:]))
        ok = ok and passed

    print()
    print("CAP4_GATE=PASS" if ok else "CAP4_GATE=FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
