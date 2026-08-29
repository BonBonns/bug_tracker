#!/usr/bin/env python3
"""Capability 2 independent acceptance gate.

Aggregates the FULL evidence required to accept capability 2 (transparent wrapper
summaries) as TWO SEPARATE proof models, run under the frozen frontend joern-c2cpg
v4.0.608. This is capability 2's OWN gate: it does not depend on, and is not implied by,
toolchain acceptance. It runs only synthetic controls, Magma DEVELOPMENT-site real bodies,
and (for the frozen-outputs check) the existing frozen corpus gate. It NEVER touches the
SecVulEval / Big-Vul / ARVO held-out corpora -- no held-out result is inspected here.

Emits CAP2_GATE=PASS iff every sub-gate passes.

Usage: gate_capability_2.py   (requires REPO env + scan_c_frozen.sh + joern 4.0.608)
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
os.environ.setdefault("REPO", REPO)

# Each sub-gate: (label, argv, success_regex). Success is a line matching the regex.
SUBGATES = [
    ("delegation-wrapper model (separate impl) + controls + Magma dev-site",
     [sys.executable, os.path.join(HERE, "cap_wrapper_summary_test.py")],
     r"^ALL PASS$"),
    ("counted-writer/loop model (separate impl) + controls + Magma dev-site",
     [sys.executable, os.path.join(HERE, "cap_counted_loop_writer_test.py")],
     r"^ALL PASS$"),
    ("frozen outputs unchanged outside cap2's domain (analysis-record-r01)",
     [sys.executable, os.path.join(REPO, "tchecker-research-complete",
      "portable-engine-full-review-package", "tests", "gates",
      "analysis-record-r01", "gate_analysis_record_r01.py")],
     r"^ANALYSIS_RECORD_R01=(\d+)/\1$"),
]

# The two models MUST be distinct implementation files (not one merged model).
REQUIRED_FILES = ["cap_wrapper_summary.py", "cap_counted_loop_writer.py",
                  "cap_wrapper_summary_test.py", "cap_counted_loop_writer_test.py"]

# Held-out corpora that this gate must NOT read (attestation: enforced by grep below).
HELDOUT_FORBIDDEN = ["secvuleval_full", "study/bigvul", "study/arvo", "study/pooled",
                     "FROZEN_heldout"]


def main():
    ok = True

    # separate implementations exist
    for f in REQUIRED_FILES:
        present = os.path.exists(os.path.join(HERE, f))
        print(("PASS" if present else "FAIL"), f"separate-impl file present: {f}")
        ok = ok and present

    # neither model nor its controls reference any held-out corpus (no held-out inspected).
    # The gate script itself is excluded: it legitimately names the forbidden tokens to
    # enforce this very check.
    srcs = ["cap_wrapper_summary.py", "cap_counted_loop_writer.py",
            "cap_wrapper_summary_test.py", "cap_counted_loop_writer_test.py",
            os.path.join("cap_controls", "cap2", "controls.c"),
            os.path.join("cap_controls", "cap_loop", "controls.c")]
    leak = False
    for s in srcs:
        txt = open(os.path.join(HERE, s)).read()
        for bad in HELDOUT_FORBIDDEN:
            if bad in txt:
                print("FAIL", f"{s} references held-out corpus token '{bad}'")
                leak = True
    print(("PASS" if not leak else "FAIL"),
          "no held-out corpus (SecVulEval/Big-Vul/ARVO/pooled) referenced by cap2 code/controls")
    ok = ok and not leak

    # run the sub-gates
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
    print("CAP2_GATE=PASS" if ok else "CAP2_GATE=FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
