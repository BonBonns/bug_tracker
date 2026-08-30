#!/usr/bin/env python3
"""LOCK-SAFE-R02 regression: runs protected_field_verdict.py against FROZEN real Joern
output (v4.0.608, checked into study/lockcap/, reproduces without Joern). Two fixtures:

  raw_xfn_real/   -- Dtls13RtxAddAck (locks ssl->dtls13Rtx.seenRecords via
                     ssl->dtls13Rtx.mutex) and Dtls13RtxRemoveCurAck (touches the SAME
                     field, no lock at all) copied VERBATIM from the real wolfSSL commit
                     3034dd9e -- development-site recovery for case_644b3e3c
                     (THREAD_SAFETY_R01.md), the shape Capability 1 explicitly could not
                     cover.
  raw_xfn_synth/  -- 3 hand-designed negative/ambiguity controls: a field consistently
                     protected everywhere (no finding), a field never touched under any
                     lock anywhere (no evidence, no finding), a field protected by two
                     DIFFERENT locks in different functions (ambiguous, abstain on both).

Regenerating the frozen raw facts: same procedure as check_lock_balance.py's docstring,
against the fixture_source.c in each directory.
"""
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).parent
CAP = HERE / "protected_field_verdict.py"

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


def run(rawdir, outname):
    outpath = HERE / (outname + ".json")
    subprocess.run([sys.executable, str(CAP), str(HERE / "study" / "lockcap" / rawdir), str(outpath)], check=True)
    return json.loads(outpath.read_text())


# --- 1. Development-site recovery: the real vulnerable Dtls13RtxRemoveCurAck / AddAck pair.
r = run("raw_xfn_real", "out_xfn_real")
findings = r["findings"]
ck("real xfn fixture: exactly 2 findings (both real seenRecords accesses in "
   "Dtls13RtxRemoveCurAck, the case_644b3e3c bug)", len(findings) == 2)
ck("both findings are in Dtls13RtxRemoveCurAck, not Dtls13RtxAddAck",
   findings and all(f["method_name"] == "Dtls13RtxRemoveCurAck" for f in findings))
ck("both findings are the real field (ssl->dtls13Rtx.seenRecords), not incidental noise",
   findings and all(f["field_path"] == ".dtls13Rtx.seenRecords" for f in findings))
ck("inferred protecting lock correctly identified as ssl->dtls13Rtx.mutex",
   findings and all(f["inferred_protecting_lock"] == ".dtls13Rtx.mutex" for f in findings))
ck("no false positive on generic single-segment fields incidentally touched inside the "
   "lock in Dtls13RtxAddAck (.next/.heap/.epoch/.seq -- found and fixed via MULTI-SEGMENT-R01)",
   not any(f["field_path"].count(".") + f["field_path"].count("->") < 2 for f in findings))
ck("the lock object itself (ssl->dtls13Rtx.mutex) never flagged as needing its own "
   "protection (LOCK-OBJECT-EXCLUSION-R01)",
   not any(f["field_path"] == ".dtls13Rtx.mutex" for f in findings))

# --- 2. Synthetic controls.
r2 = run("raw_xfn_synth", "out_xfn_synth")
ck("consistently-protected field: zero findings (negative control)",
   not any(f["field_path"] == ".grpA.fieldX" for f in r2["findings"]))
ck("consistently-protected field: both accesses classified PROTECTED_ACCESS",
   r2["classification"].get("PROTECTED_ACCESS") == 2)
ck("never-locked field: zero findings, no evidence means no guess (negative control)",
   not any(f["field_path"] == ".grpB.fieldY" for f in r2["findings"]))
ck("two-different-locks field: zero findings on EITHER access (ambiguity control -- "
   "abstain rather than guess which lock is real)",
   not any(f["field_path"] == ".grpC.fieldZ" for f in r2["findings"]))
ck("two-different-locks field: classified AMBIGUOUS_MULTIPLE_PROTECTORS, not silently dropped",
   r2["classification"].get("AMBIGUOUS_MULTIPLE_PROTECTORS") == 1)

print(f"LOCK_SAFE_R02={ok}/{total}")
sys.exit(0 if ok == total else 1)
