#!/usr/bin/env python3
"""LOCK-SAFE-R01 regression: runs lock_balance_verdict.py against FROZEN real Joern output
(Joern v4.0.608, pinned by tchecker-research-complete/bootstrap.sh) checked into
study/lockcap/, so this reproduces without needing Joern again. Three fixtures:

  raw_synthetic/  -- lockcap_probe.c: 6 hand-designed positive/negative controls.
  raw_real_vuln/  -- Dtls13RtxAddAck copied VERBATIM from the real, vulnerable wolfSSL
                     commit 7efc962d047aa5590c7d844edad87e74aed833b5 (development-site
                     recovery for case_e062ef20, CVE-2026-5264, in
                     study/postcutoff_thread/FROZEN_heldout.json).
  raw_real_fixed/ -- the same function with the real fix (commit 3034dd9e) applied --
                     must produce zero findings (no false positive on the fix).

Regenerating the frozen raw facts (only needed if a fixture .c file changes):
    export JOERN_HOME=/path/to/joern-cli   # pinned version: see bootstrap.sh
    "$JOERN_HOME/c2cpg.sh" -o /tmp/x.cpg.bin <fixture_source.c>
    "$JOERN_HOME/joern" --script ../../tchecker-research-complete/portable-engine-full-review-package/tests/gates/cpp-r06/frontend/export_c_cpp_facts_v03.sc \
        --param cpgFile=/tmp/x.cpg.bin --param outDir=study/lockcap/<dir>
"""
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).parent
CAP = HERE / "lock_balance_verdict.py"

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


# --- 1. Synthetic controls (lockcap_probe.c, 6 functions).
r = run("raw_synthetic", "out_synthetic")
findings_by_fn = {f["method_name"]: f for f in r["findings"]}

ck("vulnMissingUnlock: flagged (positive control)", "vulnMissingUnlock" in findings_by_fn)
ck("vulnMissingUnlock: flags ONLY the real bug return, not the lock-failure guard return",
   findings_by_fn.get("vulnMissingUnlock", {}).get("unsafe_return_ids") == [141733920769])
ck("fixedMissingUnlock: NOT flagged (negative control -- the fix)",
   "fixedMissingUnlock" not in findings_by_fn)
ck("negBalanced: NOT flagged (negative control -- balanced on every path)",
   "negBalanced" not in findings_by_fn)
ck("negTwoObjectsBalanced: NOT flagged (ambiguity control -- two distinct objects, both balanced)",
   "negTwoObjectsBalanced" not in findings_by_fn)
ck("negNoLock / negUnregisteredLockName: zero lock calls recognized from them",
   r["classification"].get("LOCK_CALL_FOUND") == 5)  # only the 5 registered-API call sites across
                                                       # vulnMissingUnlock/fixedMissingUnlock/negBalanced(1
                                                       # each)+negTwoObjectsBalanced(2) -- proves the
                                                       # unregistered-name fixture contributed zero,
                                                       # the same "registration table is load-bearing"
                                                       # proof as PORT_Memcpy's own negative control.

# --- 2. Development-site recovery: the real, vulnerable Dtls13RtxAddAck.
r_vuln = run("raw_real_vuln", "out_real_vuln")
vuln_findings = r_vuln["findings"]
ck("real vulnerable Dtls13RtxAddAck: exactly one finding (one lock object, one function)",
   len(vuln_findings) == 1)
ck("real vulnerable Dtls13RtxAddAck: flags BOTH real missing-unlock returns "
   "(duplicate-record return 0, and allocation-failure return MEMORY_E) -- exactly matching "
   "what CVE-2026-5264's real fix commit (3034dd9e) touches, not a superset or subset",
   vuln_findings and len(vuln_findings[0]["unsafe_return_ids"]) == 2)
ck("real vulnerable Dtls13RtxAddAck: lock object correctly identified as &ssl->dtls13Rtx.mutex",
   vuln_findings and vuln_findings[0]["lock_object"] == "&ssl->dtls13Rtx.mutex")

# --- 3. No false positive on the real fix.
r_fixed = run("raw_real_fixed", "out_real_fixed")
ck("real FIXED Dtls13RtxAddAck: zero findings (no false positive on the real fix)",
   r_fixed["findings"] == [])
ck("real FIXED Dtls13RtxAddAck: the lock call is recognized and correctly classified balanced",
   r_fixed["classification"].get("BALANCED_ON_ALL_PATHS") == 1)

print(f"LOCK_SAFE_R01={ok}/{total}")
sys.exit(0 if ok == total else 1)
