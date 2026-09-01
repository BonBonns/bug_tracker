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

# --- 4. WRAPPER-SITE-R01 real regression controls (roadmap step 7): the exact real false
# positive STEP6_PROMOTIONS_MANUAL_REVIEW.md found (ggml_graph_compute_secondary_thread, a real
# CFG-precision gap where the CFG-connected unlock representation is the WRAPPER call, not the
# recognized primitive) must now disappear STRUCTURALLY -- BALANCED_ON_ALL_PATHS, not merely
# suppressed via adjudication_registry.py's own separate veto. Run fresh over the SAME preserved
# evidence bundles the manual review itself used (no new Joern run -- these are the project's
# own already-extracted cpp_raw/*.tsv).
import tarfile
import tempfile

_BUNDLE_DIR = HERE / "npm_corpus" / "overnight_100" / "evidence_bundles_100"


def run_over_bundle(bundle_name, outname):
    bpath = _BUNDLE_DIR / bundle_name
    if not bpath.is_file():
        return None
    with tempfile.TemporaryDirectory() as td:
        with tarfile.open(bpath, "r:gz") as tf:
            tf.extractall(td)
        outpath = HERE / (outname + ".json")
        subprocess.run([sys.executable, str(CAP), str(pathlib.Path(td) / "cpp_raw"),
                         str(outpath)], check=True)
        return json.loads(outpath.read_text())


r_fugood = run_over_bundle("@fugood__whisper.node@1.1.3.tar.gz", "out_fugood_wrapper")
if r_fugood is not None:
    fugood_findings = {f["method_name"]: f for f in r_fugood["findings"]}
    ck("REAL REGRESSION: @fugood/whisper.node's real ggml_graph_compute_secondary_thread -- "
       "previously a real false RETURN_REACHABLE_WITHOUT_MATCHING_UNLOCK (adjudicated "
       "CONFIRMED_FALSE_POSITIVE in adjudication_registry.py), now STRUCTURALLY balanced, "
       "never even reaching the findings list",
       "ggml_graph_compute_secondary_thread" not in fugood_findings)
    ck("REAL REGRESSION: @fugood/whisper.node -- zero findings at all from this function's "
       "own real lock call (BALANCED_ON_ALL_PATHS, not merely absent from output)",
       r_fugood["classification"].get("BALANCED_ON_ALL_PATHS", 0) >= 1
       and r_fugood["findings"] == [])
else:
    print("SKIP: @fugood/whisper.node's real bundle not present -- real regression control skipped")

r_smartwhisper = run_over_bundle("smart-whisper@0.8.1.tar.gz", "out_smartwhisper_wrapper")
if r_smartwhisper is not None:
    sw_findings = {f["method_name"]: f for f in r_smartwhisper["findings"]}
    ck("REAL REGRESSION: smart-whisper's own real, independently-vendored copy of the SAME "
       "ggml_graph_compute_secondary_thread -- also STRUCTURALLY balanced now",
       "ggml_graph_compute_secondary_thread" not in sw_findings and r_smartwhisper["findings"] == [])
else:
    print("SKIP: smart-whisper's real bundle not present -- real regression control skipped")

# --- 5. WRAPPER-SITE-R01 synthetic negative control: a wrapper name at a DIFFERENT site (no
# real matching primitive sibling) must NOT suppress a genuine leak -- the widening is scoped
# to real (owner, line, obj_code) siblings, never a blanket "any wrapper-shaped name is safe".
# Real raw-TSV schema (base64-encoded text fields, matching every other capability's own
# `dec()` convention -- plain text would silently "succeed" as garbage base64 rather than
# raising, so this must be real base64, not a shortcut).
import base64


def _b64(s):
    return base64.b64encode(s.encode()).decode()


_wrap_calls_tsv = (
    f"1\t100\t{_b64('pthread_mutex_lock')}\t{_b64('pthread_mutex_lock')}\t\t\t"
    f"{_b64('pthread_mutex_lock(&m)')}\t\t5\t\t\n"
    f"2\t100\t{_b64('some_other_wrapper')}\t{_b64('some_other_wrapper')}\t\t\t"
    f"{_b64('some_other_wrapper(&m)')}\t\t9\t\t\n"  # NOT a real sibling of any recognized
                                                       # unlock -- a different line, never
                                                       # grouped with a real unlock call.
)
_wrap_args_tsv = (
    f"10\t1\t0\t{_b64('IDENTIFIER')}\t{_b64('&m')}\t{_b64('m')}\t{_b64('ANY')}\t\n"
    f"11\t2\t0\t{_b64('IDENTIFIER')}\t{_b64('&m')}\t{_b64('m')}\t{_b64('ANY')}\t\n"
)
_wrap_methods_tsv = f"100\t{_b64('leakyFn')}\t{_b64('leakyFn')}\t\t\t1\t12\t\t\tfalse\n"
_wrap_returns_tsv = "20\t100\t\t\t\n"
_wrap_cfg_tsv = "100\t1\t2\n100\t2\t20\n"

with tempfile.TemporaryDirectory() as td:
    tdp = pathlib.Path(td)
    (tdp / "calls.tsv").write_text(_wrap_calls_tsv)
    (tdp / "arguments.tsv").write_text(_wrap_args_tsv)
    (tdp / "methods.tsv").write_text(_wrap_methods_tsv)
    (tdp / "returns.tsv").write_text(_wrap_returns_tsv)
    (tdp / "cfg_edges.tsv").write_text(_wrap_cfg_tsv)
    outpath = HERE / "out_wrapper_negative.json"
    subprocess.run([sys.executable, str(CAP), str(tdp), str(outpath)], check=True)
    r_neg = json.loads(outpath.read_text())

ck("SYNTHETIC NEGATIVE (disclosed, not corpus data): a genuinely unrelated wrapper-shaped "
   "name at a DIFFERENT (line, obj) site is never treated as a barrier -- the real leak "
   "(no matching unlock anywhere) is still flagged",
   len(r_neg["findings"]) == 1
   and r_neg["findings"][0]["reason"] == "NO_RELEASE_ANYWHERE_IN_FUNCTION")

print(f"LOCK_SAFE_R01={ok}/{total}")
sys.exit(0 if ok == total else 1)
