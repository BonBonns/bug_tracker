#!/usr/bin/env python3
"""LOCK-SAFE corpus measurement, round 2: runs both capabilities against the 3 remaining
postcutoff_thread sites left unmeasured in THREAD_SAFETY_R01.md's first round
(case_267d5a93, case_a6eb1f6d, case_f21da596), against real code copied from the real
pinned vulnerable commits. Frozen real Joern v4.0.608 output under study/lockcap/, same
convention as the other check_*.py scripts.

Unlike those scripts, this one is NOT a pass/fail suite over "expected correct" behavior --
it is a MEASUREMENT, and two of its three assertions intentionally pin CURRENTLY-WRONG
capability output (false positives), each with a diagnosed root cause, as an honest
regression baseline for a future precision-improvement round to fix against. Do not
interpret "PASS" here as "this behavior is correct" for those two -- read the assertion
name and comment.
"""
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).parent
CAP1 = HERE / "lock_balance_verdict.py"
CAP2 = HERE / "protected_field_verdict.py"

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


def run(cap, rawdir, outname):
    outpath = HERE / (outname + ".json")
    subprocess.run([sys.executable, str(cap), str(HERE / "study" / "lockcap" / rawdir), str(outpath)], check=True)
    return json.loads(outpath.read_text())


# --- case_267d5a93: Dtls13RtxAddAck before the DTLS13_MAX_ACK_RECORDS capacity fix. Real
# root cause is a word16-overflow/unbounded-list-growth bug (destination-capacity-write
# territory, not thread-safety) -- the lock/unlock was ALREADY fully balanced at this
# revision. TRUE NEGATIVE expected and observed: confirms the site was correctly excluded
# from being treated as a lock-safety recognition target.
r1 = run(CAP1, "raw_case_267d5a93", "out_m_267d5a93")
ck("case_267d5a93: Capability 1 finds ZERO leaks (true negative -- confirms this is a "
   "capacity bug, not a lock-balance bug, matching the manual diff audit)",
   r1["findings"] == [])
ck("case_267d5a93: the lock call IS recognized and correctly classified balanced "
   "(not simply invisible)", r1["classification"].get("BALANCED_ON_ALL_PATHS") == 1)

# --- case_a6eb1f6d: full wolfSSL_RAND_bytes before the FIPS PID-reseed fix. Real root
# cause is a missing reseed-on-fork check (a cryptographic-freshness bug, not thread-
# safety) -- both locks (gRandMethodMutex, globalRNGMutex) were ALREADY correctly balanced
# at this revision. Capability 1 produces 2 FALSE POSITIVES here, each with a distinct,
# diagnosed root cause -- pinned as a known baseline, not asserted as correct.
r2 = run(CAP1, "raw_case_a6eb1f6d", "out_m_a6eb1f6d")
findings_by_obj = {f["lock_object"]: f for f in r2["findings"]}
ck("case_a6eb1f6d: KNOWN FALSE POSITIVE on &gRandMethodMutex -- root cause: the lock's own "
   "guard is a compound `A && wc_LockMutex(...) == 0` condition, which guard_success_start "
   "only recognizes when the lock call is the comparison's DIRECT, sole condition; it falls "
   "back to the raw (unguarded) lock call as BFS start, over-exploring into unrelated later "
   "code. Real code is correctly balanced; not a real bug. Baseline for a future fix, not a "
   "claim of correctness.",
   "&gRandMethodMutex" in findings_by_obj)
ck("case_a6eb1f6d: KNOWN FALSE POSITIVE on &globalRNGMutex -- root cause: PATH-INSENSITIVITY. "
   "`if (used_global == 1) wc_UnLockMutex(...)` re-tests a flag whose value is determined by "
   "which EARLIER branch executed; once both branches of that earlier decision merge back "
   "into one CFG node, a purely CFG-reachability walk (no data-flow/value tracking) cannot "
   "tell that the flag's later value is correlated with which prior branch was taken, so it "
   "treats the (semantically infeasible on this history) skip-the-unlock successor as "
   "reachable. Real code is correctly balanced; not a real bug. Baseline, not a claim of "
   "correctness.",
   "&globalRNGMutex" in findings_by_obj)

# --- case_f21da596: wolfSSL_RAND_bytes (locks globalRNGMutex) + wolfSSL_RAND_poll (reseeds
# the SAME globalRNG via wc_RNG_DRBG_Reseed with NO lock at all) -- a GENUINE missing-lock
# bug, Capability 2's exact target shape. NOT recoverable as implemented: globalRNG is a
# plain global variable/pointer argument, not a struct-field-path expression
# (ssl->dtls13Rtx.seenRecords-shaped), so protected_field_verdict's field-path signature
# scheme never sees it at all -- confirmed TRUE (zero classification entries, not just
# zero findings, meaning zero field-access calls were even extracted for this pair).
r3 = run(CAP2, "raw_case_f21da596", "out_m_f21da596")
ck("case_f21da596: Capability 2 finds NOTHING for this real missing-lock bug -- confirmed "
   "scope gap (plain global variable, not a struct-field path), not silently working by "
   "accident: zero field-access calls were extracted at all (empty classification), not "
   "just zero findings after extraction",
   r3["findings"] == [] and r3["classification"] == {})
# Capability 1 also runs against the same fixture's wolfSSL_RAND_bytes (simplified from the
# same real code as case_a6eb1f6d) -- reproduces the SAME path-insensitivity false positive
# on globalRNGMutex from a second, independently-built fixture, corroborating the root
# cause rather than being an artifact of one specific fixture's structure.
r3b = run(CAP1, "raw_case_f21da596", "out_m_f21da596_cap1")
ck("case_f21da596: the same path-insensitivity false positive on globalRNGMutex reproduces "
   "in this independently-simplified fixture too (corroborates the root cause diagnosis, "
   "not a one-off artifact)",
   any(f["lock_object"] == "&globalRNGMutex" for f in r3b["findings"]))

print(f"CORPUS_MEASUREMENT_R02={ok}/{total}")
sys.exit(0 if ok == total else 1)
