#!/usr/bin/env python3
"""LOCK-SAFE corpus measurement, round 3: runs both capabilities against the 3 remaining
postcutoff_thread sites left unmeasured in THREAD_SAFETY_R01.md's first round
(case_267d5a93, case_a6eb1f6d, case_f21da596), against real code copied from the real
pinned vulnerable commits. Frozen real Joern v4.0.608 output under study/lockcap/, same
convention as the other check_*.py scripts.

This supersedes round 2's version of this file. Round 2 found 3 issues against these
sites: a compound-guard-condition false positive on &gRandMethodMutex, a depth-exhaustion
artifact hiding behind it, and Capability 2's blindness to plain global variables (as
opposed to struct-field-path expressions). All three were investigated; two were fixed
(COMPOUND-GUARD-R01 / DEPTH-R01 in both capability scripts, GLOBAL-VAR-R01 in Capability
2) and are now asserted here as POSITIVE, confirmed-fixed behavior. The third --
path-insensitivity on &globalRNGMutex -- was deliberately NOT fixed after a general fix
was proven unsound (see THREAD_SAFETY_R01.md's "Round 3" section for the constructed
counter-example: a CFG-topology-only view cannot distinguish this false positive's
flag-guarded-cleanup pattern from a structurally identical genuine missing-unlock bug).
That one assertion below still pins CURRENTLY-WRONG output as an honest, documented
limitation -- read the assertion name and comment, do not read "PASS" as "correct" there.
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
# safety) -- both locks (gRandMethodMutex, globalRNGMutex) are correctly balanced at this
# revision. Round 2 found Capability 1 produced 2 false positives here. Round 3 fixed one
# (gRandMethodMutex, a compound-guard-condition parsing gap) and left the other
# (globalRNGMutex, path-insensitivity) deliberately unfixed with proof that the natural
# general fix is unsound.
r2 = run(CAP1, "raw_case_a6eb1f6d", "out_m_a6eb1f6d")
findings_by_obj = {f["lock_object"]: f for f in r2["findings"]}
ck("case_a6eb1f6d: CONFIRMED FIXED -- &gRandMethodMutex is no longer a false positive. "
   "Root cause was COMPOUND-GUARD-R01: the lock's own guard is a compound "
   "`A && wc_LockMutex(...) == 0` condition, whose comparison node has only 1 CFG "
   "successor (feeding a <operator>.logicalAnd node) rather than the naive 2-way branch "
   "guard_success_start expected, causing it to fall back to unguarded (over-)exploration. "
   "Fixed by walking forward through single-successor chains (branch_point()) to the real "
   "2-way branch before classifying it.",
   "&gRandMethodMutex" not in findings_by_obj)
ck("case_a6eb1f6d: the fix did not just hide the finding -- the lock call is recognized "
   "and now correctly classified balanced across all 2 lock calls in this function",
   r2["classification"].get("BALANCED_ON_ALL_PATHS") == 1
   and r2["classification"].get("LOCK_CALL_FOUND") == 2)
ck("case_a6eb1f6d: KNOWN, DELIBERATELY-UNFIXED FALSE POSITIVE on &globalRNGMutex -- root "
   "cause: PATH-INSENSITIVITY. `if (used_global == 1) wc_UnLockMutex(...)` re-tests a flag "
   "whose value is determined by which EARLIER branch executed; once both branches of that "
   "earlier decision merge back into one CFG node, a purely CFG-reachability walk (no "
   "data-flow/value tracking) cannot tell that the flag's later value is correlated with "
   "which prior branch was taken. A general fix (prune a branch whenever the OTHER branch "
   "resolves without touching the lock object) was designed and then proven UNSOUND via a "
   "constructed counter-example (see THREAD_SAFETY_R01.md): an "
   "`if (a) { /* forgot unlock */ } else { unlock(); } return 0;` bug is CFG-topologically "
   "identical to this legitimate pattern, so the naive fix would silently suppress a real "
   "missing-unlock bug. Deliberately left unfixed rather than risk a hidden false negative. "
   "Real code here is correctly balanced; not a real bug. This is a pinned, honestly-"
   "documented limitation, not a claim of correctness.",
   "&globalRNGMutex" in findings_by_obj)

# --- case_f21da596: wolfSSL_RAND_bytes (locks globalRNGMutex) + wolfSSL_RAND_poll (reseeds
# the SAME globalRNG via wc_RNG_DRBG_Reseed with NO lock at all) -- a GENUINE missing-lock
# bug, Capability 2's exact target shape. Round 2 found this unrecoverable: globalRNG is a
# plain global variable, not a struct-field-path expression (ssl->dtls13Rtx.seenRecords-
# shaped), so protected_field_verdict's field-path signature scheme never saw it at all.
# Round 3 fixed this with GLOBAL-VAR-R01: recognize `<operator>.addressOf` calls on bare
# identifiers matching known globals (collected from locals.tsv rows owned by the file's
# <global> pseudo-method), normalized into a `::name`-namespaced signature kept separate
# from field-path `.`-namespaced signatures.
r3 = run(CAP2, "raw_case_f21da596", "out_m_f21da596")
findings_by_field = {f["field_path"]: f for f in r3["findings"]}
ck("case_f21da596: CONFIRMED FIXED -- Capability 2 now recovers the real missing-lock bug: "
   "wolfSSL_RAND_poll touches ::globalRNG without holding globalRNGMutex, the same lock "
   "that protects it in wolfSSL_RAND_bytes",
   "::globalRNG" in findings_by_field
   and findings_by_field["::globalRNG"]["method_name"] == "wolfSSL_RAND_poll"
   and findings_by_field["::globalRNG"]["inferred_protecting_lock"] == "&globalRNGMutex")
ck("case_f21da596: no false positive introduced on wolfSSL_RAND_bytes's own correctly-"
   "locked access to the same global -- exactly one finding total, not two",
   len(r3["findings"]) == 1)
ck("case_f21da596: the correct access is positively classified PROTECTED_ACCESS, not just "
   "silently absent from findings (confirms the extraction saw it and reasoned about it, "
   "rather than the fix accidentally narrowing what gets extracted)",
   r3["classification"].get("PROTECTED_ACCESS") == 1
   and r3["classification"].get("MISSING_LOCK_CANDIDATE") == 1)

# Capability 1 also runs against the same fixture's wolfSSL_RAND_bytes (simplified from the
# same real code as case_a6eb1f6d) -- reproduces the SAME path-insensitivity false positive
# on globalRNGMutex from a second, independently-built fixture, corroborating the root
# cause rather than being an artifact of one specific fixture's structure. This is the same
# deliberately-unfixed limitation as above, not a regression.
r3b = run(CAP1, "raw_case_f21da596", "out_m_f21da596_cap1")
ck("case_f21da596: the same path-insensitivity false positive on globalRNGMutex reproduces "
   "in this independently-simplified fixture too (corroborates the root cause diagnosis, "
   "not a one-off artifact) -- still deliberately unfixed, same as case_a6eb1f6d above",
   any(f["lock_object"] == "&globalRNGMutex" for f in r3b["findings"]))

print(f"CORPUS_MEASUREMENT_R03={ok}/{total}")
sys.exit(0 if ok == total else 1)
