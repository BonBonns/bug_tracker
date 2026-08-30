#!/usr/bin/env python3
"""THREAD-R01: freeze a held-out corpus for a NEW property -- missing/incorrect lock-unlock
pairing (thread-safety) -- from PostCutoff-CVE (NO model calls, NO TChecker, NO manual
per-site interpretation, NO detection capability built here). This is corpus construction
only, mirroring exactly how postcutoff_freeze.py/secvuleval_freeze.py built the destination-
capacity-write corpus: pre-register CWE scope and the two deterministic rules BEFORE looking
at any yield, freeze, report counts. Building a scanner CAPABILITY that recognizes these
sites is a separate, later undertaking (the write property's own Capability 1 alone took a
dedicated round after its corpus existed) -- not attempted here.

Motivation: found while auditing the write-property corpus (POSTCUTOFF_WRITE_MAPPING_AUDIT.md).
Two wolfSSL sites (case_644b3e3c, case_e062ef20 -- dtls13.c missing mutex lock/unlock around a
list traversal and before early returns) were correctly excluded as NOT destination-capacity
write bugs -- but they ARE real, CVE-confirmed thread-safety bugs, evidence-verified against
the real diffs at the real pinned commits. That's the seed for the LOCK/UNLOCK function
regex below (wolfSSL's own wc_LockMutex/wc_UnLockMutex, real wrapper names, not guessed).

RULE 1 - lock-SITE mapping (object-identity uniqueness, NOT function-name uniqueness): map
         the diff hunk to a UNIQUE lock-OBJECT expression across the hunk (e.g.
         "&ssl->dtls13Rtx.mutex"); mapped / ambiguous / no_lock_op_found; only mapped sites
         score. Deliberately different from postcutoff_freeze.py's write-site rule (which
         dedupes by (kind, dest)): a single coherent lock fix routinely touches the SAME
         object with one acquire and several releases (one per early-return exit path) --
         caught by a pre-freeze sanity test against the two real motivating sites, where
         dedup-by-(kind,name) wrongly called that shape "ambiguous". Multiple DIFFERENT
         objects in one hunk still can't be disambiguated, so that stays ambiguous.
RULE 2 - family assignment: family_id = hash(primitive_family | op_shape) from diff
         structure only, where op_shape is the frozen-sorted set of (change_kind, lock_kind)
         pairs seen on that object (e.g. {(ADDED,lock_acquire),(ADDED,lock_release)} for a
         from-scratch missing-lock fix vs {(ADDED,lock_release)} alone for a missing-unlock-
         on-one-path fix) -- frozen now, never recomputed after any capability output.

Usage: thread_freeze.py <pccve_dir> <repo_commit>
"""
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secvuleval_freeze as S   # reuse strip_comments only -- thread-specific detection below

# THREAD-CWE scope: concurrency/synchronization CWEs whose fix shape is plausibly a
# lock/unlock call change (RULE 1 needs a lock-API CALL to detect anything at all).
# Deliberately EXCLUDES CWE-367 (TOCTOU) -- a file-race property, not a lock-call property;
# including it would just inflate no_lock_op_found, never a real site.
THREAD_CWE = {362, 366, 413, 414, 667, 820, 821}
MAGMA_REPOS = {"openssl/openssl", "pnggroup/libpng", "libpng/libpng", "the-tcpdump-group/libpcap"}

# LOCK/UNLOCK: evidence-seeded, not a guessed generic net (same discipline as COPY in
# secvuleval_freeze.py). wc_LockMutex/wc_UnLockMutex confirmed real from the wolfSSL
# dtls13.c sites that motivated this track. The rest are well-documented, standard
# concurrency-primitive APIs (POSIX pthreads; Zephyr's k_mutex; Linux-kernel-style
# spin_lock/mutex_lock common in embedded/openwrt driver code; NSPR's PR_Lock, relevant to
# this project's own NSS work; Win32 Critical Sections) -- not fabricated, but NOT
# individually re-verified against a real header the way wc_LockMutex was; treat non-wolfSSL
# entries as standard-API assumptions, flagged explicitly in THREAD_SAFETY_R01.md rather
# than silently presented as equally evidenced.
LOCK = re.compile(r"\b(pthread_mutex_lock|pthread_mutex_trylock|pthread_rwlock_rdlock|"
                  r"pthread_rwlock_wrlock|wc_LockMutex|k_mutex_lock|spin_lock_irqsave|"
                  r"spin_lock|mutex_lock|PR_Lock|EnterCriticalSection)\s*\(")
UNLOCK = re.compile(r"\b(pthread_mutex_unlock|pthread_rwlock_unlock|wc_UnLockMutex|"
                    r"k_mutex_unlock|spin_unlock_irqrestore|spin_unlock|mutex_unlock|"
                    r"PR_Unlock|LeaveCriticalSection)\s*\(")
OBJ_ARG = re.compile(r"\s*([^,)]+?)\s*[,)]")

PRIMITIVE_FAMILY = {
    "pthread_mutex_lock": "pthread_mutex", "pthread_mutex_trylock": "pthread_mutex",
    "pthread_mutex_unlock": "pthread_mutex",
    "pthread_rwlock_rdlock": "pthread_rwlock", "pthread_rwlock_wrlock": "pthread_rwlock",
    "pthread_rwlock_unlock": "pthread_rwlock",
    "wc_LockMutex": "wolfssl_wc_mutex", "wc_UnLockMutex": "wolfssl_wc_mutex",
    "k_mutex_lock": "zephyr_k_mutex", "k_mutex_unlock": "zephyr_k_mutex",
    "spin_lock": "kernel_spinlock", "spin_lock_irqsave": "kernel_spinlock",
    "spin_unlock": "kernel_spinlock", "spin_unlock_irqrestore": "kernel_spinlock",
    "mutex_lock": "kernel_mutex", "mutex_unlock": "kernel_mutex",
    "PR_Lock": "nspr_lock", "PR_Unlock": "nspr_lock",
    "EnterCriticalSection": "win32_critsec", "LeaveCriticalSection": "win32_critsec",
}


def diff_hunk_lines_marked(diff):
    """Like postcutoff_freeze.diff_hunk_lines but KEEPS the leading +/-/space marker --
    the primary structural signal for lock-bug shape (missing-lock ADDED vs missing-unlock
    ADDED vs over-locking REMOVED). The marker character is non-word, so it never affects
    \\b word-boundary matching of the lock/unlock function names that follow it."""
    out = []
    for l in diff.splitlines():
        if l[:3] in ("+++", "---") or l.startswith("@@") or l.startswith("diff ") or l.startswith("index "):
            continue
        if l[:1] in ("+", "-", " "):
            out.append(l)
    return out


def locks_in(marked_lines):
    """All lock/unlock ops: (rel_line, kind, primitive_name, primitive_family, obj_expr,
    change_kind, full_line). Comment-stripped (COMMENT-R01, same as the write property)
    before matching; obj_expr is the lock-call's first argument, normalized only by
    surrounding-whitespace strip (the identity key RULE 1 dedupes on)."""
    stripped = S.strip_comments([l[1:] if l[:1] in ("+", "-", " ") else l for l in marked_lines])
    out = []
    for marked, l in zip(marked_lines, stripped):
        change_kind = {"+": "ADDED", "-": "REMOVED"}.get(marked[:1], "CONTEXT")
        for pat, kind in ((LOCK, "lock_acquire"), (UNLOCK, "lock_release")):
            m = pat.search(l)
            if not m:
                continue
            fn = m.group(1)
            am = OBJ_ARG.match(l[m.end():])
            obj = am.group(1).strip() if am else "?"
            out.append((kind, fn, PRIMITIVE_FAMILY[fn], obj, change_kind, l.strip()))
            break
    return out


def map_site(ops):
    """RULE 1: unique lock-OBJECT across the whole hunk. Returns (status, obj_or_None,
    matched_ops_on_that_object)."""
    if not ops:
        return "no_lock_op_found", None, []
    objs = {o[3] for o in ops}
    if len(objs) != 1:
        return "ambiguous", None, []
    obj = next(iter(objs))
    return "mapped", obj, [o for o in ops if o[3] == obj]


def family_id(primitive_family, matched_ops):
    op_shape = tuple(sorted({(o[4], o[0]) for o in matched_ops}))   # (change_kind, lock_kind)
    sig = f"{primitive_family}|{op_shape}"
    return sig, "famT_" + hashlib.sha256(sig.encode()).hexdigest()[:12]


def main():
    d, commit = sys.argv[1], sys.argv[2]
    idx = {json.loads(l)["benchmark_id"]: json.loads(l) for l in open(f"{d}/data/sample_index.jsonl")}
    bi_raw = open(f"{d}/data/blind_inputs.jsonl", "rb").read()
    bi = {json.loads(l)["benchmark_id"]: json.loads(l) for l in bi_raw.splitlines()}

    excl = Counter()
    sites = []
    for cid, r in idx.items():
        cwes = set(r["strata"].get("cwe_ids") or [])
        repo = r["repository"]["canonical_id"]
        if r["binary_label"] != "vulnerability_fix":
            excl["non_vulnerability_fix"] += 1; continue
        # CWE-R01: NOT gated on THREAD_CWE. A pre-freeze sanity check against the two real
        # motivating sites (case_644b3e3c, case_e062ef20) found BOTH are labeled CWE-122
        # (heap overflow) ONLY in this dataset -- no concurrency CWE at all -- so a CWE-based
        # inclusion filter here would have silently excluded the exact evidence that
        # motivated this track. cwe_ids is still recorded per site (informational), but RULE
        # 1's lock-object detection is the sole inclusion mechanism: a site either has a
        # lock-op-shaped diff or it doesn't, exactly like "no_write_found" already gates the
        # write property regardless of what CWE-family filtering narrowed the candidate pool
        # to there. This is a real, evidence-driven divergence from postcutoff_freeze.py's
        # design, not an oversight -- see THREAD_SAFETY_R01.md.
        if repo in MAGMA_REPOS:
            excl["magma_overlap_repo"] += 1; continue
        diff = bi.get(cid, {}).get("diff", "")
        if not re.search(r"\.(c|cc|cpp|cxx|h|hpp)\b", diff):
            excl["not_c_cpp"] += 1; continue
        marked = diff_hunk_lines_marked(diff)
        ops = locks_in(marked)
        status, obj, matched = map_site(ops)
        rec = {"benchmark_id": cid, "repository": repo,
               "cve": (r["identifiers"].get("cve_id") or (r["identifiers"].get("cve_ids") or [None])[0]),
               "cwe_ids": sorted(cwes), "binary_label": r["binary_label"],
               "time_band": r.get("time_band"),
               "diff_sha256": hashlib.sha256(diff.encode()).hexdigest(),
               "mapping_status": status}
        if status == "mapped":
            fam = matched[0][2]
            rec["lock_object"] = obj
            rec["primitive_family"] = fam
            rec["op_shape"] = sorted({f"{o[4]}:{o[0]}" for o in matched})
            rec["num_ops"] = len(matched)
            sig, fid = family_id(fam, matched)
            rec["family_signature"] = sig; rec["family_id"] = fid
        sites.append(rec)

    mapped = [s for s in sites if s["mapping_status"] == "mapped"]
    fams = {s["family_id"] for s in mapped}
    manifest = {
        "FROZEN": True, "model_calls": 0, "tchecker_used": False, "capability_built": False,
        "source": "PostCutoff-CVE v1.0.0 (github.com/20000419/postcutoff-cve-dataset)",
        "why_this_property": "Found while auditing the write-property corpus: 2 real, "
                             "CVE-confirmed thread-safety wolfSSL sites (case_644b3e3c, "
                             "case_e062ef20) were correctly excluded as not destination-"
                             "capacity write bugs, but are a real, distinct bug class worth "
                             "its own track. See THREAD_SAFETY_R01.md.",
        "pinned_repo_commit": commit,
        "blind_inputs_sha256": hashlib.sha256(bi_raw).hexdigest(),
        "rule_1_lock_site_mapping": "deterministic: map the diff hunk to a UNIQUE lock-OBJECT "
                                    "expression across the hunk (NOT unique by function name -- "
                                    "one coherent fix routinely has 1 acquire + N releases on "
                                    "the SAME object, one per exit path); mapped/ambiguous/"
                                    "no_lock_op_found; only mapped sites score.",
        "rule_2_family_assignment": "family_id = hash(primitive_family | op_shape) where "
                                    "op_shape is the sorted set of (change_kind, lock_kind) "
                                    "pairs on the mapped object -- frozen now, never "
                                    "recomputed after any capability output.",
        "inclusion": "binary_label==vulnerability_fix; remove Magma-overlap repos; C/C++ "
                     "diff only. NOT CWE-gated (see cwe_r01_note) -- RULE 1's lock-object "
                     "detection is the sole inclusion mechanism.",
        "cwe_r01_note": "THREAD_CWE {362,366,413,414,667,820,821} was tried first (mirroring "
                        "postcutoff_freeze.py) and dropped as a gate: both real motivating "
                        "sites (case_644b3e3c, case_e062ef20) are labeled CWE-122 only in "
                        "this dataset, no concurrency CWE at all, so CWE gating would have "
                        "excluded the evidence that motivated this track. cwe_ids is still "
                        "recorded per mapped site for reference.",
        "twelve_family_gate_note": "Carries over the same generic >=12 minimum-inference gate "
                                   "used for the write property and for Juliet -- a "
                                   "pre-registered convention across this project's corpora, "
                                   "not independently re-derived for this property.",
        "exclusions": dict(excl),
        "counts": {
            "sites_after_filters": len(sites),
            "mapping": dict(Counter(s["mapping_status"] for s in sites)),
            "mapped_total": len(mapped),
            "families": len(fams),
            "family_sizes": dict(Counter(s["family_id"] for s in mapped)),
            "by_repo_mapped": dict(Counter(s["repository"] for s in mapped)),
            "by_primitive_family": dict(Counter(s["primitive_family"] for s in mapped)),
        },
        "twelve_family_gate": {"gate": 12, "families": len(fams), "meets_gate": len(fams) >= 12},
        "confirmatory_protocol": "Run a frozen capability (once built, separately) on the "
                                 "mapped sites; score exact-site recognition against these "
                                 "labels. No capability exists yet -- this file is corpus "
                                 "construction only. Yields NOT inspected before freezing.",
        "sites": sites,
    }
    outp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "study", "postcutoff_thread",
                        "FROZEN_heldout.json")
    os.makedirs(os.path.dirname(outp), exist_ok=True)
    json.dump(manifest, open(outp, "w"), indent=2, sort_keys=True)
    print("sites after filters:", len(sites), " exclusions:", dict(excl))
    print("mapping:", dict(Counter(s["mapping_status"] for s in sites)))
    print(f"MAPPED sites: {len(mapped)}   FAMILIES: {len(fams)}  "
          f"(12-gate: {'MEETS' if len(fams) >= 12 else 'BELOW'})")
    print("by repo:", dict(Counter(s["repository"] for s in mapped)))
    print("by primitive family:", dict(Counter(s["primitive_family"] for s in mapped)))
    print("family signatures:", sorted({s["family_signature"] for s in mapped}))
    print("frozen ->", outp)


if __name__ == "__main__":
    main()
