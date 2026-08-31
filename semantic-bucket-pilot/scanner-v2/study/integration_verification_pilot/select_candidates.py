#!/usr/bin/env python3
"""Task #28 next-phase, step 2: FROZEN candidate-selection rule, written before reading any
scanner outcome on these packages. Deterministic: for each property, the alphabetically-FIRST
real package (by package_name) whose cheap text search found >=1 recognized primitive for that
property's own vocabulary. No outcome-based choice -- this script only sorts and picks first,
it does not look at what lock_balance_verdict.py etc. would say about any candidate before
picking it.

Honest disclosure, not concealed: while this 494-package search ran in the background, its own
progress log (read to confirm the process was alive, not to hunt for good candidates) incidentally
showed a few package names with hits (vscode-sqlite3, gdal, electron-edge-js -- all LOCK_FUNCS
hits) before this selection script was written. The selection RULE below is still fully
mechanical (alphabetically-first, not "best-looking"), so this does not let outcome quality
influence which package gets used -- but it is disclosed here rather than silently claimed as
blind, consistent with this whole pilot's own standard.

Run: python3 select_candidates.py <primitive_search_results.jsonl>
"""
import json
import sys

LOCK_ANY = {"pthread_mutex_lock", "pthread_mutex_trylock", "pthread_rwlock_rdlock",
            "pthread_rwlock_wrlock", "wc_LockMutex", "k_mutex_lock", "spin_lock_irqsave",
            "spin_lock", "mutex_lock", "PR_Lock", "EnterCriticalSection",
            "pthread_mutex_unlock", "pthread_rwlock_unlock", "wc_UnLockMutex",
            "k_mutex_unlock", "spin_unlock_irqrestore", "spin_unlock", "mutex_unlock",
            "PR_Unlock", "LeaveCriticalSection"}
WRITE_ANY = {"memcpy", "memmove", "memset", "strncpy", "snprintf", "PORT_Memcpy",
             "PORT_Memmove", "wmemcpy"}
READ_ANY = {"memcpy", "memmove", "strncpy", "PORT_Memcpy", "PORT_Memmove", "wmemcpy"}
CMP_ANY = {"memcmp", "strncmp", "CRYPTO_memcmp"}

VOCABS = {"LOCK_BALANCE": LOCK_ANY, "PROTECTED_FIELD": LOCK_ANY, "OOB_WRITE": WRITE_ANY,
          "OOB_READ": READ_ANY, "OOB_COMPARE": CMP_ANY}


def main():
    recs = [json.loads(l) for l in open(sys.argv[1])]
    recs = [r for r in recs if r["status"] == "SCANNED"]
    recs.sort(key=lambda r: r["package_name"])

    print(f"{len(recs)}/494 packages successfully scanned (cheap text search)")
    print()
    for prop, vocab in VOCABS.items():
        matches = [r for r in recs if vocab & set(r.get("hits", {}).keys())]
        print(f"=== {prop} ({len(matches)} real packages match) ===")
        if not matches:
            print("  NO REAL NPM MATCH FOUND -- falls to historical-case-only per instruction #4")
            continue
        chosen = matches[0]
        print(f"  FROZEN SELECTION (alphabetically first): {chosen['package_name']}@{chosen['version']}")
        for prim, hit in chosen["hits"].items():
            if prim in vocab:
                print(f"    {prim}: {hit['file']}:{hit['line']}: {hit['line_text']}")
        print(f"  (all {len(matches)} matches: {', '.join(m['package_name'] for m in matches[:15])}"
              f"{' ...' if len(matches) > 15 else ''})")
        print()


if __name__ == "__main__":
    main()
