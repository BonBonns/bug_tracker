#!/usr/bin/env python3
"""Task #28 next-phase, step 1: cheap corpus-wide text search for the primitive function
names each of the 5 READY_TO_WIRE C/C++ scanners actually recognizes -- NO c2cpg/Joern run,
just download + extract + grep real C/C++ source text against each scanner's own real,
curated vocabulary (read directly from source, not guessed):

  LOCK_FUNCS / UNLOCK_FUNCS  (lock_balance_verdict.py, protected_field_verdict.py):
    pthread_mutex_lock, pthread_mutex_trylock, pthread_rwlock_rdlock, pthread_rwlock_wrlock,
    wc_LockMutex, k_mutex_lock, spin_lock_irqsave, spin_lock, mutex_lock, PR_Lock,
    EnterCriticalSection / (unlock siblings)

  _OPERAND_ROLES (normalize_c_cpp_facts_v03.py -- consumed by oob_write/read/compare_verdict.py):
    WRITE_DEST-bearing: memcpy, memmove, memset, strncpy, snprintf, PORT_Memcpy,
                         PORT_Memmove, wmemcpy
    READ_SRC-bearing:   memcpy, memmove, strncpy, PORT_Memcpy, PORT_Memmove, wmemcpy
    READ_CMP-bearing:   memcmp, strncmp, CRYPTO_memcmp

This is deliberately CHEAP relative to running Joern on all 494 packages: pure download +
in-memory tar extraction + regex text search, no CPG construction. Every hit records the real
file path and the real matched line's text (first occurrence per primitive per package) so
candidate selection (the next step) can be made from real evidence, not a package-name guess.

Run: python3 cheap_primitive_search.py <out.jsonl> [--workers N]
"""
import concurrent.futures
import io
import json
import re
import sys
import tarfile

sys.path.insert(0, "/tmp/integration_pilot_wt/semantic-bucket-pilot/scanner-v2/npm_corpus")
import run_pipeline_one as P  # noqa: E402 -- reuse the real fetch_bytes (retry/backoff included)

CPP_EXTS = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh", ".hxx")

LOCK_PRIMS = ["pthread_mutex_lock", "pthread_mutex_trylock", "pthread_rwlock_rdlock",
              "pthread_rwlock_wrlock", "wc_LockMutex", "k_mutex_lock",
              "spin_lock_irqsave", "spin_lock", "mutex_lock", "PR_Lock",
              "EnterCriticalSection"]
UNLOCK_PRIMS = ["pthread_mutex_unlock", "pthread_rwlock_unlock", "wc_UnLockMutex",
                "k_mutex_unlock", "spin_unlock_irqrestore", "spin_unlock",
                "mutex_unlock", "PR_Unlock", "LeaveCriticalSection"]
WRITE_PRIMS = ["memcpy", "memmove", "memset", "strncpy", "snprintf", "PORT_Memcpy",
               "PORT_Memmove", "wmemcpy"]
READ_PRIMS = ["memcpy", "memmove", "strncpy", "PORT_Memcpy", "PORT_Memmove", "wmemcpy"]
CMP_PRIMS = ["memcmp", "strncmp", "CRYPTO_memcmp"]

ALL_PRIMS = sorted(set(LOCK_PRIMS + UNLOCK_PRIMS + WRITE_PRIMS + READ_PRIMS + CMP_PRIMS))
PATTERNS = {p: re.compile(r"\b" + re.escape(p) + r"\s*\(") for p in ALL_PRIMS}


def load_eligible():
    rows = []
    with open("/tmp/integration_pilot_wt/semantic-bucket-pilot/scanner-v2/npm_corpus/eligible_packages.tsv") as f:
        header = next(f).rstrip("\n").split("\t")
        idx = {n: i for i, n in enumerate(header)}
        for line in f:
            parts = line.rstrip("\n").split("\t")
            rows.append({"package_name": parts[idx["package_name"]],
                         "version": parts[idx["version"]],
                         "tarball_url": parts[idx["tarball_url"]]})
    return rows


def scan_one(pkg):
    tb, err = P.fetch_bytes(pkg["tarball_url"], timeout=30, retries=2)
    if err:
        return {"package_name": pkg["package_name"], "version": pkg["version"],
                "status": "DOWNLOAD_FAILED", "detail": err}
    hits = {}
    n_cpp_files = 0
    try:
        tf = tarfile.open(fileobj=io.BytesIO(tb), mode="r:gz")
        for member in tf.getmembers():
            if not member.isfile():
                continue
            if not member.name.lower().endswith(CPP_EXTS):
                continue
            n_cpp_files += 1
            try:
                content = tf.extractfile(member).read().decode("utf-8", "replace")
            except Exception:
                continue
            for prim, pat in PATTERNS.items():
                if prim in hits:
                    continue
                m = pat.search(content)
                if m:
                    line_no = content.count("\n", 0, m.start()) + 1
                    line_text = content.splitlines()[line_no - 1].strip()[:200]
                    hits[prim] = {"file": member.name, "line": line_no, "line_text": line_text}
        tf.close()
    except Exception as e:
        return {"package_name": pkg["package_name"], "version": pkg["version"],
                "status": "EXTRACTION_FAILED", "detail": f"{type(e).__name__}: {e}"}
    return {"package_name": pkg["package_name"], "version": pkg["version"],
            "status": "SCANNED", "n_cpp_files_scanned": n_cpp_files, "hits": hits}


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else "primitive_search_results.jsonl"
    workers = 16
    if "--workers" in sys.argv:
        workers = int(sys.argv[sys.argv.index("--workers") + 1])

    pkgs = load_eligible()
    print(f"scanning {len(pkgs)} packages with {workers} workers", file=sys.stderr)

    done = 0
    with open(out_path, "w") as outf, \
         concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_one, pkg): pkg for pkg in pkgs}
        for fut in concurrent.futures.as_completed(futures):
            rec = fut.result()
            outf.write(json.dumps(rec) + "\n")
            outf.flush()
            done += 1
            if done % 25 == 0 or done == len(pkgs):
                print(f"[{done}/{len(pkgs)}] {rec['package_name']}: {rec['status']} "
                      f"hits={list(rec.get('hits', {}).keys())}", file=sys.stderr)

    print(f"\nWrote {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
