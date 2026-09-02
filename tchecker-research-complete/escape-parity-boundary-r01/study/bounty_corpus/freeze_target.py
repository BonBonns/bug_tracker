#!/usr/bin/env python3
"""Pin exactly which source a corpus scan ran over.

A scan result is only meaningful against a named revision and a named file
set.  This records both, plus a sha256 over the sorted (path, content-hash)
list, so a later run can prove it analysed the same bytes or prove it did
not.  Vendored third-party trees are excluded and the exclusion is recorded,
because the frozen Mozilla policy declines bounties for bugs "in or caused by
additional third party software" and for patch gaps against vendored
libraries -- so they are outside this corpus by the program's own terms, not
by our preference.

usage: freeze_target.py <repo_root> <target_key> <out.json>
"""
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

C_EXT = (".c", ".cc", ".cpp", ".cxx")
H_EXT = (".h", ".hh", ".hpp")
JS_EXT = (".js", ".mjs", ".jsm")

# Directory names that mark vendored or generated trees.  Anything under one
# of these is excluded from the analysed set and counted separately.
EXCLUDED_DIRS = {
    ".git", "third_party", "nss", "expat", "vendor", "node_modules",
    "test", "tests", "gtest", "mochitest", "crashtests", "reftests",
}


def git(root, *args):
    return subprocess.run(["git", "-C", root] + list(args),
                          capture_output=True, text=True).stdout.strip()


def classify(path):
    low = path.lower()
    if low.endswith(C_EXT):
        return "C_CPP_SOURCE"
    if low.endswith(H_EXT):
        return "C_CPP_HEADER"
    if low.endswith(JS_EXT):
        return "JAVASCRIPT"
    return None


def main():
    root, key, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    analysed, excluded = [], []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        parts = set([] if rel_dir == "." else rel_dir.split(os.sep))
        skipped = parts & EXCLUDED_DIRS
        # Only .git is pruned from the walk.  Everything else is still visited
        # so that excluded files are *counted*, not silently invisible: a
        # scan that analyses 655 of 655 files and one that analyses 655 of
        # 3,000 are different results and must not look the same.
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for fn in filenames:
            kind = classify(fn)
            if kind is None:
                continue
            rel = os.path.normpath(os.path.join(rel_dir, fn))
            if skipped:
                excluded.append({"path": rel, "kind": kind,
                                 "reason": sorted(skipped)[0]})
                continue
            with open(os.path.join(dirpath, fn), "rb") as fh:
                digest = hashlib.sha256(fh.read()).hexdigest()
            analysed.append({"path": rel, "kind": kind, "sha256": digest})

    analysed.sort(key=lambda r: r["path"])
    excluded.sort(key=lambda r: r["path"])
    roll = hashlib.sha256()
    for r in analysed:
        roll.update((r["path"] + "\0" + r["sha256"] + "\n").encode())

    counts = {}
    for r in analysed:
        counts[r["kind"]] = counts.get(r["kind"], 0) + 1

    sparse = git(root, "sparse-checkout", "list")
    doc = {
        "target": key,
        "frozen_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repo_remote": git(root, "config", "--get", "remote.origin.url"),
        "commit": git(root, "rev-parse", "HEAD"),
        "commit_date": git(root, "log", "-1", "--format=%cI"),
        "checkout_mode": "sparse" if sparse else "full",
        "sparse_paths": sparse.splitlines(),
        "excluded_dir_names": sorted(EXCLUDED_DIRS - {".git"}),
        "exclusion_rationale": (
            "Vendored/third-party and test trees are outside the analysed set. "
            "The frozen program policy declines bounties for bugs in or caused "
            "by third-party software and for patch gaps against vendored "
            "libraries, so they are out of corpus scope by the program's terms."),
        "file_counts": counts,
        "excluded_file_count": len(excluded),
        "analysed_file_count": len(analysed),
        "file_set_sha256": roll.hexdigest(),
        "files": analysed,
        "excluded_files": excluded,
    }
    with open(out_path, "w") as fh:
        json.dump(doc, fh, indent=1)
        fh.write("\n")
    print("target        %s" % key)
    print("commit        %s (%s)" % (doc["commit"][:12], doc["commit_date"]))
    print("sparse paths  %d" % len(doc["sparse_paths"]))
    print("analysed      %s" % counts)
    print("excluded      %d files" % len(excluded))
    print("file set      sha256:%s" % doc["file_set_sha256"])
    print("wrote         %s" % out_path)


if __name__ == "__main__":
    main()
