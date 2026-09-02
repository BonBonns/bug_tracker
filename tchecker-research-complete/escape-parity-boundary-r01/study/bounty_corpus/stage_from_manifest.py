#!/usr/bin/env python3
"""Materialise exactly the frozen file set into a clean staging tree.

The analyser is pointed at the staging tree, never at the working checkout,
so the set of files analysed is provably the set of files frozen: each staged
file's content hash is re-verified against the manifest as it is copied, and
a mismatch aborts rather than being analysed silently.

usage: stage_from_manifest.py <manifest.json> <src_root> <stage_root> [kind...]
"""
import hashlib
import json
import os
import shutil
import sys


def main():
    manifest, src, stage = sys.argv[1], sys.argv[2], sys.argv[3]
    kinds = set(sys.argv[4:]) or None
    doc = json.load(open(manifest))
    if os.path.exists(stage):
        shutil.rmtree(stage)
    staged = mismatched = 0
    for rec in doc["files"]:
        if kinds and rec["kind"] not in kinds:
            continue
        srcp = os.path.join(src, rec["path"])
        with open(srcp, "rb") as fh:
            data = fh.read()
        if hashlib.sha256(data).hexdigest() != rec["sha256"]:
            print("HASH MISMATCH %s" % rec["path"], file=sys.stderr)
            mismatched += 1
            continue
        dstp = os.path.join(stage, rec["path"])
        os.makedirs(os.path.dirname(dstp), exist_ok=True)
        with open(dstp, "wb") as fh:
            fh.write(data)
        staged += 1
    if mismatched:
        print("ABORT: %d files differ from the frozen manifest" % mismatched,
              file=sys.stderr)
        return 3
    print("staged %d files (kinds=%s) -> %s"
          % (staged, ",".join(sorted(kinds)) if kinds else "all", stage))
    return 0


if __name__ == "__main__":
    sys.exit(main())
