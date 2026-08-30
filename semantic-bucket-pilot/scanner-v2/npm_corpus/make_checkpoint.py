#!/usr/bin/env python3
"""NPM-CORPUS checkpoint tool: creates an ATOMIC, IMMUTABLE snapshot of a live, actively-
appended-to working file (e.g. eligibility.tsv, still being written by a background process),
without ever committing the live file itself. The live working file is never truncated,
locked, or otherwise disturbed by this script -- it is only read.

Torn-row safety: a background writer flushes after every row (one row = one line), but a
snapshot taken mid-write could still observe a partially-written final line if this script
reads at the exact instant the writer is mid-flush. This script therefore keeps only
COMPLETE, newline-terminated lines -- any trailing partial line (no final '\\n') is discarded
from the snapshot, never included.

Output: checkpoints/<name>_<row_count>_<sha256[:12]>.tsv (the immutable snapshot) plus a
sidecar checkpoints/<name>_<row_count>_<sha256[:12]>.json recording row_count,
last_package_key (first tab-delimited field of the last row), sha256 of the snapshot file
itself, source path, and wall-clock time -- exactly the fields required for a checkpoint
record. Only the snapshot pair is ever committed to git; the live working file and its log
are gitignored.
"""
import hashlib
import json
import sys
import time
from pathlib import Path


def make_checkpoint(source_path, name, out_dir):
    source_path = Path(source_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    raw = source_path.read_bytes()
    # Keep only complete lines -- discard any trailing partial (non-newline-terminated) line.
    if raw and not raw.endswith(b"\n"):
        last_nl = raw.rfind(b"\n")
        raw = raw[:last_nl + 1] if last_nl != -1 else b""

    lines = raw.decode("utf-8", "replace").splitlines()
    row_count = max(0, len(lines) - 1)  # minus header
    last_key = lines[-1].split("\t", 1)[0] if len(lines) > 1 else ""

    checksum = hashlib.sha256(raw).hexdigest()
    stem = f"{name}_{row_count:08d}_{checksum[:12]}"
    snapshot_path = out_dir / f"{stem}.tsv"
    meta_path = out_dir / f"{stem}.json"

    tmp_path = out_dir / f".{stem}.tsv.tmp"
    tmp_path.write_bytes(raw)
    tmp_path.rename(snapshot_path)  # atomic on the same filesystem

    meta = {
        "name": name,
        "source_path": str(source_path),
        "row_count": row_count,
        "last_package_key": last_key,
        "sha256": checksum,
        "snapshot_time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "snapshot_path": str(snapshot_path),
    }
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")

    print(json.dumps(meta, indent=2, sort_keys=True))
    return meta


if __name__ == "__main__":
    source_path, name, out_dir = sys.argv[1], sys.argv[2], sys.argv[3]
    make_checkpoint(source_path, name, out_dir)
