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

R06 FIX (real bug, found auditing this script against `full_scan_r05_working.jsonl`, a
headerless JSON-Lines file -- see `CHECKPOINT_METADATA_ERRATUM.md`): the original script
unconditionally assumed the source file's first line was a TSV header and subtracted it from
`row_count`, and unconditionally treated the last line as tab-delimited to extract
`last_package_key`. Neither assumption holds for a headerless JSONL source. Proven by direct
audit against the real, still-live file: the actual snapshot bytes were NEVER affected (the
script always wrote the full raw content, header assumption or not) -- only the two metadata
fields (`row_count`, `last_package_key`) were wrong, undercounting every headerless-JSONL
checkpoint's row_count by exactly 1 and recording the ENTIRE last JSON record as
`last_package_key` instead of a real key. This has been true of every full-scan checkpoint
ever taken in this project (confirmed: the `_00000317_` checkpoint's snapshot file has 318
real lines, not 317). Fixed by requiring the caller to state the source shape explicitly
(`has_header`) -- this project's own established discipline is to abstain/require evidence
rather than guess, so auto-detection (e.g. "does the first line parse as JSON") is
deliberately NOT used here: a TSV row could itself parse as valid single-token JSON in
degenerate cases, and guessing wrong would silently reintroduce the same class of bug.
`last_package_key` extraction now recognizes a JSONL record with a `package_name` field
(this project's own real record shape) and renders `package@version`; only falls back to
tab-split for anything else (real TSV rows).

Output: checkpoints/<name>_<row_count>_<sha256[:12]>.tsv (the immutable snapshot) plus a
sidecar checkpoints/<name>_<row_count>_<sha256[:12]>.json recording row_count,
last_package_key, sha256 of the snapshot file itself, source path, has_header, and
wall-clock time -- exactly the fields required for a checkpoint record. Only the snapshot
pair is ever committed to git; the live working file and its log are gitignored.
"""
import hashlib
import json
import sys
import time
from pathlib import Path


def _extract_last_key(last_line):
    """Real-record-aware key extraction. A JSONL record with a package_name field (this
    project's own run_pipeline_one.py record shape) yields 'package@version'; anything else
    (a real TSV row) falls back to the first tab-delimited field, exactly as before."""
    try:
        obj = json.loads(last_line)
    except (json.JSONDecodeError, ValueError):
        obj = None
    if isinstance(obj, dict) and "package_name" in obj:
        return f"{obj['package_name']}@{obj.get('version', '')}"
    return last_line.split("\t", 1)[0]


def make_checkpoint(source_path, name, out_dir, has_header):
    """has_header is REQUIRED and explicit -- never inferred. True for a real TSV file with a
    header row (e.g. eligible_packages.tsv); False for a real headerless JSONL working file
    (e.g. full_scan_r05_working.jsonl)."""
    if not isinstance(has_header, bool):
        raise TypeError(f"has_header must be a real bool, got {type(has_header).__name__}")

    source_path = Path(source_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    raw = source_path.read_bytes()
    # Keep only complete lines -- discard any trailing partial (non-newline-terminated) line.
    if raw and not raw.endswith(b"\n"):
        last_nl = raw.rfind(b"\n")
        raw = raw[:last_nl + 1] if last_nl != -1 else b""

    lines = raw.decode("utf-8", "replace").splitlines()
    header_rows = 1 if has_header else 0
    row_count = max(0, len(lines) - header_rows)
    last_key = _extract_last_key(lines[-1]) if len(lines) > header_rows else ""

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
        "has_header": has_header,
        "row_count": row_count,
        "last_package_key": last_key,
        "sha256": checksum,
        "snapshot_time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "snapshot_path": str(snapshot_path),
    }
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")

    print(json.dumps(meta, indent=2, sort_keys=True))
    return meta


def _parse_has_header(raw_arg):
    if raw_arg in ("true", "True", "1", "header", "has-header"):
        return True
    if raw_arg in ("false", "False", "0", "no-header", "headerless"):
        return False
    raise SystemExit(
        f"make_checkpoint.py: has_header argument must be explicit (true/false), got {raw_arg!r}. "
        "This tool never guesses the source file's shape -- state it."
    )


if __name__ == "__main__":
    if len(sys.argv) != 5:
        raise SystemExit(
            "usage: make_checkpoint.py <source_path> <name> <out_dir> <has_header:true|false>\n"
            "has_header is required and explicit -- e.g. true for a TSV file with a header row, "
            "false for a headerless JSONL working file such as full_scan_r05_working.jsonl."
        )
    source_path, name, out_dir, has_header_arg = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    make_checkpoint(source_path, name, out_dir, _parse_has_header(has_header_arg))
