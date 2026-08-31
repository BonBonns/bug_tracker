#!/usr/bin/env python3
"""R06 checkpoint-tooling fix: proves the real bug found auditing `make_checkpoint.py`
against the headerless `full_scan_r05_working.jsonl` format, and proves the fix.

The bug: the original script unconditionally treated the source's first line as a TSV
header (row_count = len(lines) - 1) and the last line as tab-delimited
(last_package_key = line.split('\\t', 1)[0]). Neither holds for a headerless JSONL file.
This test reproduces the OLD buggy arithmetic directly (not by re-running old code -- the
file has already been fixed in this worktree -- but by asserting what the old, disclosed
formula would have produced against a real captured example) and confirms the NEW code
requires an explicit has_header and gets both fields right for both real shapes this
project actually uses: headered TSV (eligible_packages.tsv-style) and headerless JSONL
(full_scan_r05_working.jsonl-style).

Run: python3 tests/test_make_checkpoint.py   (exit 0 = PASS)
"""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from make_checkpoint import make_checkpoint, _extract_last_key


def check(name, cond, detail=''):
    status = 'PASS' if cond else 'FAIL'
    print(f'[{status}] {name}' + (f' -- {detail}' if detail and not cond else ''))
    return cond


ok = True

# --- Fixture 1: real-shaped headerless JSONL (full_scan_r05_working.jsonl format) ---
print('=== Fixture 1: headerless JSONL, 3 real-shaped records ===')
records = [
    {"package_name": "pkg-one", "version": "1.0.0", "status": "ANALYZED"},
    {"package_name": "pkg-two", "version": "2.3.1", "status": "RESOURCE_LIMIT"},
    {"package_name": "pkg-three", "version": "0.0.9", "status": "ANALYZED"},
]
jsonl_content = "".join(json.dumps(r) + "\n" for r in records)

with tempfile.TemporaryDirectory() as td:
    src = Path(td) / "working.jsonl"
    src.write_text(jsonl_content)
    out_dir = Path(td) / "checkpoints"

    meta = make_checkpoint(str(src), "test_jsonl", str(out_dir), has_header=False)
    ok &= check("row_count == 3 (not 2)", meta["row_count"] == 3, f"got {meta['row_count']}")
    ok &= check("last_package_key == pkg-three@0.0.9",
                meta["last_package_key"] == "pkg-three@0.0.9",
                f"got {meta['last_package_key']!r}")
    snap = (Path(td) / meta["snapshot_path"]) if not os.path.isabs(meta["snapshot_path"]) else Path(meta["snapshot_path"])
    snap_lines = snap.read_text().splitlines()
    ok &= check("snapshot file itself contains all 3 real lines (never dropped)",
                len(snap_lines) == 3, f"got {len(snap_lines)}")
    ok &= check("snapshot's FIRST line is the FIRST real record (not dropped/shifted)",
                json.loads(snap_lines[0])["package_name"] == "pkg-one",
                f"got {snap_lines[0][:80]!r}")

    print('--- Reproducing the OLD buggy formula against this same real data (disclosed, not re-run) ---')
    lines = jsonl_content.splitlines()
    old_row_count = max(0, len(lines) - 1)  # the old, unconditional "minus header" formula
    old_last_key = lines[-1].split("\t", 1)[0]  # the old, unconditional tab-split
    ok &= check("OLD formula would have undercounted by exactly 1",
                old_row_count == 2, f"old formula gives {old_row_count}, real count is 3")
    ok &= check("OLD formula would have returned the ENTIRE last JSON line as the key, not a real key",
                old_last_key == lines[-1] and "package_name" in old_last_key,
                f"old formula gives {old_last_key!r}")

# --- Fixture 2: real-shaped headered TSV (eligible_packages.tsv format) -- must still work ---
print('=== Fixture 2: headered TSV, 2 real-shaped rows ===')
tsv_content = "package_name\tversion\ttarball_url\nleft-pad\t1.3.0\thttps://example/left-pad.tgz\nright-pad\t2.0.0\thttps://example/right-pad.tgz\n"
with tempfile.TemporaryDirectory() as td:
    src = Path(td) / "eligible.tsv"
    src.write_text(tsv_content)
    out_dir = Path(td) / "checkpoints"
    meta = make_checkpoint(str(src), "test_tsv", str(out_dir), has_header=True)
    ok &= check("row_count == 2 (header correctly excluded)", meta["row_count"] == 2,
                f"got {meta['row_count']}")
    ok &= check("last_package_key == right-pad (tab-split fallback, no package_name JSON field)",
                meta["last_package_key"] == "right-pad", f"got {meta['last_package_key']!r}")

# --- Fixture 3: has_header is REQUIRED -- no silent guessing ---
print('=== Fixture 3: has_header must be an explicit bool ===')
with tempfile.TemporaryDirectory() as td:
    src = Path(td) / "x.jsonl"
    src.write_text('{"package_name": "a", "version": "1"}\n')
    raised = False
    try:
        make_checkpoint(str(src), "n", str(Path(td) / "out"), has_header="false")  # string, not bool
    except TypeError:
        raised = True
    ok &= check("passing a non-bool has_header raises TypeError (never silently coerced)", raised)

# --- Fixture 4: exactly 1 real data line, headerless -- must not report "" as the key ---
print('=== Fixture 4: exactly 1 headerless data line ===')
with tempfile.TemporaryDirectory() as td:
    src = Path(td) / "one.jsonl"
    src.write_text('{"package_name": "solo-pkg", "version": "9.9.9"}\n')
    meta = make_checkpoint(str(src), "test_one", str(Path(td) / "out"), has_header=False)
    ok &= check("row_count == 1", meta["row_count"] == 1, f"got {meta['row_count']}")
    ok &= check("last_package_key populated for a single-line headerless file (old code returned '')",
                meta["last_package_key"] == "solo-pkg@9.9.9", f"got {meta['last_package_key']!r}")

# --- Fixture 5: torn trailing line, headerless -- must still be trimmed, count unaffected by header logic ---
print('=== Fixture 5: torn (incomplete) trailing line, headerless ===')
with tempfile.TemporaryDirectory() as td:
    src = Path(td) / "torn.jsonl"
    complete = json.dumps({"package_name": "complete-pkg", "version": "1.0.0"}) + "\n"
    torn = '{"package_name": "partial-pkg", "vers'  # no trailing newline -- simulates mid-flush read
    src.write_text(complete + torn)
    meta = make_checkpoint(str(src), "test_torn", str(Path(td) / "out"), has_header=False)
    ok &= check("torn trailing line discarded, row_count == 1 (not 2)", meta["row_count"] == 1,
                f"got {meta['row_count']}")
    ok &= check("last_package_key is the COMPLETE record, not the torn one",
                meta["last_package_key"] == "complete-pkg@1.0.0", f"got {meta['last_package_key']!r}")

print()
print('OVERALL:', 'PASS' if ok else 'FAIL')
sys.exit(0 if ok else 1)
