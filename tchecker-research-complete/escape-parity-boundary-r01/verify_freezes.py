#!/usr/bin/env python3
"""Verify every freeze file, honouring the supersession recorded in FREEZE_LINEAGE.md.

A freeze file is a historical record of what a revision froze. When a later
revision changes one of those artifacts the earlier file is left alone, so a
plain `sha256sum -c` sweep reports failures that are expected. This script
distinguishes the two cases: an entry listed as superseded MUST differ (if it
still matches, the supersession claim is wrong and that is also an error), and
every other entry MUST still match.
"""
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# entry -> the revision that superseded it. Kept here, next to the check, so a
# claim of supersession cannot drift away from what is enforced.
SUPERSEDED = {
    ("FREEZE_HASHES.txt", "producers/escape_parity_facts.sc"): "R05",
    ("CROSS_LANGUAGE_FREEZE.txt", "producers/cpp_escape_parity_facts.sc"): "R05",
    ("CROSS_LANGUAGE_FREEZE.txt", "escape_parity_sites.py"): "R05",
}

FREEZES = ["FREEZE_HASHES.txt", "PARSER_MODEL_FREEZE.txt",
           "CROSS_LANGUAGE_FREEZE.txt", "REACHABILITY_FREEZE.txt",
           "DELIMITER_IDENTITY_FREEZE.txt"]

problems = []
for name in FREEZES:
    path = HERE / name
    if not path.exists():
        problems.append("%s: missing" % name)
        continue
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        want, _, rel = line.partition("  ")
        target = HERE / rel
        if not target.exists():
            problems.append("%s: %s is missing" % (name, rel))
            continue
        got = hashlib.sha256(target.read_bytes()).hexdigest()
        superseded_by = SUPERSEDED.get((name, rel))
        if superseded_by:
            if got == want:
                problems.append(
                    "%s: %s is recorded as superseded by %s but still matches"
                    % (name, rel, superseded_by))
            else:
                print("%-30s %-38s superseded by %s" % (name, rel, superseded_by))
        elif got != want:
            problems.append("%s: %s does not match its frozen hash" % (name, rel))
        else:
            print("%-30s %-38s OK" % (name, rel))

print()
if problems:
    for p in problems:
        print("PROBLEM: %s" % p)
    print("FREEZE_VERIFY=FAIL")
    sys.exit(1)
print("FREEZE_VERIFY=PASS")
