#!/usr/bin/env bash
# JSTS-R06: conformance replay of Gates 3-23 fixtures through the REAL Java core
# (loader -> PortableProvenanceEngine), graded with the six-status ledger.
# Requires: /tmp/replay/g*/program_facts.json (v0.3) and the jsts-r05 build.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
[ -d "$HERE/../jsts-r05/build" ] || { echo "build jsts-r05 first (bash ../jsts-r05/run.sh)"; exit 20; }
python3 "$HERE/check_jsts_r06.py" | tee "$HERE/jsts_r06_ledger.txt"
