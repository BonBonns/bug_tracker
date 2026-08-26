#!/usr/bin/env bash
# Gate 39: neutral keyed-state provenance from REAL Joern reproduces prototype Gate-20 truth.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
RAW="${1:-$HERE/../gate20/run/joern/raw}"
if [[ ! -f "$RAW/calls.tsv" ]]; then
  echo "GATE39 needs real-Joern raw facts for the gate20 fixture (pass raw dir as \$1)"; exit 20
fi
python3 "$HERE/check_gate39_state.py" "$RAW" | tee "$HERE/gate39_state.out"
grep -q '^GATE39_STATE=11/11$' "$HERE/gate39_state.out"
