#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
RAW="${1:?usage: run_gate41.sh <raw-dir> [program_facts.json]}"
python3 "$HERE/check_gate41"_*.py "$RAW" "${2:-}" | tee "$HERE/gate41.out"
