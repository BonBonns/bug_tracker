#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
python3 "$ROOT/tools/js_source_r02_controls.py"
python3 "$ROOT/scanner/test_provenance_scan.py"
