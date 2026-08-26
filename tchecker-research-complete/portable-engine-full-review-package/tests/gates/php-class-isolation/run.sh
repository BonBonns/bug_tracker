#!/usr/bin/env bash
set -e
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
python3 "$ROOT/tests/gates/php-class-isolation/audit.py"
