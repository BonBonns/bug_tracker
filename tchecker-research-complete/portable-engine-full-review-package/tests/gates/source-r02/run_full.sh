#!/usr/bin/env bash
# SOURCE_R02: target recognition + the 9-shape aggregate/source matrix + k1-k5.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../../.." && pwd)"
bash "$HERE/run.sh"
