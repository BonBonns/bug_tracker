#!/bin/bash
# Reproduces the module-provenance + dedup verification independently.
set -e
git worktree add /tmp/clean-repro 8b77705 --detach
env -i PATH="/tmp/joern-cli:/usr/bin:/bin:/usr/local/bin" \
  SCANNER_DIR=/tmp/clean-repro/semantic-bucket-pilot/scanner-v2 \
  JOERN=/tmp/joern-cli/joern \
  python3 run_moz_scan_v2.py <cpp.json> <label>
