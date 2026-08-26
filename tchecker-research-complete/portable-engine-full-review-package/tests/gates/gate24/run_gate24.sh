#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
RUN="$HERE/run"
rm -rf "$RUN"; mkdir -p "$RUN/src"
cp "$HERE/fixture/gate24.ts" "$RUN/src/gate24.ts"
"$ROOT/frontends/javascript-typescript/joern/run_real_joern_frontend.sh" "$RUN/src" "$RUN/joern"
python3 "$HERE/check_gate24.py" "$RUN/joern/program_facts.json" | tee "$RUN/result.txt"
