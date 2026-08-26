#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../../.." && pwd)"; RUN="$HERE/run"
rm -rf "$RUN"; mkdir -p "$RUN/src"
cp "$HERE"/fixtures/*.ts "$RUN/src/"
cp "$HERE"/fixtures/tsconfig.json "$RUN/src/"
set +e
"$ROOT/frontends/javascript-typescript/joern-ts/run_real_joern_ts.sh" "$RUN/src" "$RUN/joern" >"$RUN/frontend.out" 2>"$RUN/frontend.err"
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
  cat "$RUN/frontend.err" >&2
  echo "$rc" > "$RUN/exitcode"
  exit "$rc"
fi
python3 "$HERE/check_gate24_ts.py" "$RUN/joern/typescript_facts.json" | tee "$RUN/result.txt"
