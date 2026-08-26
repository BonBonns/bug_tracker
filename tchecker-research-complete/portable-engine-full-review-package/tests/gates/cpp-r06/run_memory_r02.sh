#!/usr/bin/env bash
# CPP-R02: bounded C/C++ fields, constant-index elements, address-of sublocations,
# exact pointer fields, and exact static pointer-parameter side effects.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
BUILD="$HERE/../jsts-r05/build"
if [ ! -d "$BUILD" ]; then
  rm -rf "$BUILD"; mkdir -p "$BUILD"
  javac -d "$BUILD" \
    $(find "$ROOT/core/program_graph/src/main/java" -name '*.java' | sort) \
    $(find "$ROOT/core/provenance-neutral/src/main/java" -name '*.java' | sort) \
    $(find "$ROOT/core/evidence/src/main/java" -name '*.java' | sort) \
    "$HERE/../jsts-r05/EndToEndRunner.java"
fi
W="$(mktemp -d /tmp/cpp-memory-r02.XXXXXX)"; mkdir -p "$W/raw"
python3 "$HERE/tests/make_memory_r02_raw.py" "$W/raw"
python3 "$HERE/frontend/normalize_c_cpp_facts_v03.py" "$W/raw" "$W/program.json"
java -cp "$BUILD" EndToEndRunner "$W/program.json" "$W/program.json.memory.json" > "$W/e2e.out"
python3 "$HERE/tests/check_memory_r02.py" "$W/program.json" "$W/e2e.out"
echo "CPP_MEMORY_R02_ARTIFACT=$W"
