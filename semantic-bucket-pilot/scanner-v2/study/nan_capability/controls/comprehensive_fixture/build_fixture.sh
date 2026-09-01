#!/bin/bash
# Reproduces cpp_raw/ and js_raw/ from pkg/ via the REAL c2cpg/jssrc2cpg toolchain -- the exact
# commands run to produce the committed raw facts in this directory (and to develop every
# structural check in resource_guard_verdict_nan.py against). Run from this directory.
set -e
JOERN_HOME=/home/user/bug_tracker/tchecker-research-complete/joern-install/joern-cli
CPP_FRONTEND=/home/user/bug_tracker/tchecker-research-complete/portable-engine-full-review-package/tests/gates/cpp-r06/frontend
JS_FRONTEND=/home/user/bug_tracker/tchecker-research-complete/portable-engine-full-review-package/frontends/javascript-typescript/joern
NPM_CORPUS=/home/user/bug_tracker/semantic-bucket-pilot/scanner-v2/npm_corpus

WORK=$(mktemp -d)
trap "rm -rf $WORK" EXIT

# Real nan header staging -- same mechanism run_pipeline_one.py uses for every real corpus
# package (NATIVE_HEADER_DEPS includes "nan").
python3 - "$WORK" <<'EOF'
import sys, os
sys.path.insert(0, os.environ.get("NPM_CORPUS", "/home/user/bug_tracker/semantic-bucket-pilot/scanner-v2/npm_corpus"))
import run_pipeline_one as m
work_root = sys.argv[1]
include_dirs, evidence = m.stage_native_dep_headers(os.path.join(os.path.dirname(__file__) if "__file__" in dir() else ".", "pkg"), work_root)
print("staged:", evidence)
EOF

$JOERN_HOME/c2cpg.sh -o "$WORK/cpp.cpg.bin" --include "$WORK/headers/nan" \
  --define NAPI_DISABLE_CPP_EXCEPTIONS pkg
$JOERN_HOME/jssrc2cpg.sh -o "$WORK/js.cpg.bin" pkg

rm -rf cpp_raw js_raw
$JOERN_HOME/joern --script "$CPP_FRONTEND/export_c_cpp_facts_v03.sc" \
  --param cpgFile="$WORK/cpp.cpg.bin" --param outDir=cpp_raw
$JOERN_HOME/joern --script "$JS_FRONTEND/export_neutral.sc" \
  --param cpgFile="$WORK/js.cpg.bin" --param outDir=js_raw

echo "rebuilt cpp_raw/ and js_raw/ from pkg/ via the real toolchain"
