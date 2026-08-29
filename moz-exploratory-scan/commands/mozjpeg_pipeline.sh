#!/bin/bash
# Literal commands used for the mozjpeg pilot scan (excludes jchuff.c; see PILOT_REPORT.md).
set -e
git clone --depth 1 https://github.com/mozilla/mozjpeg.git mozjpeg
cd mozjpeg && git rev-parse HEAD  # -> 08265790774cd0714832c9e675522acbe5581437
cmake -B build_cfg -DCMAKE_BUILD_TYPE=Release   # generates jconfig.h/jconfigint.h/jversion.h

export PATH=/tmp/joern-cli:$PATH
F=$REPO/tchecker-research-complete/portable-engine-full-review-package/tests/gates/cpp-r06/frontend

/tmp/joern-cli/c2cpg.sh /path/to/mozjpeg \
  -o mozjpeg_pilot/cpg.bin \
  --include /path/to/mozjpeg/build_cfg \
  --exclude jchuff.c \
  --with-include-auto-discovery

/tmp/joern-cli/joern --script "$F/export_c_cpp_facts_v03.sc" \
  --param cpgFile=mozjpeg_pilot/cpg.bin --param outDir=mozjpeg_pilot/raw

python3 "$F/normalize_c_cpp_facts_v03.py" mozjpeg_pilot/raw mozjpeg_pilot/cpp.json

python3 run_moz_scan.py mozjpeg_pilot/cpp.json "mozjpeg@0826579 (full tree minus jchuff.c)"
