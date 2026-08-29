#!/bin/bash
# Literal commands used for the nss/lib/freebl pilot scan.
set -e
git clone --depth 1 https://github.com/mozilla/nss.git nss
cd nss && git rev-parse HEAD  # -> 7b5f00bfd3835fee76be428c55e60cdb3366182c

export PATH=/tmp/joern-cli:$PATH
F=$REPO/tchecker-research-complete/portable-engine-full-review-package/tests/gates/cpp-r06/frontend

/tmp/joern-cli/c2cpg.sh /path/to/nss/lib/freebl \
  -o nss_pilot_freebl/cpg.bin \
  --include /path/to/nss/lib \
  --include /path/to/nss/lib/freebl \
  --include /path/to/nss/lib/util \
  --include /path/to/nss/lib/freebl/mpi \
  --include /path/to/nss/lib/freebl/ecl \
  --with-include-auto-discovery

/tmp/joern-cli/joern --script "$F/export_c_cpp_facts_v03.sc" \
  --param cpgFile=nss_pilot_freebl/cpg.bin --param outDir=nss_pilot_freebl/raw

python3 "$F/normalize_c_cpp_facts_v03.py" nss_pilot_freebl/raw nss_pilot_freebl/cpp.json

python3 run_moz_scan.py nss_pilot_freebl/cpp.json "nss@7b5f00b lib/freebl (pilot)"
