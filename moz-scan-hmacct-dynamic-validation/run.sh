#!/bin/bash
# Reproduction script for moz-scan-hmacct-dynamic-validation/.
#
# Builds NSS+NSPR with ASan (matching the pinned commits below), creates an
# isolated throwaway NSS DB, compiles mac_init_test.c against the ASan build,
# and runs it. Does not touch any shared/system NSS installation or database.
#
# Usage: NSS_SRC_ROOT=/path/to/scratch ./repo_run.sh
#   NSS_SRC_ROOT will get nss/ and nspr/ cloned into it (or reused if already
#   present and already built). Defaults to a temp dir under $TMPDIR.
set -e

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NSS_COMMIT=7b5f00bfd3835fee76be428c55e60cdb3366182c
NSPR_COMMIT=35205360bebf33f277b1ccc898cd965633494a87

ROOT="${NSS_SRC_ROOT:-$(mktemp -d "${TMPDIR:-/tmp}/nss-mac-init-test.XXXXXX")}"
echo "== Working root: $ROOT =="
mkdir -p "$ROOT"
cd "$ROOT"

if [ ! -d nss ]; then
    git clone https://github.com/mozilla/nss.git
    git -C nss checkout "$NSS_COMMIT"
fi
if [ ! -d nspr ]; then
    git clone https://github.com/mozilla/nspr.git
    git -C nspr checkout "$NSPR_COMMIT"
fi

DIST="$ROOT/dist"
if [ ! -f "$DIST/Debug/lib/libsoftokn3.so" ]; then
    ( cd nss && ./build.sh --asan --disable-tests -j "$(nproc)" -v )
fi

INCLUDES="-I$DIST/public/nss -I$DIST/private/nss -I$DIST/Debug/include/nspr"
LIBDIRS="-L$DIST/Debug/lib"
export LD_LIBRARY_PATH="$DIST/Debug/lib:$LD_LIBRARY_PATH"

DBDIR=$(mktemp -d "$ROOT/nssdb.XXXXXX")
echo "== Isolated NSS DB dir: $DBDIR =="
"$DIST/Debug/bin/certutil" -N -d "sql:$DBDIR" --empty-password

echo "== Compiling mac_init_test.c with ASan (gcc, matching NSS's own build) =="
gcc -g -O0 -fsanitize=address -fno-omit-frame-pointer \
    $INCLUDES \
    -o "$ROOT/mac_init_test" "$HERE/mac_init_test.c" \
    $LIBDIRS -lnss3 -lnssutil3 -lsmime3 -lssl3 -lplc4 -lplds4 -lnspr4 \
    -Wl,-rpath,"$DIST/Debug/lib"

export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:halt_on_error=0:exitcode=1"
export NSS_TEST_DB_DIR="$DBDIR"

echo "== Running probe =="
"$ROOT/mac_init_test"
rv=$?
echo "== mac_init_test exited with status $rv =="
rm -rf "$DBDIR"
exit $rv
