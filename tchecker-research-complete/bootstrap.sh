#!/usr/bin/env bash
# Installs the pinned Joern used by TChecker's Layer-2 (fresh-CPG) gates into ./joern-install,
# and prints the JOERN_HOME to export. Requires network access to github.com and a JDK (21 used
# in development). Layer-1 hermetic gates do NOT need this.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
JOERN_VERSION="${JOERN_VERSION:-4.0.608}"
DEST="$ROOT/joern-install"
echo "TChecker bootstrap: Joern v$JOERN_VERSION -> $DEST"
command -v java >/dev/null 2>&1 || { echo "WARN: no 'java' on PATH. Install a JDK (21 used in dev) first."; }
java -version 2>&1 | head -1 || true
mkdir -p "$DEST"
URL="https://github.com/joernio/joern/releases/download/v${JOERN_VERSION}/joern-cli.zip"
echo "Downloading $URL"
if command -v curl >/dev/null 2>&1; then curl -fL -o "$DEST/joern-cli.zip" "$URL" || { echo "FAILED to download (network/allowlist?)."; exit 2; }
elif command -v wget >/dev/null 2>&1; then wget -O "$DEST/joern-cli.zip" "$URL" || { echo "FAILED to download."; exit 2; }
else echo "Need curl or wget."; exit 2; fi
( cd "$DEST" && unzip -q -o joern-cli.zip ) || { echo "unzip failed"; exit 2; }
chmod +x "$DEST/joern-cli/"*.sh 2>/dev/null || true
echo
echo "Joern installed. Now export and re-run the suite:"
echo "    export JOERN_HOME=\"$DEST/joern-cli\""
echo "    bash \"$ROOT/run_everything.sh\""
