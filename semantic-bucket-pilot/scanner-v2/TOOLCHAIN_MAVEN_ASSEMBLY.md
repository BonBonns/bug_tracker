# Pinned Joern v4.0.608 toolchain in this environment (Maven assembly + astgen build)

`tchecker-research-complete/bootstrap.sh` downloads the Joern v4.0.608 CLI from a
GitHub release zip. That release asset (and the astgen release binary jssrc2cpg needs)
is **unreachable through this environment's outbound proxy** (HTTP 404/403 on
`github.com/.../releases/download/...`). Git reads are served, so the identical pinned
version is assembled from sources/Maven Central instead. This file is the recipe, so
`check_provenance.py` and `run_pipeline_one.py` (which both invoke
`joern-install/joern-cli/*.sh`) run the real, pinned toolchain here. None of this is a
version change -- every artifact is Joern 4.0.608 / astgen 3.47.0, the pinned versions.

## 1. C/C++ + console (c2cpg, ReplBridge) from Maven Central

```
mkdir -p /home/user/joern-mvn && cd /home/user/joern-mvn
# pom.xml with deps: io.joern:joern-cli_3, c2cpg_3, jssrc2cpg_3 -- all 4.0.608
mvn -B dependency:build-classpath -Dmdep.outputFile=/home/user/joern-mvn/cp.txt
```

Entry points on that classpath: `io.joern.c2cpg.Main`,
`io.joern.jssrc2cpg.Main`, `io.joern.joerncli.console.ReplBridge` (serves
`--script`; run from a dir containing an empty `.installation_root` marker).

## 2. astgen 3.47.0 (jssrc2cpg's JS parser) built from source

jssrc2cpg 4.0.608 pins astgen 3.47.0 (`jssrc2cpg/src/main/resources/application.conf`),
distributed only as a GitHub release binary (proxy-blocked). Built from source instead:

```
git clone --depth 1 https://github.com/joernio/astgen-monorepo /home/user/joernio/astgen-monorepo
cd /home/user/joernio/astgen-monorepo/javascript-astgen   # package.json version == 3.47.0
PATH=/opt/node22/bin:$PATH yarn install --ignore-engines   # engines want node>=24; tsc builds under 22
PATH=/opt/node22/bin:$PATH npx tsc --build                 # -> dist/astgen.js
```

Wrapped as an executable `ASTGEN_BIN` (jssrc2cpg's documented override env var):

```
/home/user/astgen-bin:
  #!/usr/bin/env bash
  exec /opt/node22/bin/node /home/user/joernio/astgen-monorepo/javascript-astgen/dist/astgen.js "$@"
```

## 3. Shim launchers at the path the frozen pipeline files expect

`tchecker-research-complete/joern-install/joern-cli/` (gitignored -- the same path
bootstrap.sh installs to) holds thin launchers that exec the Maven classpath entry
points, so `JOERN_HOME/c2cpg.sh|jssrc2cpg.sh|joern` work unchanged for
`check_provenance.py` and `run_pipeline_one.py`:

- `c2cpg.sh`     -> `java -cp $CP io.joern.c2cpg.Main "$@"`
- `jssrc2cpg.sh` -> `export ASTGEN_BIN=/home/user/astgen-bin; java -cp $CP io.joern.jssrc2cpg.Main "$@"`
- `joern`        -> `cd <this dir>; java -cp $CP io.joern.joerncli.console.ReplBridge "$@"`
- `.installation_root` -> empty marker the console searches for

`check_provenance.py` additionally carries a `_resolve_joern_toolchain()` fallback: it
uses these `.sh` launchers when present, else reads the Maven classpath directly from
`$NAPI_JOERN_CP` / `$NAPI_JOERN_CP_FILE` / `~/joern-mvn/cp.txt` / `/home/user/joern-mvn/
cp.txt` and invokes the Java entry points itself -- so its single-file c2cpg controls
run even without the shim directory.

## Verified real passes on this toolchain

- `check_provenance.py`: **51/51** (node-libcurl reaches ANALYZED and reproduces the
  real Easy::ReadFunction finding through the full download->c2cpg->export->normalize->
  jssrc2cpg->export->link pipeline).
- `check_napi_status*.py`: R01 32/32, R02 16/16, integration 28/28, leveldb 7/7.
- The full leveldb-zlib pipeline (FULL_PIPELINE_LEVELDB_RESULT.json) ran on real JS +
  native facts.
