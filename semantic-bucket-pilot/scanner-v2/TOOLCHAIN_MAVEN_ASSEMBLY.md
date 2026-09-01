# Pinned Joern v4.0.608 toolchain assembly (machine-local; nothing here is committed)

`tchecker-research-complete/bootstrap.sh` downloads the Joern v4.0.608 CLI from a
GitHub release zip. That release asset (and the astgen release binary jssrc2cpg needs)
is **unreachable through this environment's outbound proxy** (HTTP 404/403 on
`github.com/.../releases/download/...`). Git reads ARE served, so the identical pinned
versions are assembled from source / Maven Central. Everything below is **machine-local
environment setup** -- the launchers, wrappers, and absolute install locations are NOT
committed to the repository (only this recipe, the integrity pins in `ASTGEN_PIN.json`,
and the env-var-driven fallbacks in the gates are). None of it is a version change:
every artifact is Joern 4.0.608 / astgen 3.47.0, the pinned versions.

Notation: `$MVN` = a machine-local Maven working dir; `$JS_ASTGEN` = a clone of
`javascript-astgen`; `$NODE22` = the node 22 bin dir; `$JOERN_HOME` = the dir the
frozen pipeline files expect (`tchecker-research-complete/joern-install/joern-cli`,
gitignored).

## 1. C/C++ + console + JS frontend classes (Maven Central)

```
# $MVN/pom.xml deps (all version 4.0.608): io.joern:joern-cli_3, c2cpg_3, jssrc2cpg_3
mvn -B dependency:build-classpath -Dmdep.outputFile=$MVN/cp.txt
```

Entry points on that classpath: `io.joern.c2cpg.Main`, `io.joern.jssrc2cpg.Main`,
`io.joern.joerncli.console.ReplBridge` (serves `--script`; run from a dir containing an
empty `.installation_root` marker).

## 2. astgen 3.47.0 -- built from source (NOT on npm; see ASTGEN_PIN.json)

`@joernio/astgen@3.47.0` does not exist on npm (that package ends at 2.0.4); astgen 3.x
ships only as GitHub source + release binaries. Integrity is anchored by git commit,
not an npm hash -- the exact commit, version, yarn.lock hash, and built-artifact hash
are recorded in `study/napi_status/ASTGEN_PIN.json`.

```
git clone --depth 1 https://github.com/joernio/astgen-monorepo <clone>   # javascript-astgen == 3.47.0
cd <clone>/javascript-astgen
PATH=$NODE22:$PATH yarn install --ignore-engines    # engines want node>=24; tsc builds under node22
PATH=$NODE22:$PATH npx tsc --build                  # -> dist/astgen.js
```

`ASTGEN_BIN` (jssrc2cpg's documented override env var) points at a machine-local
executable wrapper that runs `$NODE22/node <clone>/javascript-astgen/dist/astgen.js "$@"`.

## 3. Machine-local shim launchers at `$JOERN_HOME` (gitignored, not committed)

Thin launchers so the frozen `check_provenance.py` / `run_pipeline_one.py` work
unchanged through their hardcoded `JOERN_HOME`:

- `c2cpg.sh`     -> `java -cp $MVN/cp.txt io.joern.c2cpg.Main "$@"`
- `jssrc2cpg.sh` -> `export ASTGEN_BIN=<wrapper>; java -cp $MVN/cp.txt io.joern.jssrc2cpg.Main "$@"`
- `joern`        -> `cd $JOERN_HOME; java -cp $MVN/cp.txt io.joern.joerncli.console.ReplBridge "$@"`
- `.installation_root` -> empty marker the console searches for

Committed-code fallback (no machine paths in the repo): `check_provenance.py`'s
`_resolve_joern_toolchain()` uses the `$JOERN_HOME` shims when present, else reads the
Maven classpath from `$NAPI_JOERN_CP` or `$NAPI_JOERN_CP_FILE` or `~/joern-mvn/cp.txt`
and invokes the Java entry points itself. `check_js_frontend.py` resolves the JS
toolchain the same way ($JOERN_HOME shim, or `$NAPI_JOERN_CP` + `$ASTGEN_BIN`) and
SKIPS cleanly if none is present.

## Verified real passes on this toolchain

- `check_js_frontend.py`: **4/4** on the minimal JS fixture (astgen parses; normalized
  facts contain the fixture's function; non-empty calls) -- run FIRST.
- `check_provenance.py`: **51/51** (node-libcurl reaches ANALYZED and reproduces the
  real Easy::ReadFunction finding through the full download->c2cpg->export->normalize->
  jssrc2cpg->export->link pipeline).
- `check_napi_status*.py`: R01 32/32, R02 16/16, integration 28/28, leveldb 7/7.
- The full leveldb-zlib pipeline ran on real JS + native facts
  (FULL_PIPELINE_LEVELDB_RESULT.json).
