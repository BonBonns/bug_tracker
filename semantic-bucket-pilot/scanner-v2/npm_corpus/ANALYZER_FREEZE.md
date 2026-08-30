# Complete analyzer freeze, for the npm corpus phase

Recorded before any corpus construction or scanning begins, per item 1 of the corpus-phase
instruction. No semantic changes are permitted to any file listed here for the duration of
corpus construction and scanning; any change would require a fresh freeze record.

## scanner-v2 capability/gate/contract/normalizer files (all 63, this directory)

Full md5 list: `npm_corpus/scanner_v2_freeze_hashes.txt` (generated `md5sum *.py
study/resource_guard_r04/build_configs/*.json` from this directory). Load-bearing entries for
the npm corpus run (the scanning capabilities actually invoked):

- `resource_guard_verdict.py` (R01) — `ce641e1acf05ac90af9ea942c934f62e`
- `resource_contracts.py` (R01) — `2489cedf24cedc0aac8d3d48fd84a897`
- `resource_guard_verdict_r02.py` — `016b1b327d22418b326b3b1a3fafd91d`
- `resource_contracts_r02.py` — `91df28ae16f36bfa1656bfb6529a1eb5`
- `resource_guard_verdict_r03.py` — `81ce5856f142d77f9da33472faafc65a`
- `resource_contracts_r03.py` — `7a73af8853c28ec3edba4fd078d67305`
- `resource_guard_verdict_r04.py` — `b8c0e058b832b428d739b048d0f34c83`
- `resource_contracts_r04.py` — `68d2448e36556c4442bc10065b504ed3`
- `cap_addr_indexed.py` — `8f30a21b3dbaa05bfcbf5ec5ca24bec4`
- `oob_runtime_capacity_v2.py` — `13cf1466005b4e3c63434244778de60e`
- `single_object_pass.py` — `ef43d027d51c69364904fc9c7e7213dd`
- `lock_balance_verdict.py` — `67ec8bd0dbab7b59399f9ac02a3b5e48`
- `protected_field_verdict.py` — `df08d685896bc2eb6714258ea105dd6c`

Every capability's own gate is green as of this freeze (RESOURCE_GUARD_R01_GATE=19/19,
R02=20/20 + blindtest 6/6, R03=33/33 + blindtest 6/6, R04=12/12; other capabilities'
pre-existing gates unchanged, not re-verified here since this freeze does not touch them).

## Raw-fact exporters and normalizers (C/C++)

`/home/user/bug_tracker/tchecker-research-complete/portable-engine-full-review-package/tests/gates/cpp-r06/frontend/`
- `export_c_cpp_facts_v03.sc` — `3fbaa0b8264359771bbcd37f1e5b1efd`
- `normalize_c_cpp_facts_v03.py` — `61cdabe728b34e5dfc9c67da10dd192a`
- `emit_reaching_defs.py` — `d55720d115dd5890b893141d2f9a5964`

## JS/TS binding-side frontends

`/home/user/bug_tracker/tchecker-research-complete/portable-engine-full-review-package/frontends/javascript-typescript/`
- `joern/export_neutral.sc` — `939522b6fef187c87c9dba4dfce349f7`
- `joern/normalize_joern_facts.py` — `fce077d0ba91bf38595935d69e467366`
- `joern-ts/` (26 files, the TS-conformant Gate-24-TS/25+ frontend) — full md5 list:
  `npm_corpus/jsts_frontend_freeze_hashes.txt`

**Selection for the corpus run:** `joern/export_neutral.sc` +
`joern/normalize_joern_facts.py` (the Gate-24 "portable-program-facts/0.1" pair) is what
`link_napi_facts.py` (below) was measured against and is written to consume -- this is the
JS/TS half of the pipeline used for corpus scanning. The richer `joern-ts/` frontend exists
but was not the one `link_napi_facts.py`'s own docstring/gate cites; using it would be an
unverified substitution, so it is recorded here but not selected for this run.

## Cross-language binding resolver (JS <-> C/C++)

`/home/user/bug_tracker/tchecker-research-complete/portable-engine-full-review-package/frontends/polyglot/link_napi_facts.py`
— `f003a679e3565587099405da4dc14b02`

Own docstring: merges a JS/TS program-facts doc and a C/C++ program-facts doc into one
`portable-program-facts/0.3` document, resolving JS `<receiver>.X(...)` native-binding calls
to C++ functions registered via the N-API `exports.Set(Napi::String::New(env,"X"),
Napi::Function::New(env, Fn))` idiom -- a shape MEASURED on real c2cpg output of
node.bcrypt.js. Offsets JS vs. C++ Joern id spaces by a disjoint constant (`OFFSET = 1<<44`),
matches only mechanically-exact single-candidate registrations, writes a
`cross_language_bindings` block (`registrations`/`linked_calls`/`unlinked_calls`).
Java-side counterpart (`CrossLangLinkFact.java`) and its gate
(`tests/gates/core-crosslang/`, `CORE_CROSSLANG=5/5`) reconfirmed passing at freeze time.

## Toolchain versions (recorded at freeze time, this container)

- Joern: **4.0.608** (`joern --version` banner; `c2cpg.sh`/`jssrc2cpg.sh` are launchers over
  the same distribution).
- `jssrc2cpg.sh` present and functional (`joern-cli/jssrc2cpg.sh`, real frontend under
  `joern-cli/frontends/jssrc2cpg/`), confirmed via `--help`.
- node v22.22.2, npm 10.9.7, python3 3.11.15, tar (GNU tar 1.35), cmake 3.28.3, GNU Make 4.3,
  g++/gcc 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1), node-gyp 11.5.0 (bundled with npm, not a
  standalone global binary -- resolved via `npx node-gyp` / npm's own install scripts).

## Disk and network (recorded at freeze time)

- `/home/user` and `/tmp` share one 252G filesystem; 28G available at freeze time. This is a
  genuine, hard constraint on how much of the corpus (tarballs, extracted trees, node_modules,
  CPG binaries) can be held on disk at once -- addressed by processing in restartable batches
  and deleting each package's intermediate artifacts (tarball, extracted tree, CPG binaries)
  once its facts/verdict are captured, retaining only the compact TSV/JSON outputs.
- Network reachability to `registry.npmjs.org` confirmed (valid JSON response from the
  registry search API).

## What this freeze does NOT cover (real, disclosed scope limits)

- No existing infrastructure builds an npm-registry-wide package manifest, downloads
  tarballs, performs eligibility filtering, extracts automatic build-configuration evidence,
  or orchestrates checkpointed batch runs across a corpus -- these are new, this-phase-only
  scripts under `npm_corpus/`, built and verified incrementally, never touching any frozen
  capability file above.
- `link_napi_facts.py` matches ONE specific binding idiom (`exports.Set(Napi::String::New(...),
  Napi::Function::New(...))`) and states its own scope plainly (mechanically-exact,
  single-candidate registrations only) -- packages using other binding-registration idioms
  (e.g. `NODE_API_MODULE`, class-wrapped exports via `Napi::ObjectWrap`, `Nan::SetMethod`,
  bulk `napi_define_properties` tables) will not link via this resolver and are expected to
  surface as `BINDING_UNRESOLVED` or `UNSUPPORTED_BINDING_API`, not silently miscounted as
  `NO_RELEVANT_CROSS_LANGUAGE_EDGE`.
