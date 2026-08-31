# /tmp/pp2 and /tmp/cmp2 fixture provenance (added 2026-08-24)

GUARD-R01 reads pre-built fact documents from /tmp/pp2 (param.cpp) and /tmp/cmp2
(shapes.cpp + src.cpp). No script in this repo generates those directories -- they
are operator-maintained (see tools/workspace/c.cpg*/project.json for the original
Joern sessions). Build each as: c2cpg -> export_c_cpp_facts_v03.sc -> 
normalize_c_cpp_facts_v03.py -> EndToEndRunner, mirroring cpp-param-r01/run.sh.

DEBUGGING RECORD: a stale /tmp/pp2/program.json.reachingdef.json (built by an older
normalizer invocation) contained 3 reaching-def facts a fresh normalizer run over the
SAME raw/ correctly refuses to emit -- including a false EXACT narrowing on
p2_branch_reassign's parameter-storage local, which failed tooth G5. The bundled
normalizer's anchor guard is sound (verified via REACH_R02_DEBUG: both defs CFG-anchored,
both reach, reach==candidates => no fact). Regenerating the fact documents from raw/
with the current normalizer yields GUARD_CONTROLS=6/6. If G5 ever fails, regenerate
/tmp/pp2 before suspecting the normalizer.

ALSO operator-maintained: /tmp/cap_corpus, /tmp/norm_scan, /tmp/sd_scan (used by the
oob/capacity/bound control checks) -- same staleness class as /tmp/pp2. If a capacity or
oob control fails inexplicably, regenerate those fact documents with the current
normalizer before suspecting the readers.

2026-08-24 LATER: /tmp/cap_corpus, /tmp/norm_scan and /tmp/sd_scan were lost to /tmp
cleanup during this session (GUARD-R01 had passed 6/6 with them present at 11:27).
No archive contains their sources or a builder — see docs/CODE_REVIEW_2026-08-24.md
finding #2. Until the operator commits the corpus sources + a builder, the oob/bound
live teeth cannot run and oob_read/oob_write_controls crash (finding #3) rather than
reporting BLOCKED.

2026-08-31 RESOLVED for /tmp/cap_corpus (task #42): committed real, real C++ source
for it at `fixtures/cap_corpus/{g,t3,t5}.cpp`, reproducing every function
oob_write_controls.py/oob_read_controls.py's own real assertions name (g_write_ok,
g_write_lt, nc_b1, nc_b3, nc_b4, nc_b5, nc_b6, g_read_ok, mix_fixed, teeth_case,
teeth_read) and a real builder, `fixtures/cap_corpus/build_cap_corpus.sh`, running the
same real c2cpg -> export_c_cpp_facts_v03.sc -> normalize_c_cpp_facts_v03.py pipeline
this note already documented. `tools/oob_write_controls.py` and
`tools/oob_read_controls.py` (and their mirrored copies here) now self-heal: if
`/tmp/cap_corpus/g.json` is absent, they invoke the builder automatically; only if
`joern`/`c2cpg.sh` itself is unavailable do they now exit 20 with an explicit BLOCKED
message, never a bare crash. Verified: both gates pass every one of their original
assertions against the freshly rebuilt corpus (`OOB_WRITE_CONTROLS=11/11`,
`OOB_READ_CONTROLS=10/10`), and the pre-existing `bound_controls.py` (which also reads
`/tmp/cap_corpus` but already degraded gracefully rather than crashing) independently
confirms the same corpus (`BOUND_CONTROLS=11/11`).

`/tmp/norm_scan` and `/tmp/sd_scan` remain unresolved — they are optional, anchor-only
inputs for oob_write_controls.py/oob_read_controls.py (each check is wrapped in
`if pathlib.Path(...).exists()`, so their absence degrades gracefully rather than
blocking or crashing) and are out of task #42's scope. `/tmp/pp2` and `/tmp/cmp2` (used
by GUARD-R01's other ten scripts: guard_controls.py, guard_r02.py, status_r02/r03,
status_norm_gate, keyselector_controls.py, js_source_r01_controls.py,
origin_kind_purity/corpus_purity, operand_role_controls.py, capacity_controls.py) are
ALSO still unresolved and still block `run_all.py` gate 114 (GUARD-R01) as a whole —
a separate, larger fixture-recovery task than #42, not attempted here.
