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
