# R40 + Guard-Fallthrough detector

Verified against real Joern v4.0.608 and the real Corpus D
(gothinkster/koa-knex-realworld-example).

## R40 — nested & multi-hop export-member resolution
- export_r38_facts.sc      adds nested_member_exports.tsv (recursive object-literal leaves)
- app_mount_flow.py        R38+R39+R40 resolver (nested + alias + selector, N-part paths)
- gate_r40.py              JS_PROV_R40=9/9 on Corpus D
- gate_r38.py / gate_r39.py  regressions, still 10/10 and 7/7

## Guard-fallthrough detector (the Pods pods_error() bypass class, in JS/TS)
- export_guard_facts.sc          terminator_profile / guard_calls / sink_sites facts
- guard_fallthrough_verdict.py   CANDIDATE_GUARD_FALLTHROUGH verdict (never "VULNERABLE")
- gate_guard_fallthrough.py      GUARD_FALLTHROUGH=6/6
- guard-fixture/                 vulnerable shape + two discriminating negative controls

Run (with JOERN_HOME set):
  $JOERN/jssrc2cpg.sh <src> --output cpg.bin
  $JOERN/joern --script export_guard_facts.sc --param cpgFile=cpg.bin --param outDir=raw
  $JOERN/joern --script .../module_export_identity.sc --param cpgFile=cpg.bin --param outDir=raw
  python3 guard_fallthrough_verdict.py raw
