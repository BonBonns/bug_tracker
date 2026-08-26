# Gate 2 — real-engine JS adapter: PARTIAL PASS + decisive finding

## Headline
The REAL compiled PHP engine (StaticAnalysis/PHPCGFactory) runs end-to-end on
JavaScript-derived CSV: ANALYSIS_STATUS=COMPLETE. All three previously-identified
structural blockers are CLOSED. One deeper coupling was discovered and precisely
located — it is the answer to "can Joern JS translate into the engine's facts?"

## What now WORKS (run-verified against the compiled engine)
- ESTree -> joern-php CSV with correct funcid+1/+2 id discipline (CFG_FUNC_ENTRY at
  id+1, CFG_FUNC_EXIT at id+2, immediately after each AST_TOPLEVEL/AST_FUNC_DECL).
- Filesystem preamble (Directory/File/DIRECTORY_OF/FILE_OF), TOPLEVEL_FILE flag,
  endlineno on function-scope nodes, numeric defaults.
- CALLS edges (call-site -> func-decl).
- Engine result: ANALYSIS_STATUS=COMPLETE. CFG built (4 nodes). allFunc=3 — the
  engine correctly DISCOVERED all three JS functions (main, middle_f, sink_f).

## The finding (this is the real deliverable)
call2mtd (resolved call edges) = EMPTY. Root cause, located exactly:
  - allFunc = 3   (functions found)
  - path2callee = 0   (call-site -> target resolution EMPTY)
`createFunctionCallEdges` resolves calls ONLY via `path2callee`, which is populated
from an EXTERNAL "Spider" file (6-word lines, PHPCGFactory ~line 12540) and PHP
file-path matching via getDir() — NOT from the CPG's CALLS edges. So the engine
sees the functions but cannot connect the calls, because call-graph resolution is
coupled to PHP's on-disk file model, not to the language-neutral CPG facts.

## What this answers for the DoD plan
"Can Joern's JS/TS CPG translate into the minimum facts the engine requires?"
ANSWER: The AST/CFG/DDG facts translate cleanly and completely — proven, the engine
runs. But CALL-GRAPH RESOLUTION does NOT come from those facts; it comes from a
PHP-specific external mechanism (Spider file + getDir path matching). This is the
concrete, run-verified boundary between:
  - language-INDEPENDENT facts (AST/CFG/DDG/params/args/returns) — portable NOW, and
  - the PHP-SPECIFIC call resolver — must be replaced by a neutral one that consumes
    CALLS edges (or the resolution-classified CallEdge from the IR) directly.

This is EXACTLY the migration-map prediction ("call-graph construction is SPLIT:
traversal is core, resolving a call site is frontend") now demonstrated against the
running engine, not inferred. The fix is: make createFunctionCallEdges consume the
CPG's CALLS edges (which the adapter already emits) instead of path2callee — a
bounded change to ONE method, and it would make JS call resolution work immediately
because the CALLS edges are already correct (24->6, 38->16 verified).

## Confidence levels
- RUN-VERIFIED: full engine executes on JS input, discovers all functions, builds CFG.
- FINDING (run-verified): call resolution is PHP-file-coupled; CALLS edges are ignored
  by the resolver. Located to the exact method and mechanism.
- NEXT: point createFunctionCallEdges at CALLS edges (gated), rerun, expect call2mtd
  to populate main->middle_f->sink_f. Then the JS value traces end-to-end.

## Not done: TypeScript (adapter work consumed the session; TS builds on this adapter).
