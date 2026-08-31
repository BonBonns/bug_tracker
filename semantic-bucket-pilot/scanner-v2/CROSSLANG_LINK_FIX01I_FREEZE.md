# CROSSLANG-LINK-FIX01I freeze: cross-language JS-to-native linker

Frozen after real, iterative correction through FIX01 (root cause) -> FIX01B/C/D
(boundary/curation corrections) -> FIX01E (source-formatting-fragile regex replaced
with ID-based provenance) -> FIX01F (real reaching-definition, not name-only lookup)
-> FIX01G (real CFG dominance, replacing scope-uniqueness alone) -> FIX01H (cross-
function "dominance" was itself an overclaim; real closure-capture evidence required
instead) -> FIX01I (conditional-initializer and closure-escape soundness gaps closed).
Full, real, quantitative account of every step: `study/crosslang_link_fix/
CHARACTERIZATION.md`.

No further changes are made to these files on this branch without re-running
`gate_crosslang_link_fix.py`, re-verifying zero regressions on the real end-to-end
corpus packages, and recording a new hash below -- same discipline as
`RESOURCE_GUARD_R05.md` and `npm_corpus/PIPELINE_FREEZE.md`.

## 1. What this linker establishes

Resolves JS/TS `<receiver>.X(...)` calls to the C/C++ functions registered via the
N-API `exports.Set(Napi::String::New(env,"X"), Napi::Function::New(env,Fn))` idiom,
where the receiver is proven -- by real, structural, ID-based evidence, never a
name/text heuristic alone -- to originate from a curated native-addon loader
(`bindings`, `node-gyp-build`). Every accepted link carries an explicit evidence tier:

- `dominance_proven` -- assignment and use are real nodes in the SAME function's own
  CFG; real, direct node-removal dominance of the specific use node.
- `closure_capture_proven` -- assignment and use are in DIFFERENT functions. Real,
  separate evidence required (never CFG dominance across functions, which is not a
  well-formed claim): a genuine `const` declaration; Joern's own structural
  closure-binding proof (`Local.closureBindingId`); the assignment dominates its own
  defining function's real exit; every direct same-scope invocation AND every escape
  of the closure function as a value (passed, assigned, exported, returned) is also
  dominated by the assignment.
- `fallback_marker_regex` -- lower-confidence, gated behind the IDENTICAL
  dominance-or-closure-capture proof as the two tiers above; never tried independently.
- `build_path` -- a direct `.node`/build-path require, no loader-invocation ambiguity.
- `js_receiver_name` -- the original, unchanged `--js-receiver` name match.

Missing, ambiguous, or cross-function evidence always ABSTAINS with an explicit,
disclosed reason -- there is no code path anywhere in this design that falls back to a
weaker, scope-only, or lexical-ancestry-only result.

## 2. Real controls, five fixture suites, all through the real frontend (not hand-typed JSON)

`study/crosslang_link_fix/gate_crosslang_link_fix.py`: **PASS** (re-run immediately
before this freeze).

| Fixture | Real cases | What it proves |
|---|---|---|
| `controls/js` + `controls/cpp` (14-control suite) | 8 positive, 6 negative | Core loader-invocation recognition across every real quote/template/whitespace/alias form observed |
| `controls/js_reaching_def_probe` | 5 | Real reaching-definition: overwrite-before-use, branch multi-definition, parameter shadowing, safe assignment-after-use-but-only-exported, alias cycle |
| `controls/cfg_dominance_probe` | 4 | One-branch-only, loop-only, try/catch-only, and assignment-after-use-with-direct-invocation assignments |
| `controls/const_cross_function_probe` | 5 | Real cross-function `const` capture: safe module-level, safe same-scope-invoked-after, real early-return-before-const, real invoked-before-const, genuine same-function |
| `controls/const_cross_function_escape_probe` | 4 | Conditional (ternary) initializer; callback escape before init; callback escape after init (positive); export/assignment escape before init |

## 3. Real end-to-end validation on two independent real corpus packages

Re-verified through the fully-extended exporter (`cfg_edges`, `method_cfg_endpoints`,
`try_nested_calls`, `locals` with closure-binding ids) immediately before this freeze,
identical to every prior fix in this series:

- `memoryjs`: `registrations=12 linked=15 unlinked=25` -- all 15 real links are
  `build_path` (direct `.node` require), entirely outside this fix's own scope.
- `node-liblzma`: `registrations=6 linked=6 unlinked=0` -- all 6 real links are
  `closure_capture_proven` (genuine module-level `const` bindings captured by
  separately-defined exported functions), plus 30 real, disclosed abstentions
  (including one real `try`-nested loader-adjacent assignment, correctly rejected).

## 4. Claims boundary

A `linked_calls` entry is a real, structurally-proven binding EDGE from a JS call site
to a C++ function -- not yet a complete attacker-input-to-native-finding PATH. Joining
these edges to R05's own native findings (section 6 below) is what establishes that.
The curated loader set (`bindings`, `node-gyp-build`) means corpus coverage is an
intentional, disclosed LOWER BOUND -- an unknown or custom loader convention is still
missed, same discipline as R01-R05's own curated-contract scope. `closure_capture_proven`
is EXPLICITLY a weaker evidence kind than `dominance_proven` (real cross-function
execution order can never be directly observed, only inferred from the module-load-
then-export contract plus exhaustive escape-site dominance) -- the two tiers are never
merged or presented as equivalent in any output.

## 5. What this freeze does NOT establish

- No claim about packages or loader conventions outside the curated set.
- No claim about a captured `let`/`var` binding (only `const` is trusted for
  cross-function closure capture -- see CHARACTERIZATION.md section 6g/6h for why).
- No claim about multi-hop escape chains (e.g. `wrapper` passed to `invoke`, which
  itself passes it on to a THIRD function before ever calling it) -- `escape_sites()`
  is scoped to the assignment's own DEFINING function, matching this project's
  established bounded-trace discipline (`LOADER_ALIAS_DEPTH`); a real, disclosed bound,
  not a silent gap.
- No corpus-wide base rate yet. One real positive validation (`node-liblzma`, 6 links)
  and one real "linker matches, but only via build_path, not this fix's own mechanism"
  case (`memoryjs`) does not establish how often real cross-function closure capture
  occurs across the full corpus -- that is exactly what the pending 494-package rerun
  (section 6) is for.

## 6. What happens next (real plan, not started until R05 freezes)

Per direct instruction: this branch (`claude/crosslang-linker-fix`) stays UNMERGED
anywhere for now -- kept on its own branch while the separate R05 494-package corpus
rerun (main working tree, `claude/aggregate-kinds-producer-test-03zs7n`) continues
unattended. No merge target has been decided yet.

Once R05 finishes and is itself frozen:

1. Regenerate JS/TS facts for the SAME 494 pinned packages through the extended
   exporter/normalizer (`cfg_edges`, `method_cfg_endpoints`, `try_nested_calls`,
   `locals`) -- required because the currently-running R05 scan used the OLD,
   pre-FIX01G/H/I exporter, whose JS facts lack these fields entirely. This does NOT
   require re-running c2cpg or regenerating any C++ facts -- the C++ side is completely
   untouched by this whole branch.
2. Run this frozen FIX01I `link_napi_facts.py` over each package's already-saved C++
   facts (from the R05 run) and the newly-regenerated JS facts.
3. Report, corpus-wide: packages with real C++ registrations; packages with at least
   one eligible JS native receiver; linked vs. ambiguous/abstained calls, broken out by
   evidence tier; the real distribution of abstention reasons.
4. Join linked calls to R05's own frozen native findings (`r05_findings`) to establish,
   for the first time, complete JS-input -> native-callback -> vulnerable-site paths
   where both a real link and a real R05 finding coincide on the same package.

Scheduled for AFTER R05 finishes specifically so the two genuinely expensive jobs
(the C++-side R05 corpus scan and this JS-side corpus regeneration) never compete for
the same container's resources.

## 7. Frozen files

- `tchecker-research-complete/.../javascript-typescript/joern/export_neutral.sc`:
  `e7da5d870ff671cfa466ccf64c4c0079`
- `tchecker-research-complete/.../javascript-typescript/joern/normalize_joern_facts.py`:
  `5283717188a7bdf12c2aa8bbb7bc3bec`
- `tchecker-research-complete/.../frontends/polyglot/link_napi_facts.py`:
  `14b9e39d0d0c00feeba2dea799ba2887`
- `study/crosslang_link_fix/gate_crosslang_link_fix.py`: `08ef034a2ce8991304768c2c1b5c08ac`
- `gate_crosslang_link_fix.py`: PASS (5/5 real fixture suites + both real end-to-end
  corpus packages, re-run immediately before this freeze)
