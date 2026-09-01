# Prefilter/classifier divergence audit: the 14 `NO_COMPLEXITY_CANDIDATE` packages

Per direct instruction, task 3: "Categorize why the 14 prefilter-selected packages produced no
real complexity candidate -- this measures divergence between the cheap Python proxy and the
Joern classifier." Sampled the top 8 of the 14 by prefilter `supported_sink_count` (covering
157 of the total flagged literals): `ember-one-way-controls` (89), `@appthreat/sqlite3` (29),
`realm` (16), `linux-device` (8), `numbl` (6), `sdenv` (4), `uplink-nodejs` (3), `jsmeow` (2).
Each package's real tarball was fetched fresh; the prefilter's own real `REGEX_LITERAL`/
`classify_dangerous()` logic was run against the real extracted source to get the exact file+line
+pattern hits; the real jssrc2cpg frontend's own default-ignore mechanisms were extracted by
decompiling `jssrc2cpg-4.0.608.jar` (`javap`) and independently confirmed empirically against
small synthetic probes before being trusted as the explanation.

## Root discovery: jssrc2cpg has its own default file/folder ignore list the prefilter never replicated

Confirmed, both by decompilation and by direct synthetic-probe testing (a file placed inside each
excluded shape was verified dropped from the real CPG; a sibling file outside it was verified
kept):

  AstGenDefaultIgnoreRegex = (conf|test|spec|[.-]min|\.d)\.(js|jsx|cjs|mjs|xsjs|xsjslib|ts|tsx)$
  default ignored folders = venv, docs, test, tests, e2e, e2e-beta, examples, cypress,
                             jest-cache, eslint-rules, codemods, flow-typed, i18n, vendor,
                             www, dist, build
  node_modules exclude    = UNANCHORED substring match on "node_modules" anywhere in the path
  LineLengthThreshold     = 10000 (content-based: any file with a line >= 10,000 chars is
                             skipped regardless of filename -- catches minified/bundled output
                             even when NOT named *.min.js)

The prefilter's own file filter (`prefilter_select_25.py`'s `iter_js_ts_members`) only checked
`"node_modules/" in name` (exact substring WITH a trailing slash), `/test/`, `/tests/`, and
`name.endswith(".min.js")` -- none of which reproduce `docs/`, `dist/`, `.d.ts`, the unanchored
`node_modules` match, or the content-based minified-line detector.

## Per-package finding (dominant reason, real evidence)

| Package | Hits | Reason | Real evidence |
|---|---|---|---|
| `ember-one-way-controls` | 89 | (d) unanchored `node_modules` match | All 89 under `.node_modules.ember-try/` (a devDependency snapshot npm did not strip) -- jssrc2cpg's unanchored regex matches the substring anywhere, including inside a DOT-prefixed folder name; the prefilter's own exact `"node_modules/"` check does not. |
| `@appthreat/sqlite3` | 29 | (c) JSDoc misparse | All 29 are `/** @type {A \| B} */`-style JSDoc comments in real, non-excluded files (`lib/pool.js`, etc.) -- the prefilter's regex-literal scanner doesn't track `{}` depth, so it reads the comment's own `|` as top-level alternation and its `**` as a quantifier. A real JS parser tokenizes `/** ... */` as a comment, never a `Literal` node. |
| `realm` | 16 | (d) `.d.ts` + `dist/` [+c] | All 16 in `dist/*.d.ts` files -- doubly excluded (filename `.d.ts` suffix AND parent folder `dist`). The prefilter's own `dist`-skip has a real operator-precedence bug: `"/dist/" in name or ... or "/dist/" in name and name.endswith(".min.js")` -- `and` binds tighter than `or`, so non-minified `dist/*.d.ts` files are never actually skipped. Content is the same JSDoc-comment misparse as (c) above. |
| `linux-device` | 8 | (d) `docs/` folder | All 8 in vendored Google Code Prettify under `docs/scripts/prettify/` -- `docs` is a literal jssrc2cpg default-ignored folder. |
| `numbl` | 6 | (d) `.d.ts` + line-length | 4 in `.d.ts` files (filename-suffix exclusion); 2 in a Vite-bundled worker file with lines of 205,792/194,593 characters -- far past the 10,000-char minified-file threshold. |
| `sdenv` | 4 | (d) line-length [+c] | An obfuscated/compiled bundle whose first line is 202,063 characters -- skipped as minified content regardless of filename. The "patterns" captured are garbled obfuscator-table fragments, not real regex syntax either (moot, since the file is dropped before that would matter). |
| `uplink-nodejs` | 3 | (d) `docs/` folder | Vendored jQuery 3.4.1 under `docs/api-doc/jquery.js` -- same `docs` default-exclusion as `linux-device`. |
| `jsmeow` | 2 | (d) `.d.ts` [+c] | `types/index.d.ts`, same JSDoc-comment misparse as (c), doubly moot since `.d.ts` is excluded anyway. |

**Dominant cause: reason (d), file/directory exclusion the prefilter never replicated -- 7 of 8
sampled packages, 128 of 157 hits (~82%).** Reason (c) (JSDoc-comment misparse) appears as either
the primary or a secondary contributing cause in 4 of 8. **This divergence is systematic and
mechanically explainable, not idiosyncratic noise.**

## Consequence for the prefilter's own precision (not the real analyzer)

This is a **prefilter-only** issue. The real, Joern-based classifier that governs actual findings
was correct throughout -- it never saw these files at all (jssrc2cpg's own frontend excluded
them), so `dangerous_sinks: 0` for these 14 packages is the CORRECT real answer, not a scanner
miss. What this audit found is that the cheap PROXY score (`supported_sink_count`) used to RANK
and SELECT packages for the pilot is inflated for any package carrying vendored dependencies,
`.d.ts` type-declaration files, `docs/`/`dist/` folders, or JSDoc union-type comments -- which
could, in principle, have caused the selection to miss a genuinely higher-scoring real candidate
elsewhere in the 494-package corpus whose own real (non-vendored, non-doc) source happened to
score lower under the inflated ranking. See `PREFILTER_FIX.md` for the fix and its own
before/after regression evidence.
