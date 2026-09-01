# Root-cause audit: the remaining 6 `NO_COMPLEXITY_CANDIDATE` packages never sampled by `PREFILTER_DIVERGENCE_AUDIT.md`

`PREFILTER_DIVERGENCE_AUDIT.md` sampled the top 8 of the 14 `NO_COMPLEXITY_CANDIDATE` packages by
prefilter `supported_sink_count`, leaving 6 unsampled: `argon2@0.45.1`, `ssh2@1.17.0`,
`x11-dri@0.6.0`, `multi-spec-parser@0.4.2`, `mariasql@0.2.6`, `tree-sitter-4dm@2.11.0`. This
document closes that gap. Method, matching the prior audit: each package's real tarball
(`tarball_url` from `pilot25_selection.json`) was fetched fresh, a real Joern CPG was rebuilt with
`jssrc2cpg.sh` (`$JOERN_HOME` = `/home/user/bug_tracker/tchecker-research-complete/joern-install/joern-cli`,
same as `run_pilot25.py`), and the frozen, byte-for-byte-unchanged `export_redos_npm_integ.sc` was
run against that CPG. All 6 real reruns reproduced `pilot25_results.json`'s recorded
`sink_targets`/`dangerous_sinks` counts exactly, confirming the original pilot run and this
rerun are the same real pipeline. For per-sink diagnostic detail the frozen producer itself prints
no per-sink text (only aggregate counts), so a **separate, unmodified-in-place** debug copy
(`/tmp/.../scratchpad/debug_producer.sc` -- not committed, not touching the frozen file) was made
that adds one `System.err.println` per `SinkTarget` (resolution kind, resolved pattern text,
classification, note) directly after the frozen `sinkTargets` computation, with the classification
logic itself never touched. Two further tiny read-only Joern queries (`query1.sc`/`query2.sc`,
same non-modifying pattern) were used to inspect enclosing-`Method` scope boundaries for two
packages. `classify_dangerous()` was imported directly from `prefilter_select_25.py` (current, R02
repo state) for every candidate pattern, and cross-checked against the exact same logic evaluated
by hand against the frozen Scala `classifyPattern()` source in `export_redos_npm_integ.sc`.

## Summary table

| Package | Real `sink_targets` / `dangerous_sinks` | Prefilter hit (pre-registration-time, unfixed prefilter) | Root cause | Bucket |
|---|---|---|---|---|
| `argon2@0.45.1` | 0 / 0 | 2 dangerous ("regex literals") | Both "literals" are JSDoc comments (`/** @enum {...\|...} */`); no real regex, no real sink call exists anywhere in the package's one real JS file | **GENUINELY_SAFE** |
| `ssh2@1.17.0` | 29 / 0 | 1 dangerous (`RE_HEADER`) | Regex is real, genuinely nested-quantifier-shaped, and IS reached by a real `.exec()` call -- but Stage 1's `resolvePattern` only searches the calling `Method`'s own AST for the assignment, and the `const RE_HEADER = /.../gm` lives in the *enclosing module scope*, a different CPG `Method`, so Stage 1 correctly abstains (`UNRESOLVED_IDENTIFIER`) instead of guessing | **UNSUPPORTED_REGEX_CONSTRUCTION** |
| `x11-dri@0.6.0` | 3 / 0 | 1 dangerous (JSDoc-comment misparse) | Flagged text is a JSDoc comment (`/** Bracket CPU writes with \`START \| WRITE\`... */`) inside `index.d.ts`, a non-executable `.d.ts` type file also excluded by jssrc2cpg's own default ignore rule; the package's 3 *real* sink calls all resolve to genuinely non-dangerous patterns | **GENUINELY_SAFE** |
| `multi-spec-parser@0.4.2` | 3 / 0 | 1 dangerous (`isHtml`'s alternation regex) | The flagged regex is real, reachable, and genuinely dangerous-shaped, in `dist/src/spec-validation.js:57` -- but `dist/` is the package's *entire, sole, `package.json`-designated* runtime source (`"main": "./dist/src/index.js"`), and jssrc2cpg's default folder-ignore list drops the whole `dist/` tree, so **every real `.js` file in this package is invisible to the CPG** except two unrelated native-addon build scripts | **JOERN_PARSING_GAP** |
| `mariasql@0.2.6` | 2 / 0 | 1 dangerous (`RE_PARAM`) | Identical mechanism to `ssh2`: `var RE_PARAM = /.../g` is declared at module scope, used inside a different, nested function-expression `Method` (`Client.prototype.prepare`); Stage 1's same-method-only assignment search cannot cross that boundary | **UNSUPPORTED_REGEX_CONSTRUCTION** |
| `tree-sitter-4dm@2.11.0` | 0 / 0 | 1 dangerous (`grammar.js` comment regex) | The flagged regex is real JS syntax and does structurally match the nested-quantifier rule, but it is `tree-sitter` grammar-DSL data (an argument inside `seq(...)`, consumed by tree-sitter's own external code generator) -- it is never passed to any real `.test`/`.exec`/`.match`/`.search`/`.replace`/`.replaceAll` call anywhere in the package | **GENUINELY_SAFE** |

**No `CLASSIFIER_DISAGREEMENT` found in any of the 6.** Every resolved pattern that Stage 1 handed
to Stage 2 was checked by hand against the frozen `classifyPattern()` source and the classification
returned (`SAFE`/`UNKNOWN`) is correct under the rule's own stated shape. **One `JOERN_PARSING_GAP`
found** (`multi-spec-parser`) -- a real, currently-shipping-style npm package (TS source compiled to
`dist/`, nothing else shipped) whose entire real code is dropped by jssrc2cpg's own default `dist`
folder exclusion. The two `UNSUPPORTED_REGEX_CONSTRUCTION` cases (`ssh2`, `mariasql`) are not
"dynamic regex construction" in the `new RegExp(expr)` sense -- both are static literals -- but a
distinct, real Stage-1 abstention mechanism (cross-`Method`-scope identifier resolution) that the
task's taxonomy places in this bucket; see each package's detail section for the precise
distinction, which is called out explicitly below rather than silently folded in.

---

## 1. `argon2@0.45.1` -- GENUINELY_SAFE

Real Joern rerun: `sink_targets: 0, dangerous_sinks: 0` (matches `pilot25_results.json` exactly).

The rebuilt CPG contains exactly one real JS file:
```
FILES IN CPG:
  package/argon2.cjs
```
(everything else in the tarball is C/C++ Argon2 source, prebuilt `.node` binaries, and
`argon2.d.cts`/`argon2.d.cts.map` -- correctly excluded as `.d.*ts`-suffixed type-declaration
files, not executable code.)

`grep` for every sink method name in `argon2.cjs` (`.test(`, `.exec(`, `.match(`, `.matchAll(`,
`.search(`, `.replace(`, `.replaceAll(`) returns **zero matches** -- there is no regex sink call
anywhere in the package's real source at all, which is why the real Joern run reports
`sink_targets: 0`.

**Why the pre-registration-time prefilter scored this package `supported_sink_count: 2`
(`regex_literals_seen: 3`):** the prefilter version used at selection time (before the `_strip_comments`
fix documented in `PREFILTER_FIX.md`) scanned raw, un-stripped text. `argon2.cjs` contains three
JSDoc block comments:
```
/** @type {(size: number) => Promise<Buffer>} */
/** @enum {argon2i | argon2d | argon2id} */
/** @enum {'argon2d' | 'argon2i' | 'argon2id'} */
```
The prefilter's `REGEX_LITERAL` regex, run on raw (unstripped) text, matches starting from the
second `*` of each `/**` opener (the `/` in `/**` satisfies its leading-context alternation) and
reads the comment body as a regex literal. Reproduced directly:
```
$ python3 -c "... REGEX_LITERAL.finditer(raw_text) ... classify_dangerous(body) ..."
'** @type {(size: number) => Promise<Buffer>} *'                    -> not dangerous
"** @enum {argon2i | argon2d | argon2id} *"                          -> DANGEROUS
"** @enum {'argon2d' | 'argon2i' | 'argon2id'} *"                    -> DANGEROUS
total 3, dangerous 2
```
This exactly reproduces `pilot25_selection.json`'s recorded `regex_literals_seen: 3,
supported_sink_count: 2` for this package. Running the **current** (R02, comment-aware) prefilter
against the same file confirms the fix: `has_export=True, n_regex=0, n_dangerous=0` -- the current
prefilter would not have selected `argon2` for this reason at all.

This is the same class of bug the earlier audit documented for `@appthreat/sqlite3`/`realm`/
`jsmeow` (JSDoc `{A | B}` union-type comments misread as regex alternation) -- not a new
divergence, and it is a **prefilter-only** artifact (already disclosed and already fixed in the
current `prefilter_select_25.py`), never a real analyzer issue: `dangerous_sinks: 0` is the
objectively correct real answer since there is no regex sink call to find.

---

## 2. `ssh2@1.17.0` -- UNSUPPORTED_REGEX_CONSTRUCTION

Real Joern rerun: `sink_targets: 29, dangerous_sinks: 0` (matches `pilot25_results.json` exactly).

**The prefilter-flagged pattern is real and genuinely reaches a real sink call.** Full-source scan
(current, fixed prefilter, `dist`/`.d.ts`/etc. exclusions applied) finds exactly one dangerous-shaped
literal in the whole package:
```
mscdex-ssh2-5c506eb/lib/protocol/keyParser.js:1231 (raw source, unstripped-comment line numbering)
  const RE_HEADER = /^([\x21-\x39\x3B-\x7E]{1,64}): ((?:[^\\]*\\\r?\n)*[^\r\n]+)\r?\n/gm;
```
and it IS consumed by a real sink call four lines later, inside `RFC4716_Public.parse`:
```js
RFC4716_Public.parse = (str) => {
  ...
  while (m = RE_HEADER.exec(body)) {   // line 1242
```
`classify_dangerous()` on the body confirms the nested-quantifier shape by the rule's own logic:
```
body = ^([\x21-\x39\x3B-\x7E]{1,64}): ((?:[^\\]*\\\r?\n)*[^\r\n]+)\r?\n
NESTED_QUANTIFIER match: '(?:[^\\]*\\\r?\n)*'   -- inner class [^\\]* contains '*', whole group
                                                    followed by outer '*': (...*...)*
is_safe_delimited_nested_quantifier: False
classify_dangerous: True
```

**Why the real Joern run still shows `classification: UNKNOWN` for this exact sink, never
reaching Stage 2's `classifyPattern()` at all.** Instrumented rerun (debug producer, per-sink
print) shows:
```
[DEBUG_SINK] L1242 call=exec code=RE_HEADER.exec(body) resKind=UNRESOLVED_IDENTIFIER
             resText=RE_HEADER classification=UNKNOWN note=pattern not statically resolved
```
A direct CPG scope query confirms the exact mechanism:
```
identifier RE_HEADER at L1242 in method=...keyParser.js::program:<lambda>7    methodLine=1233
assignment: const RE_HEADER = /.../gm  at L1231 in method=...keyParser.js::program  methodLine=1
```
The `const RE_HEADER = ...` assignment lives in `keyParser.js::program` -- the file's top-level
module scope (a bare `{ ... }` block, not a function) -- while the `.exec()` call that uses it
lives inside `RFC4716_Public.parse = (str) => {...}`, compiled to a **separate** CPG `Method`
(`...::program:<lambda>7`). The frozen Stage 1 `resolvePattern`'s identifier-resolution logic is:
```scala
case id: nodes.Identifier =>
  val assigns = method.ast.isCall.name("<operator>.assignment").l.filter { a => ... }
```
where `method` is `c.method` -- the CALL's own enclosing `Method`. `method.ast` only covers that
one `Method`'s own AST subtree; it never crosses into an enclosing closure/module scope. Since the
real assignment sits in a *different* `Method` than the call that reads it, the frozen search finds
zero candidate assignments and correctly falls through to `UNRESOLVED_IDENTIFIER`. `classifyPattern`
is then never invoked on the real pattern text at all (`isResolved=false` short-circuits it to
`("UNKNOWN", "pattern not statically resolved")`).

**Bucket note:** this is *not* a `new RegExp(dynamicExpr)`-style dynamic construction -- `RE_HEADER`
is a plain, static regex literal, and its value is knowable at compile time. It is placed in
`UNSUPPORTED_REGEX_CONSTRUCTION` per the task's own bucket text ("...or some other construction the
frozen Stage 1 cannot statically resolve to a literal pattern") because the observable behavior is
identical: Stage 1 correctly abstains rather than guessing, and Stage 2 never sees the pattern.
It is explicitly **not** `CLASSIFIER_DISAGREEMENT` -- `classifyPattern()` was never called with the
real pattern text, so there is no classification decision to disagree with. The real, precise
mechanism (cross-`Method` closure-scope identifier resolution) is distinct enough from "dynamic
construction" that it is called out here in case a finer-grained bucket is ever introduced.

---

## 3. `x11-dri@0.6.0` -- GENUINELY_SAFE

Real Joern rerun: `sink_targets: 3, dangerous_sinks: 0` (matches `pilot25_results.json` exactly).

The rebuilt CPG contains exactly:
```
FILES IN CPG:
  package/index.js
  package/scripts/install.js
```
`package/index.d.ts` is absent -- correctly excluded by jssrc2cpg's own default
`(...|\.d)\.(js|...|ts|tsx)$` filename-suffix ignore rule (`_jssrc2cpg_would_ignore_path('package/index.d.ts') == True`,
confirmed directly).

**The prefilter's one flagged "dangerous" hit is a JSDoc comment, not a regex, inside that excluded
`.d.ts` file:**
```
package/index.d.ts:142 (raw text)
    /** Bracket CPU writes with `START | WRITE` and `END | WRITE`. */
```
The prefilter's raw-text scanner reads the comment body `** Bracket CPU writes with \`START | WRITE\`
and \`END | WRITE\`. *` as a regex literal, and its `|` characters as top-level alternation with
`*` quantifiers on either side of the ``` ` ``` delimiters, hence `classify_dangerous() == True`.
This is doubly moot: (a) `.d.ts` files contain only TypeScript type declarations, never executable
code -- stripped entirely at compile time, never really "package-API-reachable" code in the first
place; and (b) it is a comment, not a real regex, so it was never a real hazard in the source
language sense either.

**The package's 3 *real* sink calls (all in `package/index.js`) all resolve to genuinely
non-dangerous patterns**, confirmed by instrumented rerun:
```
[DEBUG_SINK] L322 call=replace code=info.name.replace(/\[0\]$/, '') resKind=DIRECT_LITERAL
             resText=/\[0\]$/ classification=UNKNOWN note=not a recognized SAFE or DANGEROUS shape
[DEBUG_SINK] L424 call=exec   code=/OpenGL ES(?:-\w+)?\s+(\d+)\.(\d+)/.exec(string || '')
             resKind=VARIABLE_TO_LITERAL resText=/OpenGL ES(?:-\w+)?\s+(\d+)\.(\d+)/
             classification=UNKNOWN note=not a recognized SAFE or DANGEROUS shape
[DEBUG_SINK] L525 call=exec   code=/(\d+)\.(\d+)/.exec(string || '')
             resKind=VARIABLE_TO_LITERAL resText=/(\d+)\.(\d+)/
             classification=UNKNOWN note=not a recognized SAFE or DANGEROUS shape
```
Manual check against the frozen rule for all three: none contains a parenthesized group with an
internal `+`/`*` immediately followed by an outer `+`/`*` (`(?:-\w+)?` is followed by `?`, not
`+`/`*`, so `NESTED_QUANTIFIER` does not match it), and none contains top-level `|` alternation.
`UNKNOWN` is the correct classification for all three under the rule's own text -- **no
`CLASSIFIER_DISAGREEMENT`.**

---

## 4. `multi-spec-parser@0.4.2` -- JOERN_PARSING_GAP

Real Joern rerun: `sink_targets: 3, dangerous_sinks: 0` (matches `pilot25_results.json` exactly).

**This is the one package in the group of 6 where a genuinely dangerous, genuinely reachable regex
literal exists in the real, non-vendored source and is simply never seen by the CPG at all.**

Full-source scan (fixed prefilter, current exclusion rules) finds exactly one dangerous-shaped
literal:
```
package/dist/src/spec-validation.js:57
  return Boolean(contentType && /text\/html/i.test(contentType)) ||
         /<!doctype\s+html|<html[\s>]/i.test(head);
```
in `function isHtml(contentType, head)`, called from `validateSpecText()`, called from
`assertValidSpecText()`, imported into and used by `dist/src/parse-spec.js`
(`import { assertValidSpecText, validateSpecUrl } from "./spec-validation.js"`), which is the
module the exported `MultiSpecParser` class's `parse()`/`load()` methods use to validate fetched
spec documents.

Body `<!doctype\s+html|<html[\s>]` splits into two top-level alternation branches:
```
branches: ['<!doctype\\s+html', '<html[\\s>]']
'<!doctype\\s+html'  -> has_quantifier_followed_by_more_content = True   (the '+' in \s+ is
                          immediately followed by 'html', not end-of-branch or '$')
'<html[\\s>]'         -> False
classify_dangerous: True   ("quantifier followed by more content in alternation branch")
```
This is a real, structural match of the frozen rule's own stated DANGEROUS shape (the same rule
text as `export_redos_npm_integ.sc`'s `hasQuantifierFollowedByMoreContent`) -- if this sink call had
reached Stage 1/Stage 2, it would legitimately classify `DANGEROUS`.

**But it never reaches Stage 1 at all, because `jssrc2cpg` drops the entire `dist/` directory by
default**, and `dist/` is this package's **only shipped runtime source**:
```
$ grep '"main"\|"exports"\|"types"' package/package.json
  "main": "./dist/src/index.js",
  "types": "./dist/src/index.d.ts",
  "exports": { "." : { "types": "./dist/src/index.d.ts", "import": "./dist/src/index.js" }, ... }

$ find src -name '*.js' -o -name '*.ts' -o -name '*.mjs' -o -name '*.cjs' | grep -v node_modules
  package/dist/src/*.js  (26 files: index.js, factory.js, spec-validation.js, ...)
  package/examples/*.mjs (7 example scripts, not part of the published module surface)
  package/native/{build,install}.mjs
```
There is no un-compiled `src/` outside `dist/` in the published tarball at all -- `dist/src/*.js`
*is* the package. Confirmed by directly listing every file jssrc2cpg actually put in the CPG:
```
FILES IN CPG:
  package/native/build.mjs
  package/native/install.mjs
```
Every one of the 26 real `dist/src/*.js` files -- including the package's own `main` entry point,
`index.js` -- is completely absent. `_jssrc2cpg_would_ignore_path('package/dist/src/spec-validation.js')
== True` (matches the `dist` folder-name entry in jssrc2cpg's own default ignore-folder list,
independently confirmed against the same decompiled constant used throughout
`PREFILTER_DIVERGENCE_AUDIT.md`). The 3 sink calls the real CPG does contain are confirmed (via
instrumented rerun) to come from the two `native/*.mjs` build scripts, not from any file under
`dist/`.

**This is exactly the `JOERN_PARSING_GAP` case the task description called out by name**: the file
is legitimately covered by jssrc2cpg's documented default-ignore rule, but it *is* real,
package-API-reachable code -- there is no other, non-`dist` copy of this source anywhere in the
published package. `dist` as a folder name is a reasonable default heuristic for "generated build
output, skip it" for packages that ship both original source and a build artifact, but for a
TypeScript package that (like an increasing share of the modern npm ecosystem) ships *only* its
compiled `dist/` output with no parallel `src/`, that heuristic silently blinds the whole analyzer
to 100% of the package's real code. `dangerous_sinks: 0` for this package is a real scanner miss,
not a correct null result.

---

## 5. `mariasql@0.2.6` -- UNSUPPORTED_REGEX_CONSTRUCTION

Real Joern rerun: `sink_targets: 2, dangerous_sinks: 0` (matches `pilot25_results.json` exactly).

Same mechanism as `ssh2` (case 2 above), confirmed independently. Full-source scan finds exactly
one dangerous-shaped literal in the whole package:
```
mscdex-node-mariasql-a3baacb/lib/Client.js:18
  var RE_PARAM = /(?:\?)|(?::(\d+|(?:[a-zA-Z][a-zA-Z0-9_]*)))/g;
```
`classify_dangerous()`:
```
branches: ['(?:\\?)', '(?::(\\d+|(?:[a-zA-Z][a-zA-Z0-9_]*)))']
'(?::(\d+|(?:[a-zA-Z][a-zA-Z0-9_]*)))' -> has_quantifier_followed_by_more_content = True
    (the '+' in \d+ is followed by '|'; the '*' in [a-zA-Z0-9_]* is followed by ')))';
    branch does not end in a bare '+'/'*')
classify_dangerous: True
```
`RE_PARAM` is used at two real sink calls, both inside `Client.prototype.prepare`:
```js
Client.prototype.prepare = function(query) {
  ...
  var ppos = RE_PARAM.exec(query);        // line 302
  ...
  } while (ppos = RE_PARAM.exec(query));  // line 352
```
Instrumented rerun confirms both sinks abstain identically to `ssh2`'s case:
```
[DEBUG_SINK] L302 call=exec code=RE_PARAM.exec(query) resKind=UNRESOLVED_IDENTIFIER
             resText=RE_PARAM classification=UNKNOWN note=pattern not statically resolved
[DEBUG_SINK] L352 call=exec code=RE_PARAM.exec(query) resKind=UNRESOLVED_IDENTIFIER
             resText=RE_PARAM classification=UNKNOWN note=pattern not statically resolved
```
Direct scope query confirms the identical root mechanism:
```
identifier RE_PARAM at L302/L352 in method=...Client.js::program:<lambda>16   methodLine=296
assignment: var RE_PARAM = /.../g  at L18 in method=...Client.js::program     methodLine=1
```
`var RE_PARAM = ...` is declared at file/module top level (`::program`, `methodLine=1`);
`RE_PARAM.exec(query)` is used inside the separate `Method` compiled for the
`Client.prototype.prepare = function(query) {...}` function expression
(`::program:<lambda>16`, `methodLine=296`). Same cross-`Method` scope boundary that
`resolvePattern`'s same-method-only assignment search cannot cross; same correct
`UNRESOLVED_IDENTIFIER` abstention; Stage 2 never invoked on the real pattern text. Bucket
assignment and caveats are identical to `ssh2`'s (case 2): this is `UNSUPPORTED_REGEX_CONSTRUCTION`
in the sense the task's taxonomy defines it (Stage 1 cannot statically resolve this construction to
a literal pattern), not a truly dynamic `new RegExp(...)` construction, and explicitly not
`CLASSIFIER_DISAGREEMENT`.

---

## 6. `tree-sitter-4dm@2.11.0` -- GENUINELY_SAFE

Real Joern rerun: `sink_targets: 0, dangerous_sinks: 0` (matches `pilot25_results.json` exactly).

The rebuilt CPG correctly contains both real JS files (`grammar.js` is *not* excluded by any
jssrc2cpg default rule):
```
FILES IN CPG:
  package/grammar.js
  package/index.js
```
Full-source scan finds exactly one dangerous-shaped literal, and it is real, well-formed JS regex
syntax (not a comment misparse):
```
package/grammar.js:61
  /[^*]*\*+([^/*][^*]*\*+)*/
```
in context:
```js
comment: $ => choice(
    prec(PREC.comment, seq('//', /.*/)),
    prec(PREC.comment, seq(
      '/*',
      /[^*]*\*+([^/*][^*]*\*+)*/,
      '/'
    ))
),
```
`classify_dangerous()` on the body confirms a genuine nested-quantifier match by the rule's own
text (`([^/*][^*]*\*+)*` -- inner class `[^*]*` and `\*+` both contain quantifiers, whole group
followed by outer `*`): `NESTED_QUANTIFIER` matches, `is_safe_delimited_nested_quantifier == False`,
`classify_dangerous == True`. **This is a real, structurally dangerous regex under the rule.**

**Why `sink_targets: 0` is nonetheless the correct real answer: this regex is never passed to any
real JS RegExp sink method anywhere in the package.** `grammar.js` is a `tree-sitter`
grammar-definition file -- a declarative DSL consumed by the external `tree-sitter` CLI code
generator, which compiles rules like `seq('/*', /.../,'/ ')` into a generated C parser
(`src/parser.c`, not shipped as part of the scanned JS surface and not itself JS in the first
place). The regex literal here is a plain **argument value** describing a lexical rule to that
external generator -- it is never called with `.test()`, `.exec()`, `.match()`, `.matchAll()`,
`.search()`, `.replace()`, or `.replaceAll()` anywhere. Confirmed directly:
```
$ grep -rn '\.test(\|\.exec(\|\.match(\|\.matchAll(\|\.search(\|\.replace(\|\.replaceAll(' \
      --include='*.js' --include='*.ts' --include='*.mjs' --include='*.cjs' . | grep -v node_modules
(no output -- zero matches anywhere in the package)
```
This fully and independently explains the real `sink_targets: 0` (there is no sink call to find,
not merely no dangerous one). The pattern is real and genuinely dangerous-shaped, but it is inert
grammar data, never JS-regex-engine-executed code -- `GENUINELY_SAFE` is the correct bucket per the
task's own definition ("no genuinely dangerous-shaped regex literal exists ... reachable from a
sink call at all"; here the literal exists and is dangerous-shaped, but there is no sink call for
it, or any other pattern in this package, to reach).

---

## Consequence

Across these 6 packages: 3 `GENUINELY_SAFE` (2 of which trace to the same already-disclosed,
already-fixed JSDoc-comment-misparse prefilter bug documented in `PREFILTER_DIVERGENCE_AUDIT.md`/
`PREFILTER_FIX.md`; the third is real dangerous-shaped grammar-DSL data that is provably never
regex-engine-executed), 2 `UNSUPPORTED_REGEX_CONSTRUCTION` (both the *same*, single, previously
undocumented Stage 1 mechanism: `resolvePattern`'s identifier-to-literal search is scoped to the
calling `Method`'s own AST and cannot cross into an enclosing module/closure scope where the
`const`/`var` regex assignment actually lives -- a real, disclosed-here-for-the-first-time
limitation, but one where Stage 1 correctly abstains rather than mis-answering), and 1
`JOERN_PARSING_GAP` (`multi-spec-parser`: a real, genuinely dangerous, genuinely
package-API-reachable regex sitting in the ONLY code the package ships, silently dropped in its
entirety by jssrc2cpg's `dist`-folder default exclusion).

**Zero `CLASSIFIER_DISAGREEMENT`** -- every pattern Stage 1 successfully resolved and handed to
Stage 2 across all 6 packages was checked by hand against the frozen `classifyPattern()` source and
classified correctly under the rule's own stated shape.

Of the two code-change-relevant findings:
- `multi-spec-parser`'s `JOERN_PARSING_GAP` is the more actionable one: jssrc2cpg's default `dist`
  folder exclusion, reasonable for packages that ship both source and build output, silently
  zeroes out 100% of the scanned surface for packages (increasingly common) that ship *only*
  compiled `dist/` output as their real source.
- The `ssh2`/`mariasql` `UNSUPPORTED_REGEX_CONSTRUCTION` cross-`Method`-scope resolution gap is a
  real Stage 1 limitation worth naming precisely (it is not the same thing as `new RegExp(dynamicExpr)`),
  though its current behavior -- abstaining to `UNKNOWN` rather than guessing -- is the safe
  failure mode, not a false negative promoted to a false "SAFE"/incorrect classification.
