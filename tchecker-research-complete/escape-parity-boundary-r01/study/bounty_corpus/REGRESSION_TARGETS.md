# Regression and precision targets — not bounty targets

These four repositories are detector-quality material only. They carry **no
scope freeze**, they are **not** bounty targets, and nothing found in them is
submitted anywhere. They were chosen because they are dense in quoted-string
boundary handling, which makes them good at exposing detector defects.

`reportable=false`. No security impact or severity is assessed.

## Results (frozen analyser, one run each)

| repository | commit | files | coverage | records | candidates | abstentions |
|---|---|---|---|---|---|---|
| taozhi8833998/node-sql-parser | `c1be9649` 2026-07-19 | 52 | 0.98 | 10 | 0 | 1 |
| nene/sql-parser-cst | `3e049312` 2026-08-23 | 128 (TS) | 0.99 | 29 | 0 | 2 |
| mholt/PapaParse | `f88432d3` 2026-09-01 | 1 | 1.00 | 7 | 0 | 3 |
| nodemailer/mailparser | `c5390ac7` 2026-09-01 | 5 | 1.00 | 28 | 0 | 1 |

No false positives: every one of the 74 records is a `NEGATIVE` or an
abstention, and each abstention was read by hand.

## The abstentions are all correct

All seven are `UNRESOLVED_REGEX_CONSTRUCTION` — the pattern is assembled at
runtime, so no boundary rule can be read out of it:

- `papaparse.js:212` — `new RegExp(escapeRegExp(_quoteChar), 'g')`
- `papaparse.js:1103` — `new RegExp(escapeRegExp(quoteChar) + '([^]*?)' + escapeRegExp(quoteChar), 'gm')`
- `papaparse.js:1454` — `new RegExp(escapeRegExp(escapeChar) + escapeRegExp(quoteChar), 'g')`
- `mailparser lib/mail-parser.js:58` — a Twitter-handle pattern built from a variable
- `node-sql-parser src/parser.js:49` — `` new RegExp(`^${whiteAuthority}$`, 'i') ``
- `sql-parser-cst scripts/utils.ts:36,37`

The first three are genuinely undecidable statically: PapaParse's quote and
escape characters are user configuration. Abstaining is the right answer.

Worth noting as noise rather than error: the mailparser and node-sql-parser
abstentions are on regexes that are not quoted-string constructs at all. The
analyser abstains on unresolved *construction* before it can ask whether the
site is even relevant, so a runtime-built pattern that could never have been
a finding still costs an abstention record.

## A real gap this exercise found: JavaScript character scanners

**The JavaScript layer emitted zero `parser_quote_sites` rows across all four
targets** — including one that plainly contains the shape this property
exists to find.

`papaparse.js:1506`:

```js
if (quoteChar !== escapeChar && quoteSearch !== 0 && input[quoteSearch - 1] === escapeChar)
```

`input[quoteSearch - 1] === escapeChar` is a one-position lookbehind: the same
structural rule as the pre-fix Gecko `aMimeType[i - 1] != '\\'` that this
property flagged in `SplitMimetype`. The analyser never considered it.

The cause is in `producers/escape_parity_facts.sc`. A quote site is recorded
only when one operand of the comparison is a **string literal** quote:

```scala
val QUOTE_CHARS = Set("'", "\"", "`")
def isQuoteLiteral(n: nodes.AstNode) = stringValue(n).exists(QUOTE_CHARS.contains)
...
val quoteSide = as.find(isQuoteLiteral)
```

Gecko compares against `'"'` and `'\\'` as literals, so the C/C++ side fires.
PapaParse compares against `quoteChar` and `escapeChar`, which are variables
carrying configurable values, so nothing is emitted — not a candidate, not a
negative, not an abstention. The site is simply invisible.

This matters beyond PapaParse: parameterised quote and escape characters are
the ordinary idiom in JavaScript text parsers, so the JS layer's recall on
hand-written character scanners is currently unknown and probably poor. The
C/C++ layer has the same literal requirement and would have the same gap
against C code that parameterises its delimiters.

**A "0 candidates" result from the JavaScript layer is therefore not evidence
that a codebase has no such rule.** It is evidence about regex-literal
boundary rules only. The Mozilla C/C++ result is unaffected — Gecko's scanners
use character literals, the sites were seen, and 26 of them were classified.

This is what the regression targets are for. **It has since been fixed** —
see `../../DELIMITER_IDENTITY_R05.md`. R05 resolves a delimiter variable to its
literal value when every assignment reaching it is a literal, and abstains when
any is not. Under R05 `papaparse.js:1506` is recorded as
`UNRESOLVED_DELIMITER_IDENTITY` → `ABSTAINED`, along with three more sites in
the same parser loop, and no new candidate appears anywhere in the corpus.
Abstaining is the correct verdict: PapaParse's quote and escape characters are
user configuration, so the rule's parity cannot be decided statically. The
revision converts silence into a stated abstention rather than manufacturing a
finding.

Everything in the tables above was produced by the pre-R05 analyser and is kept
as the record of what the gap looked like. Post-R05 results are in
`results_r05/`.

## Manifest note

PapaParse and mailparser initially reported `INFRASTRUCTURE_FAILURE` at
parse coverage (0.40 and 0.47). The uncovered files were `.eslintrc.js`,
`.ncurc.js`, `.prettierrc.js`, `Gruntfile.js`, `papaparse.min.js` and
`examples/` — tooling, build scripts and a generated bundle, none of it
library source. The threshold was **not** lowered. `freeze_target.py` was
given a uniform rule excluding dotfile configs, named build scripts and
generated bundles, applied to every target including Mozilla, and the runs
were repeated. No findings had been produced or seen for either target before
the re-freeze.
