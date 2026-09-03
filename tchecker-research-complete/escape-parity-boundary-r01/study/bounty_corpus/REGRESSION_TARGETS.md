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

## C/C++ precision target: alliedmodders/source2mod (R08, corrected at R09)

Added at R08 to validate that the analyser finds the structural pattern in a
live, actively maintained C/C++ codebase beyond the Mozilla corpus.
`reportable=false`. No security impact or severity is assessed.

**Target key**: `regr-sourcemod-textparsers`  
**Commit**: `9976b514686d28386cf73b0bb3dc0102827285db` (2023-12-20)  
**Files analysed**: 114 `C_CPP_SOURCE` + 144 `C_CPP_HEADER` = 258 files  
**Parse coverage**: 1.00 (258/258)  
**Records**: 17 (**1** `ESCAPE_PARITY_PARSER_CANDIDATE`, 16 `NEGATIVE`)  
**Results**: `results_r09/sourcemod-textparsers/` (corrected). The original R08
run, `results_r08/sourcemod-textparsers/`, is kept unmodified as the record of
what R08 actually produced — see below for why it differed.

### R08 originally over-reported: 2 candidates, not 1

The first run of this target (R08) reported 2 candidates, both attributed to
`core/logic/TextParsers.cpp:ParseStream_SMC`, at lines 457 and 638. Re-reading
the actual source at both lines — rather than trusting the tool's field
dump — showed only line 457 is a real boundary rule:

```cpp
// line 457, inside `if (in_quote) { ... }`: a genuine one-position rule
if ((&parse_point[i] != in_buf) && c == '"' && parse_point[i-1] != '\\')

// line 638, a SEPARATE, sibling `else if` branch a few dozen lines later:
// no escape check anywhere near it, and none is needed -- opening a quoted
// region has no escape-run to be ambiguous about, only closing one does
else if (c == '"') {
    strings[0].ptr = &parse_point[i];
    in_quote = true;
    ignoring = true;
}
```

The pre-R09 producer paired an escape comparison with **every** quote
comparison sharing a method, base expression (`parse_point`), and index
variable (`i`) — with no requirement that the two be part of the same
conditional. `ParseStream_SMC` is one big state-machine loop using a single
index `i` throughout, so the one real escape check at line 457 was wrongly
attached to the unrelated line-638 branch as well. The raw fact rows made
this legible directly: both entries in `parser_index_checks.tsv` carried the
identical `check_node_id` / `escape_cmp_node_id` (line 457's check), differing
only in which `quote_cmp_node_id` they were attached to.

R09 fixes this in both the CPG producers and the reducer — see
`../../SAME_BOUNDARY_SCOPE_R09.md` for the full trace, the structural fix
(same-condition-or-nested-guard pairing that never climbs through a loop
boundary), and the two new fixtures (`q10`, `q11`) that pin both the false
positive and the legitimate nested-if shape. Re-run under R09, this target
now reports exactly 1 candidate.

### What was found (post-R09)

The one candidate is in `core/logic/TextParsers.cpp:ParseStream_SMC`, line
457. The detection trace:

```cpp
// line ~430: c extracted from buffer via index access
c = parse_point[i];

// line 457: quote-boundary rule with single-position escape check, both
// comparisons in the SAME condition
if ((&parse_point[i] != in_buf) && c == '"' && parse_point[i-1] != '\\')
```

`c = parse_point[i]` populates `charVarOrigin[("c")] = ("parse_point", "i")`.
`c == '"'` is traced back to `parse_point[i]` (offset 0).
`parse_point[i-1] != '\\'` is at offset -1, same base name and index variable,
same enclosing condition. The pairing logic records a
`SINGLE_POSITION_INDEX_CHECK` row, which is the detectable form.

### Chain: vacuous negative

Chain status: `NOT_ESTABLISHED — NO_STRUCTURED_CONSUMER_MODELLED_IN_UNIT`

The fopen source IS resolved (line 101, `RESOLVED_EXTERNAL`, mode "r"); the
buffer is populated by `fread` at line ~173. The consumer — callbacks on
`ITextListener_SMC` (`ReadSMC_KeyValue`, `ReadSMC_NewSection`,
`ReadSMC_RawLine`) — is not in the reachability model's consumer vocabulary.
The chain fails at the consumer end, not because of a flow gap.

One additional fopen in `smn_filesystem.cpp:176` was recorded as
`AMBIGUOUS_MODE_ARGUMENT` (R08's fopen mode-argument filter could not resolve
the mode string) and is excluded from the chain but listed under
`unresolved_source_identities`. That filter is working as intended.

### Why this validates the detector

The pattern in `ParseStream_SMC` is genuinely structural — it is the same
`buf[i] == '"' && buf[i-1] != '\\'` shape the analyser was built to detect.
The source and the parse loop are real. The chain is vacuous only because the
SMC consumer callbacks are an application-framework type not in the model
vocabulary; this is a scope gap in the chain, not a gap in the parser layer.

The R09 run confirms:
- `charVarOrigin` correctly links an extracted-char variable to its buffer
  and index when the RHS is an index access.
- The pairing logic produces `SINGLE_POSITION_INDEX_CHECK` for the (offset 0,
  offset −1) pair sharing a base, index variable, and enclosing condition —
  and, as importantly, does NOT produce one for the unrelated sibling branch
  that merely shares the base and index variable (this is exactly what R08
  got wrong; see above).
- The chain layer correctly records `NO_STRUCTURED_CONSUMER_MODELLED_IN_UNIT`
  rather than fabricating a positive.

## C/C++ model gap: getc() + prev_char (libspatialite)

`CGX-GROUP/libspatialite src/spatialite/virtualgeojson.c` contains a
quote-boundary rule that the analyser cannot detect:

```c
int prev_char = '\0';
while ((c = getc(parser->in)) != EOF) {
    if (is_string) {
        if (c == '"' && prev_char != '\\') {
            is_string = 0;
        }
    }
    prev_char = c;
}
```

`c = getc(parser->in)` is a function call, not an index-subscript access. It
does not produce an `indexParts` result, so `c` is never added to
`charVarOrigin`. Without a `charVarOrigin` entry, the pairing between
`c == '"'` and `prev_char != '\\'` (a loop-carried variable) cannot be
established by the current producer.

The chain would be complete if the parser were detected: the source is
`fopen(path, "rb")` (a `STORED_FILE_READ` in the model) and the consumer is
`sqlite3_exec()` (a `STRUCTURED_DATA_IMPORT` in the model). Both ends are
modelled; only the parser layer is blind.

**This is a false negative.** A future revision could extend `charVarOrigin`
to track the `getc()`/`fgetc()`/`fread()` + scalar-assignment pattern
(`c = getc(f); prev = c;`), analogous to how R05 added support for
parameterised delimiters and R06 added search-established positions. Until
then, a "0 candidates" result from C/C++ code that uses `getc()` loops is not
evidence that no such rule exists.

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
