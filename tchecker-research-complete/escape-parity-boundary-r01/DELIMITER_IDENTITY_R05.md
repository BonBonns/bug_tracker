# R05 — delimiter identity

`reportable=false`. No security impact, severity or exploitability is assessed.

## The gap this closes

Up to R04 a quoted-string boundary site was recorded only when one side of the
comparison was a quote **literal**. Real parsers routinely parameterise their
delimiters, and every such site was invisible — not a candidate, not a
negative, not even an abstention.

The gap was found by running the property over PapaParse, a regression target.
`papaparse.js:1506`:

```js
if (quoteChar !== escapeChar && quoteSearch !== 0 && input[quoteSearch - 1] === escapeChar)
```

`input[quoteSearch - 1] === escapeChar` is a one-position lookbehind —
structurally the same rule as the pre-fix Gecko `aMimeType[i - 1] != '\\'` that
this property flagged in `SplitMimetype`. The analyser never considered it,
because neither operand is a literal.

## What R05 does

A delimiter variable is resolved to its literal value when **every** assignment
reaching it in the file is a literal. If any assignment is not, the identity is
unresolved and the site **abstains**. Resolution is deliberately all-or-nothing:
a user-configurable quote character genuinely cannot be decided statically, and
an abstention says so where silence said nothing.

An unresolved name is treated as a delimiter only when it provably holds a
quote or escape character on at least one path, following one alias step
(`escapeChar = quoteChar` before `escapeChar = config.escapeChar`) — the exact
shape real parsers use to default one delimiter to another. Without that
constraint, any `x == y` between two identifiers inside a method that indexes a
container looked like a quote-boundary site.

A boundary rule is decided per method, so one unresolved delimiter blocks the
whole method: a quote compared against a literal is not evidence of a correct
parser when the escape character it is paired with is configurable.

Both the JavaScript and the C/C++ producer carry the same rule, and both emit a
`delimiter_resolution` of `LITERAL`, `RESOLVED` or `UNRESOLVED` on every
character-scanner record.

## Controls

`check_delimiter_identity_r05.py` — **12/12**, over 7 JavaScript and 4 C++
fixtures compiled by real Joern. D1 resolved-variable candidate, D2 resolved +
parity counting stays negative, D3 unresolved abstains **and is recorded**, D4 a
non-quote delimiter creates no site, D5 an unresolved escape blocks its whole
method, D6 the real-parser shape abstains rather than vanishing, D7 inline
literals unchanged, D8 C/C++ reproduces all four outcomes, D9 an unresolved
delimiter is never a candidate, D10 every scanner record carries a resolution,
D11 every earlier per-site verdict is unchanged, D12 no impact language.

D11 is the one that matters most. R05 widens what the analyser can **see**; it
must not move a verdict that was already reachable.
`fixtures_delim/PRE_R05_VERDICTS.json` pins all 28 per-site verdicts produced by
the pre-R05 code over the R01 and C/C++ corpora, and the control fails if any
one of them moves. The R01, R02, R03 and R04 gates all still pass.

## Effect on the corpus

Every target was re-run under R05 (`study/bounty_corpus/results_r05/`), with the
pre-R05 results kept beside them.

| target | records before → after | candidates | what changed |
|---|---|---|---|
| PapaParse | 7 → 11 | 0 → 0 | **4 scanner sites now visible**, all abstaining |
| mozilla-firefox (C/C++) | 26 → 26 | 0 → 0 | unchanged |
| gecko-dev pre-fix (C/C++) | 26 → 26 | 1 → 1 | unchanged |
| mozilla-firefox (JS) | 9 → 9 | 0 → 0 | unchanged |
| node-sql-parser | 10 → 10 | 0 → 0 | unchanged |
| sql-parser-cst | 29 → 29 | 0 → 0 | unchanged |
| mailparser | 28 → 28 | 0 → 0 | unchanged |

`papaparse.js:1506` is now recorded, as `UNRESOLVED_DELIMITER_IDENTITY` →
`ABSTAINED`, together with three more sites in the same parser loop (1461, 1499,
1528). That is the correct verdict: PapaParse's quote and escape characters are
user configuration, so the rule's parity cannot be decided statically. The
revision converts silence into a stated abstention; it does not manufacture a
finding.

**No new candidate appeared anywhere.** The Mozilla differential is untouched:
1 candidate on the 2025-07-08 snapshot, 0 on the live tree.

## Two defects found while building this, both fixed

**Delimiter-likeness was too permissive at first.** The initial rule treated any
unresolved identifier as a possible delimiter, which took the Mozilla C/C++ run
from 26 records to 131 with 110 abstentions — from methods like
`FragmentOrElement::CanSkipInCC` and `ShadowRoot::SlotInsertionPointFor`, which
parse nothing. Requiring the name to provably hold a quote or escape character
on some path removed all of it. It also removed three Firefox JS sites that were
byte comparisons in certificate parsing (`this._bytes[this._cursor] == tag`,
`versionBytes[0] == X509v3`) and a clock comparison in a PAC helper — none of
them quoted-string boundaries — while keeping `papaparse.js:1506`.

**`Map.collect` returning a pair rebuilds a Map.** The delimiter-likeness set was
built with `assignedValues.collect { case (k, vs) if … => k }.toSet`. Because `k`
is itself a `(file, name)` pair, Scala rebuilt a `Map[String, String]` keyed by
file, so every delimiter in a file but the last silently disappeared — which is
why the C++ control for a configurable quote character stopped producing a site.
Collecting over `.iterator` fixes it. The control caught this; a corpus run
would not have, because "one fewer record" looks like nothing.
