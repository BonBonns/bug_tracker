# ESCAPE-PARITY-BOUNDARY -- parser-only layer (dialect-separated)

Supersedes the parser layer of R01. Covers **only** how a quote-boundary rule is
recovered from a resolved AST/CPG site and classified. Delayed-dataflow reachability is
deliberately **not** in this layer and is added only after this one is frozen.

## 1. The boundary this revision enforces

R01 used one dialect-blind regex parser for both the PHP/PCRE historical differential and
the ECMAScript corpus. That was wrong, and it was not harmless.

The published corrected pattern is PCRE:

```
7.110 corrected   /'((?:[^'\\]++|\\.)*+)'/sS
```

`[^'\\]++` and `)*+` are **possessive quantifiers**. They do not exist in ECMAScript.
R01's fixture `c14b-historical-corrected/index.js` shipped that pattern as a JavaScript
regex **literal**, and R01 classified it `PARITY_ESTABLISHED` — a clean ECMAScript
negative. The JavaScript engine disagrees:

```
$ node -e "new RegExp(\"'((?:[^'\\\\]++|\\\\.)*+)'\")"
SyntaxError: Invalid regular expression: /'((?:[^'\\]++|\\.)*+)'/: Nothing to repeat
```

The pattern cannot exist in JavaScript at all. The JS frontend stores a regex literal's
text without validating it, so a dialect-blind parser downstream turned a PHP pattern into
a JavaScript "finding". That is exactly the conflation this revision removes: **successful
parsing of the PHP pattern was never evidence that the JavaScript path is correct.**

(The 7.109 faulty pattern `/'(.*?)(?<!\\)'/S` *is* valid ECMAScript — lookbehind is
ES2018+ — so only the corrected half was invalid. That asymmetry is precisely why the
error was easy to miss.)

## 2. Architecture: separate adapters, one shared parity rule

```
  dialect_ecmascript.py ──┐
                          ├──► regex_ast.py  (shared representation + the parity rule)
  dialect_pcre.py       ──┘
                              boundary_model.py  (dispatcher; stamps dialect + role)
```

- `_grammar.py` holds the grammar core. **Every construct that differs between dialects
  is behind a feature flag**; there is no permissive mode.
- `dialect_ecmascript.py` rejects possessive quantifiers, atomic groups `(?>...)`, inline
  modifier groups `(?i)`, comment groups `(?#...)`, recursion/conditionals, `(?P<>)` named
  groups, and PCRE-only escapes (`\A \Z \z \G \K \h \R \N ...`) with `DialectError`.
- `dialect_pcre.py` accepts them.
- `regex_ast.py` states the parity rule **once**, structurally: a boundary rule
  establishes parity iff every escape character it can consume is consumed as part of an
  escape **pair**.

Every result carries its provenance, and the mapping is enforced in code:

| | |
|---|---|
| historical fixture | `regex_dialect: PCRE`, `evidence_role: HISTORICAL_DESIGN_DIFFERENTIAL` |
| npm findings | `regex_dialect: ECMASCRIPT`, `evidence_role: CORPUS_ANALYSIS` |

`classify()` **raises** if asked for `CORPUS_ANALYSIS` under `PCRE`. PCRE evidence cannot
be requested for corpus analysis, so the two can never be tallied together by accident.

## 3. Behavioural confirmation: escape runs 0..6, each dialect in its own engine

`parity_matrix/` builds one subject per (rule, run-length) and applies it in that
dialect's **own** engine — PCRE through PHP's `preg_match_all`, ECMAScript through node's
`RegExp`. The ECMAScript conclusions therefore rest on nothing PHP did.

`.` = obeys the parity rule at that run length, `X` = does not.

| rule | dialect | structural verdict | runs 0..6 |
|---|---|---|---|
| historical faulty (7.109) | PCRE | `SINGLE_CHAR_LOOKBEHIND` | `..X.X.X` |
| historical corrected (7.110) | PCRE | `PARITY_ESTABLISHED` | `.......` |
| one-char lookbehind | ECMASCRIPT | `SINGLE_CHAR_LOOKBEHIND` | `..X.X.X` |
| classic parity | ECMASCRIPT | `PARITY_ESTABLISHED` | `.......` |
| unrolled-loop parity | ECMASCRIPT | `PARITY_ESTABLISHED` | `.......` |
| negated class, one char | ECMASCRIPT | `NEGATED_CLASS_ONE_CHAR` | `XXXXXXX` |
| no escape awareness | ECMASCRIPT | `NO_ESCAPE_AWARENESS` | `.X.X.X.` |

The one-position rule's signature is exact: correct at run 0, correct at **every odd** run,
wrong at **every even** run >= 2. That is the parity defect itself, reproduced
independently in both engines.

`NO_ESCAPE_AWARENESS` shows the exact complement (`.X.X.X.`) — right on even runs, wrong
on odd. It is a genuinely different correctness shape, which is why it is deliberately
**not** a candidate for this property.

## 4. Controls: 17/17

`check_parser_model_r02.py` -> `ESCAPE_PARITY_PARSER_MODEL=17/17`, `PROMOTION_GATE=PASS`,
covering the 15 required parser controls plus provenance and site-identity discipline.

| control | result |
|---|---|
| P1 escape runs 0..6, both engines | 7 run lengths x 7 rules, no engine errors |
| P2 odd runs -> quote escaped | all parity rules *and* both one-position rules agree |
| P3 even runs -> quote terminates | parity rules obey at every even run; one-position rules violate at every even run >= 2 |
| P4 one-char negative lookbehind | candidate (ECMAScript, from a real CPG site) |
| P5 explicit parity-counting construction | negative |
| P6 backslashes inside character classes | parsed as escape atoms, not class terminators |
| P7 escaped backslashes in regex literals | survive the CPG round trip, parse as a pair |
| P8 alternation affecting the quote branch | one incomplete branch still yields a candidate |
| P9 nested / non-capturing groups | neither verdict hidden |
| P10 lookbehind unrelated to quote termination | never a candidate |
| P11 dynamic `RegExp` | classified only when the pattern identity is uniquely resolved |
| P12 regex-looking text in strings/comments | never discovered as a site |
| P13 PCRE-only syntax under ECMAScript | always `FOREIGN_DIALECT_SYNTAX`, never silently parsed |
| P14 flags | recorded as evidence; do not move the parity conclusion |
| P15 real 7.109 / 7.110 patterns | candidate / negative, under PCRE, tagged historical |
| P16 provenance | dialect+role on every record; role guard enforced |
| P17 site identity | four sites, identical rule text, four distinct CPG node ids |

**P9 found a real gap in the shared parity rule.** An escape pair written as its own group,
`(?:\\.)`, was not recognised because the pairing scan only paired *sibling* atoms. The
scan now recurses into groups (and skips non-consuming lookaround). Fixed before freezing.

**P12** is a discovery control, not a pattern control: the fixture holds three strings and
a comment containing regex-looking text plus one real regex, and exactly **one** site is
discovered — from the CPG literal node, never from a source-text search.

**P14** note: flags are recorded (`flags`, `unknown_flags`) and the verdict is explicitly
flag-independent (`flags_affect_verdict: false`). No flag moves the parity conclusion
because none has a modelled reason to; `g`/`s`/`m`/`u`/`i` change matching behaviour, not
whether the rule's structure establishes run parity.

## 5. Regression sweep over all real data

The P9 fix changed the shared parity rule, so every distinct ECMAScript pattern recovered
from real CPGs — the 20 pilot packages plus both fixture sets, **143 distinct patterns** —
was classified under both the R01 model and this one:

| change | count |
|---|---|
| `UNCLASSIFIED_BOUNDARY_SHAPE` -> `PARITY_ESTABLISHED` | 1 (the P9 nested-group fix) |
| `PARITY_ESTABLISHED` -> `ABSTAIN: FOREIGN_DIALECT_SYNTAX` | 1 (the invalid-in-JS fixture in §1) |
| `UNCLASSIFIED_BOUNDARY_SHAPE` -> `ABSTAIN: MALFORMED_PATTERN` | 1 (a truncated pattern in `node-libcurl`) |
| **new candidates introduced** | **0** |

Both changed verdicts move *away* from asserting a clean negative, and no change
manufactures a positive.

## 6. Pinned artifacts

`historical/ARTIFACT_HASHES.txt` pins, by sha256: both published plugin archives (7.109,
7.110), the single source file in each carrying the boundary rule, all four behavioural
harnesses, the rule set, and the engine versions used (PHP 8.4.19 / PCRE 10.42, node
v22.22.2).

Parser layer frozen in `PARSER_MODEL_FREEZE.txt`:

```
bcf5634c4a85a51d08c0130755095094f76f679e30244b4199c39339e1f4d3ea  parser_model/regex_ast.py
ca4b7b66b381d5418dab9cc232f9cd58cc20791aabceb124393cdad21fe4e1e6  parser_model/_grammar.py
f323036a6d99461a46f180088b0263e4190c5ec7175f446ff136e48c27a43160  parser_model/dialect_ecmascript.py
32115db86924b3a23a6787747acaee58fe0bed2dfc59b80c7bd757fd0091f75d  parser_model/dialect_pcre.py
a8a7d5f41a657deaa6638aeb68d5ee167822f30801eff37c85a870d13ee58b5b  parser_model/boundary_model.py
b025a0b21ba5e82d5e43e6e3b4a0079b5fe1c9d6a2d7d952df41d78cf74503e9  check_parser_model_r02.py
```

## 7. Status of the R01 layer and its pilot

R01's four frozen files still verify against `FREEZE_HASHES.txt` and were not modified.
Per the protocol R01 itself stated, a correction to the model means **the R01 pilot set
becomes development evidence**: its headline (9 analyzed packages, 0 candidates) was
produced by a dialect-blind parser and is not carried forward as corpus evidence. The
regression sweep in §5 shows the corrected model introduces no candidate on that data, so
the *direction* of the earlier result is unchanged — but it is superseded, not reaffirmed,
and a fresh blind set will be drawn when reachability is re-added.

`c14b-historical-corrected` is retained as R01 evidence but is **invalid as an ECMAScript
fixture**; the historical differential now lives entirely in the PCRE lane.

## 8. What comes next

This layer is frozen. Only after this point does the next revision add
stored-source -> transform -> structured-consumer reachability on top of it, with its own
controls and its own blind set. Site discovery stays structural throughout: pattern bodies
are parsed, regexes are never found by searching source text.

Nothing here is an impact, severity or exploitability assessment.
