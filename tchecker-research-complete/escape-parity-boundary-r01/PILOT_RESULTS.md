# ESCAPE-PARITY-BOUNDARY-R01 -- bounded npm discovery pilot

Reports parser correctness, transformation integrity, evidence-chain completeness,
abstentions, and measured outcomes. Nothing here is an impact, severity or
exploitability assessment; `reportable` is false on every record.

## 1. What the property decides

A quoted-string parser must decide whether a quote closes the string. The rule is:

```
A quote is escaped when preceded by an odd-length consecutive escape run.
A quote terminates the string when preceded by an even-length consecutive escape run.
```

A boundary rule that inspects only a fixed single preceding position cannot establish
that parity. The property has exactly two classifications:

| classification | requires |
|---|---|
| `ESCAPE_PARITY_PARSER_CANDIDATE` | a structurally incomplete quote-boundary rule, and nothing else |
| `DELAYED_STRUCTURED_TEXT_CONSUMER_REACHABLE` | the above **plus** a proven delayed-source -> transformation -> structured-consumer chain with every identity resolved and unambiguous |

Everything else is a classified NEGATIVE (with a reason) or an ABSTENTION (with a
reason). Abstention is mandatory wherever regex construction, replacement-callback
identity, delayed-source identity, transformation order, or downstream-consumer
identity is unresolved or ambiguous.

## 2. Analyzer, and how classifications are derived

- `regex_boundary_model.py` parses a pattern into a **regex AST** (atoms, character
  classes, groups, quantifiers, alternations, lookaround) and derives the verdict from
  that structure. The parity rule is stated structurally: a rule establishes parity when
  every escape character it can consume is consumed **in a pair**. There is no substring
  matching of patterns or of file text anywhere in the classification path.
- `producers/escape_parity_facts.sc` emits graph facts only, each row carrying its real
  CPG node id: regex sites (literal / constructed / unresolved), character-scanning
  parser sites, single-position index checks, parity mechanisms (modulo-two, boolean
  toggle, backward escape-run walk), delayed sources resolved **through a real import**,
  transform calls, replacement-callback identities, consumers, and dataflow chain edges
  computed by the engine. Identifier resolution is file-scoped, so a same-named binding
  in another file is never mistaken for the definition.
- `escape_parity_r01.py` joins those facts by node identity. Two sites with identical
  rule text are never merged.
- Execution timing (cron / scheduled / deferred registration) is recorded as
  **evidence only** and never reaches a verdict. Gate check K17 asserts this.

Frozen before the pilot (`FREEZE_HASHES.txt`), unmodified since:

```
94c9603a01d61cf882cebf32290a381543e88e536d554c03da9749245aec0411  producers/escape_parity_facts.sc
62016e910e82be1742ab8740f19bb17fe536980b3d23a883df64ba4055b4e432  regex_boundary_model.py
5464addb3be9a83312792fa2035c6c2b7398e603a21fc7c18470e6f29da06bc4  escape_parity_r01.py
ea0476dd469bbb2cf2d97e5202ead2ce172ad7bfbbd195b998466b682fa98bed  check_escape_parity_r01.py
```

## 3. Controls: 17/17

`check_escape_parity_r01.py` -> `ESCAPE_PARITY_BOUNDARY_R01=17/17`, `PROMOTION_GATE=PASS`,
over 15 real-Joern-compiled fixtures covering the 14 required controls. Full per-control
detail is in that gate's docstring. Two points worth stating here:

- **Control 3 is discriminating, not blanket.** The explicit-counting parser is a
  negative *and* a contrasting one-position custom parser in the same code shape
  (`c03b`) is still a candidate. Without that contrast a "negative" would be
  indistinguishable from "the analyzer never looked".
- **Controls 3, 4 and 11 are classified negatives, not absences.** Every
  character-scanning quoted-string parser is emitted as a record, so a parity-correct
  hand-written parser appears with an explicit `PARITY_ESTABLISHED_IN_METHOD` verdict.

## 4. Historical parser differential (outside the npm totals)

Full record in `historical/PROVENANCE.md`. The published before/after change was located
by probing published releases; the boundary is **7.109 -> 7.110**.

```
historical faulty parser     /'(.*?)(?<!\\)'/S
historical corrected parser  /'((?:[^'\\]++|\\.)*+)'/sS
```

Behavioural confirmation in the original language, on synthetic quoted text only
(`historical/differential.php`):

| input | historical faulty parser | historical corrected parser |
|---|---|---|
| even-length escape run (2) before the quote | 1 match, `abc\\', ` -- consumed through the true closing quote, the separator and the next opening quote | 2 matches, `abc\\` and `next` |
| odd-length escape run (1) before the quote | 1 match, `abc\', ` | 1 match, `abc\', ` (identical) |

**Confirmed:** the faulty form mishandles an even-length escape run; the corrected form
preserves quote boundaries, including on the odd-run case the one-character rule already
handled correctly.

The analyzer classifies the faulty form `ESCAPE_PARITY_PARSER_CANDIDATE` and the
corrected form `NEGATIVE` / `PARITY_ESTABLISHED`. In addition, every in-scope structural
verdict was cross-checked against real engine behaviour on both parities
(`historical/xcheck_boundary.php`) and **all agree**.

## 5. The bounded npm pilot

### 5.1 Selection (pre-registered, committed before any outcome was viewed)

The frozen 494-package corpus was scanned in full by the deterministic, source-only
prefilter: **494 scanned, 0 download failures, 0 unreadable archives**. A package is
eligible only with evidence in all four required dimensions (quoted-string parsing;
escape/decode/encode/replacement; archive/dump/import/restore/migration/database-
processing context; structured-text consumer call). **33 packages met all four.** All 33
tie at score 4, so frozen corpus order is the tie-break and the first 20 were selected.
A prefilter match is never a finding.

### 5.2 A correction made to the outcome bucketing (not to the analyzer)

The first pass reported all 20 packages as analyzed with zero candidates. Three packages
produced zero records, which did not look credible for their size, so CPG content was
measured independently for every package. It was not credible:
`node-llama-cpp` had **560 source files extracted and 0 files in its CPG**;
`ember-one-way-controls` had 7,445 extracted and 51 in the CPG.

Counting those as clean negatives would have inflated the result with packages the
frontend never actually parsed. Coverage is therefore reported as a first-class outcome,
and packages below the threshold are bucketed `INFRASTRUCTURE_FAILURE`.

One refinement matters: TypeScript `.d.ts` declaration files carry no executable code and
legitimately produce no CPG nodes, so they are excluded from the denominator. Coverage is
`cpg_files / executable_source_files`, threshold **0.80**, disclosed here so any reader
can re-bucket at a different threshold from `study/pilot_coverage.json`.

The frozen analyzer was **not** modified. Re-running it on the same inputs reproduced
every classification identically, which also confirms determinism.

### 5.3 Outcomes

| bucket | count |
|---|---|
| `PREFILTER_SELECTED` | 20 |
| `PIPELINE_ANALYZED` | **9** |
| `INFRASTRUCTURE_FAILURE` | **11** |
| `NO_PARSER_CANDIDATE` | 9 |
| `ESCAPE_PARITY_PARSER_CANDIDATE` | **0** |
| `DELAYED_STRUCTURED_TEXT_CONSUMER_REACHABLE` | **0** |
| `ABSTAINED` | 3 |

Site-level totals across the 9 genuinely analyzed packages: **207 boundary-rule records**
— 202 regex literals and 5 constructed regexes.

| outcome | sites |
|---|---|
| `NEGATIVE` / `NO_QUOTED_STRING_CONSTRUCT` | 200 |
| `NEGATIVE` / `NO_ESCAPE_AWARENESS` | 2 |
| `ABSTAINED` / `UNRESOLVED_REGEX_CONSTRUCTION` | 5 |
| candidates of either classification | **0** |

Per-package coverage and record counts are in `study/PILOT_OUTCOMES.json`; the full
per-package analyzer output is in `study/pilot_findings/`.

### 5.4 Manual review

The protocol calls for manual review of complete graph-supported candidates only. **There
were none**, so no candidate review was performed. What was reviewed instead was the
integrity of the zero itself — that is what produced the bucketing correction in 5.2.

### 5.5 What this result does and does not say

- It says: across 9 npm packages that the frontend genuinely parsed, the analyzer
  examined 207 real quote-boundary constructs and found **no** rule that decides a quote
  by inspecting a single preceding position. 200 of those constructs are not
  quoted-string parsers at all, which is the expected shape of regex use in a package.
- It does **not** say the property is absent from npm. The analyzed set is 9 packages,
  drawn from a corpus originally assembled for native-addon work, and 11 of 20 selected
  packages could not be parsed completely enough to contribute either way. The pilot is
  bounded discovery, not a survey.
- The prefilter's four dimensions are coarse text signals (`.replace(` and `JSON.parse(`
  are near-ubiquitous), so meeting all four does not imply a quoted-string parser exists
  in a package.

## 6. Known limitations (disclosed, not worked around)

1. **Frontend coverage is the dominant limit of this pilot** — 11 of 20 packages fell
   below the 0.80 executable-source threshold, including two near-total parse failures.
   The cause is in the external JS frontend, not in this property, and is out of scope
   to fix in this revision.
2. **The custom-parser chain is not modelled.** A hand-written character parser has no
   `replace` call to anchor a transform chain, so such sites can reach
   `ESCAPE_PARITY_PARSER_CANDIDATE` but never `DELAYED_STRUCTURED_TEXT_CONSUMER_REACHABLE`.
   Recorded explicitly as `CUSTOM_PARSER_CHAIN_NOT_MODELLED`.
3. **The escape character is modelled as backslash.** Doubled-quote escaping (CSV-style)
   is not covered and is not claimed to be.
4. **Boundary shapes outside the model abstain rather than guess** — e.g. a lookbehind of
   two escape characters, or an alternation whose branches make escape consumption
   ambiguous. These are `UNMODELLED_BOUNDARY_SHAPE`, never negatives.
5. **`NO_ESCAPE_AWARENESS` is deliberately not a candidate.** A parser with no escape
   handling at all is a different correctness shape from one that checks a single
   position, and this property targets only the latter.

## 7. Scope

Everything lives under `tchecker-research-complete/escape-parity-boundary-r01/` on the
isolated branch `study/escape-parity-boundary-r01`. No Serialize DoS, ReDoS, Path
Traversal, N-API, shared pipeline file or existing frozen analyzer was modified. The
property is deliberately **not** integrated into shared reporting or production scanning
in this phase.

Per the pilot protocol, the frozen implementation is not altered after blind selection.
If a correction to the analyzer is required, this pilot set becomes development evidence
and a new revision with a fresh blind set is published.
