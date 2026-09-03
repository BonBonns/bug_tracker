# R09: same-boundary-scope pairing fix

`reportable=false`. No security impact or severity is assessed anywhere below.

## What was wrong

Both parser producers (`producers/cpp_escape_parity_facts.sc` and
`producers/escape_parity_facts.sc`) paired an escape comparison (`buf[i-1] !=
'\\'`) with a quote comparison (`buf[i] == '"'`) whenever the two shared a
**method**, a **base expression**, and an **index variable** — with no
requirement that they be part of the same conditional. The reducer
(`escape_parity_sites.py`) then compounded this: for a given quote-comparison
site it attached **every** index-check row found anywhere in the method, not
just the one naming that site's own comparison node.

A single character-by-character scanner routinely has more than one `if`
branch comparing the current character against a quote literal on the same
buffer and loop index — an *opening*-quote branch and a *closing*-quote
branch are the ordinary shape. Only the closing branch needs an escape check;
opening a quoted region needs no escape-awareness at all. The old pairing
logic could not tell these apart and manufactured a second, spurious
candidate for the branch that has no boundary rule at all.

## How it was found

Not by construction — by re-verifying a real scan result. The R08 SourceMod
precision-target run (`alliedmodders/source2mod`, see `REGRESSION_TARGETS.md`)
reported 2 candidates in `core/logic/TextParsers.cpp:ParseStream_SMC`. Reading
the actual source at both reported lines showed one genuine one-position rule
(line 457, closing-quote branch) and one branch with no escape check anywhere
near it (line 638, opening-quote branch, `else if (c == '"') { in_quote =
true; ignoring = true; }`). The raw fact tables confirmed the second row was
manufactured by the same-method-only join: both rows in
`parser_index_checks.tsv` carried the identical `check_node_id` and
`escape_cmp_node_id` (the line-457 check), differing only in which
`quote_cmp_node_id` they were attached to.

## The fix

A quote comparison and an escape comparison are now paired only when they are
part of the **same boundary rule**:

- they sit in the same condition (a flat `a && b` / `a || b`), or
- one is nested inside a branch guarded by the other (`if (a) { if (b)
  {...} } }`, in either order).

This is computed structurally from the CPG: `nearestControlId` finds the
nearest enclosing **IF**-shaped control structure (loops don't count — a loop
body is not a decision), and `isWithinControl` climbs the AST from one
comparison toward the other's guard, refusing to climb through a loop
boundary. Climbing through *other, unrelated* `if` nodes is allowed and
required, so a rule split across nested ifs still pairs.

An earlier version of this fix used "any ancestor at any depth" for the
nesting check, with no loop boundary at all. That still produced a false
positive: a search-established quote position taken once per loop iteration
(`p = s.indexOf(quote, cursor)`, a sibling statement to the escape-guarded
branch, both inside the same `while`) shares the loop as a common ancestor
with the escape check without sharing its decision. This was caught while
regenerating the R06 search-position fixtures (`fixtures_delim/d08-*`,
`fixtures_delim_cpp/e05_search_position.cpp`) under the first version of the
fix, before anything was frozen — see the fixture-level detail below.

The reducer fix is the second, independent layer: `escape_parity_sites.py`
now filters `checks_by_method` down to rows whose `quote_cmp_node_id` equals
the **current site's own** comparison node id, rather than attaching every
check found anywhere in the method. Both fixes are needed together — the
producer fix stops the spurious row from being written at all; the reducer
fix stops a genuinely-different site in the same method from borrowing
another site's check even when the producer's own join is otherwise correct.

## What changed in each corpus

- **SourceMod** (`results_r08/sourcemod-textparsers/` — kept as the frozen R08
  record — vs `results_r09/sourcemod-textparsers/`): 2 candidates → **1
  candidate**. The surviving candidate is line 457 (`ParseStream_SMC`'s
  closing-quote branch), unchanged in every field. The line-638 opening-quote
  branch is now `NEGATIVE` / `NO_ESCAPE_AWARENESS` with no borrowed
  `single_position_checks`.
- **Mozilla** (`dom/base/MimeType.cpp:SplitMimetype`, the gecko-dev prefix
  snapshot): re-run against the same CPG under the fixed producer — **still
  exactly 1 candidate, same site, same boundary rule.** This finding was
  always a flat `&&` condition (`c == '"' && (i == 0 || s[i-1] != '\\')`), the
  simplest case the fix was never going to touch. Re-verified rather than
  assumed.
- **PapaParse / mailparser / node-sql-parser / sql-parser-cst**: unaffected —
  none of their `index_checks` rows changed under R09 (JS producer regenerated
  and diffed; only `fixtures_delim`'s and `fixtures_delim_cpp`'s search-position
  fixtures had legitimate changes, both accounted for above).

## Fixture evidence

Two new C/C++ fixtures in `fixtures_cpp/src/`:

- `q10_unrelated_branch_negative.cpp` — the SourceMod shape in miniature: one
  `for` loop, one closing-quote branch with a real escape check, one sibling
  opening-quote branch with none. Expect: 1 candidate, 1 negative, no borrowed
  evidence on the negative.
- `q11_nested_if_candidate.cpp` — the same one-position rule as `q01`, written
  as two nested `if`s instead of one `&&` condition. Expect: still a
  candidate (proves the fix does not regress recall for the nested-guard
  shape).

`check_cross_language_r03.py` gained X16 (asserts the q10 split) and X17
(asserts the q11 nesting still pairs). `check_search_position_r06.py`'s S1
was corrected: it previously asserted that **every** search-position site in
`d08`/`e05` becomes a candidate, which was itself validating a symptom of the
bug (the old pairing made all three search calls in each fixture candidates).
It now asserts exactly one candidate per fixture — the search call actually
nested inside the escape check's guard — and that the other two are
`NEGATIVE`. `check_delimiter_identity_r05.py`'s D11 and (already, since R06)
`check_search_position_r06.py`'s S5 scope their pinned-verdict comparison to
the exact sites the baseline recorded, so adding q10/q11 to `fixtures_cpp`
does not spuriously fail them.

All R01–R08 gates still pass on their own controls: 95/95 across the full
suite (17+17+17+15+12+6+7+4).

## Corpus results relabelled

`study/bounty_corpus/REGRESSION_TARGETS.md` and `CORPUS.md` are corrected to
report 1 SourceMod candidate, not 2, with this document linked as the reason
the number changed. `results_r08/sourcemod-textparsers/` is kept as-is (the
record of what R08 actually produced, matching the project's stated practice
of not rewriting earlier revisions' archives); the corrected run is
`results_r09/sourcemod-textparsers/`.
