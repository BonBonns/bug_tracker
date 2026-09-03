# Freeze lineage

Each revision freezes the artifacts it depends on by hash. When a later
revision changes one of those artifacts, the earlier freeze file is **not**
rewritten — it is the record of what that revision actually froze, and editing
it would erase the only evidence of what changed. The lineage below names every
entry a later revision supersedes, and `verify_freezes.py` enforces exactly
that: superseded entries are expected to differ, everything else must still
match byte for byte.

| Freeze file | Revision | Status |
|---|---|---|
| `FREEZE_HASHES.txt` | R01 parser layer | 1 entry superseded by R05 |
| `PARSER_MODEL_FREEZE.txt` | R02 dialect-separated regex model | intact |
| `CROSS_LANGUAGE_FREEZE.txt` | R03 JavaScript + C/C++ | 2 entries superseded by R05 |
| `REACHABILITY_FREEZE.txt` | R04 stored-source → transform → consumer | 2 entries superseded by R08 (via R05 and R07 intermediately) |
| `DELIMITER_IDENTITY_FREEZE.txt` | R05 delimiter identity | 2 entries superseded by R06 |
| `SEARCH_POSITION_FREEZE.txt` | R06 search-established positions | intact |
| `SEARCH_SPACE_FREEZE.txt` | R07 traced vs. vacuous chain negatives | 2 entries superseded by R08 |
| `SOURCE_MODE_FREEZE.txt` | R08 fopen mode-argument filter | intact |
| `SAME_BOUNDARY_SCOPE_FREEZE.txt` | R09 same-boundary-scope pairing fix | current |

## What R05 supersedes, and why

R05 changed three artifacts:

- `producers/escape_parity_facts.sc` (frozen by R01)
- `producers/cpp_escape_parity_facts.sc` (frozen by R03)
- `escape_parity_sites.py` (frozen by R03)

The change adds delimiter-identity resolution: a quote-boundary site is now
recorded when the comparison names a delimiter *variable* that resolves to a
literal, and recorded as an abstention when the identity cannot be resolved.
Before R05 such sites were not recorded at all.

This widens what the analyser can **see**. It does not move any verdict that
was already reachable, and that is checked rather than asserted:
`fixtures_delim/PRE_R05_VERDICTS.json` pins every per-site verdict produced by
the pre-R05 code over the R01 and C/C++ fixture corpora — 28 sites — and gate
control D11 fails if any one of them moves. The R01, R02, R03 and R04 gates all
still pass against their own controls.

## What R06 supersedes, and why

R06 changed both producers again, to let a resolved search position stand in for
a quote comparison at offset zero. `escape_parity_sites.py` is unchanged by R06.

The same discipline applies: `fixtures_delim/PRE_R06_VERDICTS.json` pins all 38
per-site verdicts the R05 code produced across four corpora, read from the R05
commit's own fact tables, and control S5 fails if one moves.

## What R07 supersedes, and why

R07 changed `escape_parity_chain.py`, frozen by R04, so that a chain records the
search space it failed within and its reasons distinguish a traced negative from
one the model could never have produced otherwise. No verdict moves: the change
is to what the record *says*, and the R04 gate still passes on its own controls.

## What R08 supersedes, and why

R08 changed two artifacts:

- `producers/cpp_reachability_facts.sc` (last changed by R05, originally frozen by R04)
- `escape_parity_chain.py` (changed by R07, originally frozen by R04)

The C/C++ producer previously matched every `fopen` call as a `STORED_FILE_READ`
delayed source regardless of its mode argument. A hand scan of the gecko-dev prefix
snapshot's two "resolved sources" found that both open files in write-only mode
(`"wb"` and `"wb+"`) for unrelated subsystems (frame recording, window dump output)
and cannot supply read data to a text parser. The fix inspects the mode argument: only
mode literals containing `r` or `+` are included; `"w"` / `"wb"` / `"a"` / `"ab"`
literals are excluded as `WRITE_ONLY_MODE_EXCLUDED` (not emitted). Non-literal mode
arguments are retained as `AMBIGUOUS_MODE_ARGUMENT`.

The reducer gains `flow_edges_by_kind` in every candidate chain's `search_space` so
each segment of the source→parser→consumer path reports its own edge count rather than
only an aggregate. The aggregate `flow_edges_in_unit` cannot prove that a specific
segment's flow query ran and returned empty; the per-kind split lets a reader verify
each segment independently.

No verdict moves: the gecko-dev candidate's chain status stays NOT_ESTABLISHED but the
reason changes from `NO_DELAYED_SOURCE_REACHES_PARSER` (incorrectly implied traced)
to `NO_SOURCE_API_MODELLED_IN_UNIT` (correctly vacuous for an analysis unit that has
no fopen-for-read calls). All R01–R07 gates still pass.

## What R09 supersedes, and why

R09 changed three artifacts:

- `producers/cpp_escape_parity_facts.sc` (last changed by R08, originally frozen by R03)
- `producers/escape_parity_facts.sc` (last changed by R06, originally frozen by R01)
- `escape_parity_sites.py` (last changed by R05, originally frozen by R03)

Both producers previously paired an escape comparison with a quote comparison
whenever they shared a method, base expression, and index variable — with no
requirement that they be part of the same conditional. The reducer compounded
this by attaching every check found anywhere in a method to every quote site
in that method, not just the site the check actually named. A scanner with
both an opening-quote branch (no escape check needed) and a closing-quote
branch (a genuine one-position rule) in the same method had the closing
branch's check wrongly borrowed as evidence for the opening branch.

Found by re-verifying, not by construction: the R08 SourceMod precision-target
scan reported 2 candidates in `alliedmodders/source2mod`'s `ParseStream_SMC`,
and reading the actual source at both lines showed only one was a real
boundary rule. See `SAME_BOUNDARY_SCOPE_R09.md` for the full trace, the fix
(structural same-condition-or-nested-guard pairing, never crossing a loop
boundary), and the two new fixtures (`q10`, `q11`) that pin both the false
positive and the legitimate nested-if shape going forward.

No previously-reported candidate outside SourceMod moved: the Mozilla
`SplitMimetype` finding was re-verified against the same gecko-dev CPG under
the fixed producer and is unchanged (it was always a flat `&&` condition, not
a cross-branch artifact). All R01–R08 gates still pass on their own controls.

## Results produced under each revision

Corpus results are labelled by the revision that produced them:
`study/bounty_corpus/results/` predates R05, `results_r05/` is R05,
`results_r06/` is R06, `results_r07/` is R07, `results_r08/` is R08, and
`results_r09/` is R09. They are kept side by side because the difference
between them is itself the evidence that each revision does what it claims —
nothing is overwritten to make the current revision look like it was always
right.
