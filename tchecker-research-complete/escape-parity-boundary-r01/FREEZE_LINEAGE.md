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
| `REACHABILITY_FREEZE.txt` | R04 stored-source → transform → consumer | 1 entry superseded by R07 |
| `DELIMITER_IDENTITY_FREEZE.txt` | R05 delimiter identity | 2 entries superseded by R06 |
| `SEARCH_POSITION_FREEZE.txt` | R06 search-established positions | intact |
| `SEARCH_SPACE_FREEZE.txt` | R07 traced vs. vacuous chain negatives | current |

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

## Results produced under each revision

Corpus results are labelled by the revision that produced them:
`study/bounty_corpus/results/` predates R05, `results_r05/` is R05,
`results_r06/` is R06 and `results_r07/` is R07. They are kept side by
side because the difference between them is itself the evidence that R05 does
what it claims — nothing is overwritten to make the current revision look like
it was always right.
