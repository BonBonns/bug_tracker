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
| `REACHABILITY_FREEZE.txt` | R04 stored-source → transform → consumer | intact |
| `DELIMITER_IDENTITY_FREEZE.txt` | R05 delimiter identity | current |

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

## Results produced under each revision

Corpus results are labelled by the revision that produced them. Results under
`study/bounty_corpus/results/` were produced before R05; results under
`study/bounty_corpus/results_r05/` were produced after. They are kept side by
side because the difference between them is itself the evidence that R05 does
what it claims — nothing is overwritten to make the current revision look like
it was always right.
