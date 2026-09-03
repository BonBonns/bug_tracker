# R06 — search-established quote positions

`reportable=false`. No security impact, severity or exploitability is assessed.

## The gap this closes

Through R05, the two halves of a one-position rule were paired only when the
quote half was a **comparison**. Scanners routinely establish "position `p`
holds a quote" with a search instead:

```js
let p = input.indexOf(quoteChar, cursor);   // JavaScript
```
```cpp
size_t p = s.find(QUOTE, cursor);           // C++
```

A rule written that way was never paired, so `input[p - 1] === ESCAPE` went
unclassified even when both delimiters resolved cleanly. R05 made such sites
*visible*; it did not make them *decidable*.

R06 lets a resolved search position stand in for a quote comparison at offset
zero on the same base and position variable. Search calls recognised:
`indexOf` / `lastIndexOf` in JavaScript, `find` / `find_first_of` / `rfind` and
`strchr` / `strrchr` / `memchr` in C/C++.

## The error this revision had to avoid

The obvious over-reach is treating a **forward** look as a one-position rule:

```js
if (input[p + 1] === QUOTE) { p += 2; continue; }   // doubled delimiter
```

That is the doubled-delimiter idiom. It consumes the pair, so it is
parity-**correct**, and calling it a candidate would be a false positive on
correct code — in exactly the place CSV parsers live.

Only backward offsets pair. `offsetParts` recognises subtraction and not
addition, which is what enforces it, and control S2 fails if a forward doubling
check ever reaches the candidate path. That control is the reason this revision
was deferred out of R05 rather than bolted on.

A search position whose delimiter is unresolved does **not** stand in for a
comparison: the method already abstains on delimiter identity and must not
reach a verdict through the back door (control S3).

## Controls

`check_search_position_r06.py` — **6/6**, over 9 JavaScript and 6 C++ fixtures
compiled by real Joern. S1 search position + backward check is a candidate in
both languages, S2 the forward doubling check never is, S3 an unresolved
delimiter reaches no verdict, S4 search-established sites are recorded with a
resolution, S5 every pre-R06 per-site verdict is unchanged, S6 no impact
language.

S5 is pinned by `fixtures_delim/PRE_R06_VERDICTS.json`, read from the R05
commit's own fact tables — 38 sites across four corpora. R01 through R05 all
still pass.

## Effect on the corpus

| target | R05 → R06 records | candidates |
|---|---|---|
| PapaParse | 11 → 15 | 0 → 0 |
| everything else | unchanged | unchanged |

The four new PapaParse records are its `indexOf`-established quote positions,
which now appear as sites and abstain — correctly, because its quote and escape
characters are user configuration. The Mozilla differential is untouched: 1
candidate on the 2025-07-08 snapshot, 0 on the live tree.

**Stated plainly: R06's candidate path is exercised by fixtures only.** No
target in this corpus has a search-established one-position rule with resolvable
delimiters, so the revision adds visibility here rather than findings. The
fixtures show the pairing works in both languages; the corpus shows it does not
fire on these seven targets. Those are different claims and only the first is
demonstrated by controls.

## What is still not modelled

- **The chain layer does not treat an HTTP response header as a source.** This
  is the property's specified scope, not a defect: it was defined over *delayed*
  import, restore and text-transformation pipelines, and a response header is
  not stored text. Widening it would change what the property is, which is a
  decision to take deliberately rather than absorb into a bug fix.
- Delimiters that resolve only across a function boundary (a quote character
  passed as a parameter from a single call site) are still unresolved, and
  abstain.
