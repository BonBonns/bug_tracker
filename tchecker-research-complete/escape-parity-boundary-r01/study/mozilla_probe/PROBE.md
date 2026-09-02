# Exploratory probe: Mozilla repositories

**Status: exploratory. Outside the pre-registered corpus and outside every corpus total.**
This was an ad-hoc test of whether the shape occurs in real Mozilla code, not a blind
draw. It is recorded because it found a defect in the analyzer.

## What was probed

| repo | commit | engine | scope |
|---|---|---|---|
| `mozilla/gecko-dev` | `5836a062726f715fda621338a17b51aff30d0a8c` | C/C++ (c2cpg) | sparse checkout: `modules/libpref`, `netwerk/cookie`, `parser/htmlparser`, `xpcom/ds`, `dom/base`, `security/manager/ssl` (325 .cpp) |
| `mozilla/nunjucks` | `2025c933fba374482ef97122514bb36de6bf9de4` | JavaScript (jssrc2cpg) | 86 source files |

## The analyzer was wrong, and this found it

The first C/C++ run over the gecko subset reported **zero candidates**. One record stood
out — `dom/base/MimeType.cpp:256` classified `NEGATIVE / PARITY_ESTABLISHED_IN_METHOD` —
so the source was read. It is the shape:

```cpp
// TMimeType<char_type>::SplitMimetype
bool inQuotes = false;
for (size_t i = 0; i < aMimeType.Length(); i++) {
  char_type c = aMimeType[i];
  if (c == '"' && (i == 0 || aMimeType[i - 1] != '\\')) {   // one preceding position
    inQuotes = !inQuotes;
  } else if (c == ',' && !inQuotes) { ... }
}
```

Two real analyzer defects, both found only because this was run on real code:

1. **`BOOLEAN_TOGGLE` was too loose.** `inQuotes = !inQuotes` is structurally `X = !X`,
   identical to an escape flag, so it counted as an escape-parity mechanism and
   *exonerated* the one-position rule. But that toggle tracks **quote state**, not escape
   parity. A toggle now qualifies only when a controlling condition tests the current
   character for **equality** against the escape character. Requiring equality at offset
   zero also excludes the `s[i-1] != ESCAPE` test that is itself the defect — note that
   the naive fix ("does a controlling condition mention the escape char") would have
   still passed this code, because its condition does mention it.

2. **The two halves of a rule were only paired when both were direct indexed accesses.**
   Real parsers extract the character first (`char_type c = aMimeType[i];`) and compare
   the *variable* to the quote while testing `aMimeType[i-1]` against the escape. Such a
   variable is now mapped back to the `(base, index)` it was read from at offset zero.

Both are fixed, with `fixtures_cpp/src/q09_quote_state_toggle.cpp` as a regression
fixture modelled on this exact code. All four gates pass after the fix
(17/17, 17/17, 15/15, 15/15).

## Result after the fix

`dom/base/MimeType.cpp:256` classifies **`ESCAPE_PARITY_PARSER_CANDIDATE`**
(`SINGLE_POSITION_INDEX_CHECK`, base `aMimeType`, index `i`, offset −1). The other eight
records in the subset stay negatives. `mozilla/nunjucks`: 37 records, **no candidates**
(33 with no quoted-string construct, 2 with no escape awareness, 2 abstentions).

## Behavioural confirmation

`mime_parity.cpp` reimplements that loop faithfully and runs it against inputs whose
closing quote follows an escape run of length 0..6, beside the same loop with parity
established. Nothing else from Mozilla is executed.

| escape run | agrees with parity? |
|---|---|
| 0 | yes |
| 1 | yes |
| **2** | **no** |
| 3 | yes |
| **4** | **no** |
| 5 | yes |
| **6** | **no** |

`..X.X.X` — the same signature the historical PHP rule and the ECMAScript lookbehind
produce. Worked example at run 2 (an escaped backslash, so the quote *should* close):

```
input          text/plain;p="v\\",text/html
this loop  ->  [text/plain;p="v\\",text/html]        (one part: the quote never closed,
                                                      so the comma was not a separator)
parity     ->  [text/plain;p="v\\"] [text/html]      (two parts)
```

## What this does and does not establish

- It establishes that the **shape is present** in current mozilla-central C++, and that
  the loop's own splitting behaviour diverges from escape-run parity at even runs >= 2.
- The reachability layer reports **`NOT_ESTABLISHED`**: no delayed source reaches this
  parser and no structured consumer is reached, so it stays a candidate and is **not**
  promoted. That is expected — this parses MIME strings, not stored text — and it means
  the second-order chain this property looks for is absent here.
- Whether inputs reaching `SplitMimetype` can carry backslash escapes at all, and what
  follows if they can, is **not established here** and was not investigated.
- No impact, severity or exploitability assessment is made. `reportable=false`.

## Consequence for the corpus run

The analyzer changed after the corpus run had started, so per this property's own
protocol that in-flight run becomes development evidence and is re-run from the start
with the corrected analyzer against the same pre-registered selection.
