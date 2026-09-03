# ESCAPE-PARITY-BOUNDARY -- JavaScript and C/C++ detection

## 1. Correction: what the target actually is

The defect was **found** in PHP. That is where the shape came from; it is not what the
analyzer is for. The target engines are **JavaScript/TypeScript** and **C/C++**.

Earlier revisions drifted: they built a PCRE analysis lane, PHP harnesses and pinned PHP
artifacts, and shipped **no C/C++ path at all**. This revision adds the C/C++ engine and
demotes PHP/PCRE to what it should always have been — a **shape reference**. PHP
contributes nothing to any corpus total and is never an analysis target.

## 2. The shape, stated language-neutrally

```
A quote is escaped when preceded by an ODD-length consecutive escape run.
A quote terminates the string when preceded by an EVEN-length escape run.
```

A boundary rule that inspects a **fixed single preceding position** cannot establish that
parity. Every spelling below is the same defect:

| language | spelling |
|---|---|
| C++ | `s[i] == '\'' && s[i-1] != '\\'` |
| C | `*p == '"' && *(p-1) != '\\'` |
| C++ | `s.at(i) == '"' && s.at(i-1) != '\\'` |
| C++ | `s[i] == '\'' && (i == 0 \|\| s[i-1] != '\\')` |
| JavaScript | `s[i] === "'" && s[i-1] !== '\\'` |
| regex (either) | `(?<!\\)'` — one-character negative lookbehind |
| regex (either) | `[^\\]'` — one-character negated class |

## 3. Architecture: one shape model, per-language adapters

```
  jssrc2cpg ─► escape_parity_facts.sc      ─┐
                                            ├─► escape_parity_sites.py ─► one verdict
  c2cpg     ─► cpp_escape_parity_facts.sc  ─┘      (shared shape model)     vocabulary
                                                            │
                                       regex patterns ──────┴──► ECMAScript adapter
                                                                 (JS literals AND std::regex)
```

Both producers emit the **same fact schema**, so a finding means the same thing in either
language. Two things genuinely differ in C/C++ and are handled rather than papered over:

1. **Character literals keep their source escaping.** C/C++ stores `'\\'`, `'\''`, `'"'`
   as written; the JS frontend stores an already-unescaped value. The C/C++ producer
   decodes C escape sequences before any character comparison.
2. **Three character-access forms, not one.** Subscript (`<operator>.indexAccess` and
   `<operator>.indirectIndexAccess` — the latter for an overloaded `operator[]`), pointer
   dereference (`*(p - 1)`), and member call (`s.at(i - 1)`, whose receiver is
   `argumentIndex 0`, unlike the operator forms). All three reduce to
   *(base identity, index expression, offset)* so the shared model needs no per-spelling
   knowledge.

**`std::regex` is ECMAScript.** Its default grammar is ECMAScript, so C++ regex patterns
go to the ECMAScript adapter — the same one JS regex literals use — and never to the PCRE
adapter. Language and regex dialect are separate axes.

## 4. Cross-language gate: 15/15

`check_cross_language_r03.py` -> `ESCAPE_PARITY_CROSS_LANGUAGE=15/15`, `PROMOTION_GATE=PASS`,
over 8 real `c2cpg`-compiled C++ fixtures and the existing `jssrc2cpg` fixtures.

| # | control | result |
|---|---|---|
| X1 | C++ subscript `s[i-1]` | candidate |
| X2 | C++ pointer `*(p-1)` | candidate |
| X3 | C++ member `s.at(i-1)` | candidate |
| X4 | C++ bounds-guarded `(i==0 \|\| s[i-1]...)` | still a candidate — the guard is about staying in bounds, not parity |
| X5 | C++ explicit escape-run counting | negative (`MODULO_TWO` + `ESCAPE_RUN_COUNT_LOOP`) |
| X6 | C++ parity-aware state machine | negative (`BOOLEAN_TOGGLE`) |
| X7 | C++ no escape awareness | negative — a *different* shape |
| X8 | C++ `std::regex` | ECMAScript adapter; one-char class form candidate, parity form negative |
| X9 | JavaScript, own producer | same shape detected |
| X10 | both languages | one shared verdict vocabulary and schema |
| X11 | C++ runtime signature, runs 0..6 | reproduced |
| X12 | all three engines | identical signature |
| X13 | C literal decoding | escape comparison found despite `'\\'` source form |
| X14 | site identity | distinct CPG node ids retained in both languages |
| X15 | discipline | `reportable=false`; no impact/severity/exploitability language |

## 5. Runtime confirmation in three engines

Each engine runs the shape **natively** — native C++ compiled with g++, ECMAScript through
node's `RegExp`, PCRE through PHP. `.` = obeys the parity rule at that escape-run length,
`X` = does not:

| shape | engine | runs 0..6 |
|---|---|---|
| one-position rule (C++ subscript) | g++ | `..X.X.X` |
| one-position rule (ECMAScript lookbehind) | node | `..X.X.X` |
| one-position rule (PCRE lookbehind, the reference) | php | `..X.X.X` |
| explicit counting (C++) | g++ | `.......` |
| parity state machine (C++) | g++ | `.......` |
| parity regex (ECMAScript) | node | `.......` |
| **no escape awareness** (C++) | g++ | `.X.X.X.` |

The one-position rule fails at **exactly** the even runs >= 2, identically in all three
engines. The no-escape-awareness shape fails at exactly the **odd** runs — the complement
— which is why it is a different defect and deliberately not a candidate here.

**A harness correction worth recording:** the first C++ harness scanned from `i = 1`,
skipping the opening quote. That is a second, unrelated defect and it masked the parity
signature (`XXXXXXX` — wrong everywhere, for the wrong reason). Rewritten to guard
position 0 rather than skip it, the signature came out identical to the other engines.

## 6. Frozen

```
af9618f5cd87281fd32cde15aeab3d2be324933af631a030cda7d0bd759000a8  producers/cpp_escape_parity_facts.sc
e4673cd2a31f06caee37adf426877ef501d31ce01618b1b9ff6309c7dea0ea5f  escape_parity_sites.py
a88983c2305eed7441110e10aa3f690a9be9b13f8d7a3c878d2d78d5b74e7c2e  check_cross_language_r03.py
a344468c12974a332d375d8ad1f3ed483e0dfa5329e3ed3216170d5e80cc2a11  parity_matrix/run_cpp.cpp
```

The earlier freezes (`FREEZE_HASHES.txt`, `PARSER_MODEL_FREEZE.txt`) still verify
unchanged. All three gates pass: R01 17/17, parser model 17/17, cross-language 15/15.

## 7. Status and limitations

- **PHP/PCRE is a shape reference only.** The PCRE adapter and the pinned 7.109/7.110
  artifacts remain as provenance for where the shape came from. `boundary_model.classify`
  still refuses `CORPUS_ANALYSIS` under `PCRE`, so PCRE can never enter a corpus tally.
- **Parser layer only.** Stored-source -> transform -> structured-consumer reachability is
  a separate layer, still to be added on top, in both languages.
- **No corpus run yet for C/C++.** The C/C++ engine is validated on compiled fixtures and
  by runtime confirmation; it has not been run over a package corpus. The earlier
  JavaScript pilot remains development evidence, superseded for the reasons in
  `PARSER_MODEL_R02.md`.
- The escape character is modelled as backslash; doubled-quote (CSV-style) escaping is not
  covered and is not claimed to be.
- Unmodelled boundary shapes and unresolved regex construction abstain; they are never
  reported as negatives.

Nothing here is an impact, severity or exploitability assessment.
