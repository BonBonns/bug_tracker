# Prefilter fix: file/folder-exclusion parity (R01) + comment-stripping regression fix (R02)

Per direct instruction, task 4: "If code changes are justified, use these 21 packages strictly as
the development/regression set." This documents both the fix and the real regression its own
regression test caught and forced a second correction for -- the fix is not considered validated,
and `prefilter_select_25.py` is not considered frozen, until this document's own R02 section.

## R01: file/folder-exclusion parity with jssrc2cpg's real defaults

Justified directly by `PREFILTER_DIVERGENCE_AUDIT.md`'s finding: ~82% of the 14-package
`NO_COMPLEXITY_CANDIDATE` divergence traced to files jssrc2cpg's own real frontend already
excludes by default (`node_modules` anywhere in the path, `docs/`/`dist/`/`test/`/etc. folders,
`.d.ts`/`.min.js`/etc. filename suffixes, any line >= 10,000 chars). This is low-risk: it only
narrows `iter_js_ts_members`'s own file selection to match a real, decompiled, empirically-
confirmed constant (`_jssrc2cpg_would_ignore_path`, `_LINE_LENGTH_THRESHOLD`) -- it never touches
`classify_dangerous()` (the frozen, Scala-verified Stage 2 port) or the real Joern-based producer/
reducer at all.

## R02: comment-stripping regression, root cause, and fix

The same commit also added a comment-stripping pass (`_strip_comments`, motivated by the
divergence audit's secondary JSDoc-misparse finding -- `@appthreat/sqlite3`/`realm`/`jsmeow`) --
**this pass introduced a real regression**, caught by this document's own regression test
(`audit/validate_prefilter_fix.py`, run per instruction point 4 against exactly these 21 real
packages' already-recorded real Joern ground truth) before anything was committed or frozen.

**Regression found:** `velociradix@8.3.1`'s own real, previously-detected `PUBLIC_EXPORT_
RESOLUTION_GAP` sink (`index.mjs:940`, `fieldRegex` in `Context.graphql()` -- real
`dangerous_sinks: 1` per the actual Joern run) scored `corrected_prefilter_score=0` under the R01
comment stripper -- meaning a corrected-prefilter rerun over the full 494-package corpus would
have silently DROPPED a package containing a real, already-confirmed complexity candidate. This
is exactly the "must never undercount" invariant this whole prefilter is designed never to
violate, so it was treated as blocking: "This is a real regression -- I must not let this stand."

**Root cause (confirmed by direct instrumentation, not inferred):** the R01 `_strip_comments` was
a bare regex pass (`/\*.*?\*/` DOTALL) applied to raw text with no string-literal awareness.
`velociradix`'s real source contains an HTTP Accept-header wildcard check,
`accept.includes('*/*')` (`index.mjs`, well before the sink) -- the string literal `'*/*'` itself
contains the two-character substring `/*`, which the regex misread as a comment-OPEN delimiter.
The non-greedy `.*?` then hunted forward for the next unrelated `*/` and found one ~9,000
characters later (inside a real `/** ... */` JSDoc comment), so everything in between --
including the real, genuinely dangerous `fieldRegex` literal at line 940 -- was silently deleted
from the scanned text before `REGEX_LITERAL` ever ran. Confirmed directly:
`'/(\\w+)\\s*(?:\\(([^)]*)\\))?\\s*\\{([^}]*)\\}|(\\w+)(?:\\s*\\(([^)]*)\\))?/g' in raw_text` is
`True`; the same check against the R01-stripped text is `False`. The content-based line-length
exclusion was independently ruled out first (the file's longest real line is 2,989 chars, well
under the 10,000-char threshold).

**Fix:** replaced the regex-based stripper with a single left-to-right scan (`_strip_comments`,
R02) that treats single-quoted, double-quoted, and template-literal string BODIES as opaque spans
-- comment delimiters found inside one are never recognized, and the span's own characters are
always copied through verbatim (only real comments are ever replaced; string contents never are).

**Why this is provably sound, not another shortcut:** outside of a tracked string span, `//` is
*always* a real line comment in valid JS -- there is no way to write two adjacent, un-quoted `/`
characters that isn't one (even `a / /re/.test(x)`, division immediately followed by a regex
literal, requires a separating token; a bare `//` is itself parsed as a line comment by every real
JS tokenizer, not just this one). Likewise `/*` outside a string is always a real block comment --
a regex literal can never legally begin with `*` (`SyntaxError: nothing to repeat`), so `/*` can
never be the start of a regex literal either. The only known residual imprecision is nested
template-literal interpolation (`` `a ${`b`} c` ``), which can mis-locate a template span's own
boundary -- disclosed, and still safe by the same argument: mis-tracking can only leave an
occasional real comment un-stripped (the tolerated over-count direction, per this prefilter's own
documented invariant), never delete real code, since string/template bodies are always copied
through rather than removed.

## Validation: regression test re-run after the R02 fix

`audit/validate_prefilter_fix.py`, unchanged, re-run against the corrected prefilter and the same
21 packages' real, already-recorded Joern ground truth (`prefilter_fix_validation.json`):

```
{
  "n_packages": 21,
  "n_real_no_complexity_candidate": 14,
  "n_now_correctly_zero": 12,
  "n_still_falsely_nonzero": 2,
  "n_real_positives": 7,
  "n_real_positives_still_detected": 7,
  "n_real_positives_now_missed_REGRESSION": 0
}
```

**Zero regressions: all 7 real positives (the 6 `COMPLEXITY_ONLY` + `phplike`) are still detected,
`velociradix` included** (`corrected_prefilter_score=1`, up from the regression's `0`). 12 of the
14 real `NO_COMPLEXITY_CANDIDATE` packages now correctly score 0 (up from 0 of 14 before either
fix), confirming the R01 file-exclusion fix's own intended effect survived the R02 correction
intact.

## Disclosed residual: `ssh2` and `mariasql` still score falsely nonzero (not a regression, not fixed)

Both scored nonzero before R01/R02 too (via different, now-superseded reasons) -- this is a
pre-existing, disclosed prefilter imprecision, not something either fix introduced or was
expected to resolve. Direct inspection of both real sites:

- `ssh2@1.17.0`: `const RE_HEADER = /^([\x21-\x39\x3B-\x7E]{1,64}): ((?:[^\\]*\\\r?\n)*[^\r\n]+)\r?\n/gm;`
  -- a real, structurally-DANGEROUS-shaped regex literal, declared as a module-level `const` among
  several sibling `RE_*` regexes, consumed later via a differently-named local variable
  (`regexp.exec(str)`) whose real resolution back to `RE_HEADER` specifically (as opposed to
  `RE_BEGIN`/`RE_DATA`/`RE_HEADER_ENDS`, also declared nearby) is exactly the kind of def-use
  resolution the real Joern Stage 1 (sink identification) performs and this prefilter does not.
- `mariasql@0.2.6`: `var RE_PARAM = /(?:\?)|(?::(\d+|(?:[a-zA-Z][a-zA-Z0-9_]*)))/g;` -- same shape:
  a real, structurally-dangerous literal assigned to a variable, whose real usage as a `.exec`/
  `.test` argument (if any) is not textually adjacent to the declaration.

**Not fixed, deliberately.** `classify_dangerous()` (the frozen Stage 2 port) is correctly
identifying both literals' *structure* -- this is not a classifier-port bug. What's missing is
Stage-1-equivalent sink-call identification (proving a specific literal is the resolved argument
to `.test`/`.exec`/`.match`/`.search`/`.replace`/`.replaceAll`, as opposed to merely appearing
somewhere in the file) -- real def-use/call-target resolution, which is precisely the class of
analysis this prefilter's own header comment already scopes OUT ("a cheap TEXT-level proxy...
must never undercount... [may] overcount"). Attempting it with more regex heuristics would risk
introducing new UNDER-count risk (the unsafe direction) for uncertain precision gain on a
prefilter whose only real job is nominating candidates for the real Joern pipeline to adjudicate
-- exactly the same fix-vs-adjudicate judgment already applied to `phplike`
(`phplike_review/ROOT_CAUSE_AND_DECISION.md`): a provably-safe fix is taken; an unsafe shortcut is
not, in favor of disclosure. Both packages remain real, honest over-counts within this prefilter's
own documented tolerance -- they cost one extra real Joern run each if reselected, never a missed
candidate.

## Status

`prefilter_select_25.py` at this state (R01 file-exclusion parity + R02 string-aware comment
stripping) is frozen as the corrected implementation, validated with zero regressions against the
21-package real ground truth (instruction point 4/5). The 21 packages used for this development
and validation are excluded from any new blind selection (see `pilot25_blind2_selection.json`
and its own provenance file) to preserve genuine blindness for the next pilot, per instruction
point 6.
