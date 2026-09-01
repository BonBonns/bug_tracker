# Frozen 25-package discovery pilot: manual review

Per direct instruction, step 6 of the pre-registered protocol (see `README.md` and
`pilot25_selection_provenance.json` for corpus/prefilter integrity hashes): the frozen ReDoS
pipeline (`export_redos_npm_integ.sc` -> `redos_verdict.py`, neither modified since the selection
in `pilot25_selection.json` was committed) was run once over the 21 packages the prefilter
selected. `pilot25_results.json` is the complete, real output;
`pilot25_categorized_results.json` reclassifies it into the exact category taxonomy below.

## Terminology, precise

A prefilter **`PREFILTER_SELECTED`** package (e.g. `node-addon-api`) is a package chosen for
deeper analysis -- it is NOT itself a ReDoS finding, and the 21 packages below are the pilot's
own INPUT set, not 21 findings and not 21 unresolved packages. Only a package that reaches
`PACKAGE_API_INPUT_REACHABLE` proceeds to manual review at all.

## Real run result, by category (totals from `pilot25_categorized_results.json`)

| Category | Count | Meaning |
|---|---|---|
| `PREFILTER_SELECTED` | 21 | chosen by the cheap prefilter for deeper analysis |
| `PIPELINE_ANALYZED` | 21 | the real frozen Joern pipeline completed successfully |
| `INFRASTRUCTURE_FAILURE` | 0 | pipeline itself failed to complete (fetch/CPG/producer/reducer) |
| `NO_COMPLEXITY_CANDIDATE` | 14 | zero DANGEROUS-classified regex operations found at all |
| `COMPLEXITY_ONLY` | 6 | a DANGEROUS regex exists, but not reachable from any export |
| `PACKAGE_API_INPUT_REACHABLE` | 1 | DANGEROUS regex reachable from an exported parameter -- the only category manually reviewed |
| `MANUALLY_CONFIRMED` | 0 | -- |
| `MANUALLY_REJECTED` | 1 | `phplike@2.5.12` (below) |
| `ABSTAINED` | 0 | -- |

**21/21 `PIPELINE_ANALYZED` = `PREFILTER_SELECTED`** (`status: OK` on every one -- the first
attempt hit a path bug in `run_pilot25.py`, the orchestration script, not the analyzer; fixed and
confirmed by manually re-invoking `redos_verdict.py` standalone with identical arguments before
touching anything else -- see the `run_pilot25.py` fix commit). `COMPLEXITY_ONLY`'s own 6
packages (`fuse-napi`, `node-addon-api`, `@depup/node-addon-api`, `@h1x4dev/node-addon-api`,
`velociradix`, `koffi`) each have a real DANGEROUS-classified regex somewhere in their own source,
but none of those sinks trace back to an exported function's own parameter -- correctly NOT
promoted to `PACKAGE_API_INPUT_REACHABLE`, and correctly not manually reviewed (per direct
instruction, only that one category proceeds to review).

## Manual review of the one `PACKAGE_API_INPUT_REACHABLE` record

**Site**: `phplike@2.5.12`, `src/js/string.js:209`, `exports.sprintf`'s own
```js
var regex = /%%|%(\d+\$)?([-+\'#0 ]*)(\*\d+\$|\*|\d+)?(\.(\*\d+\$|\*|\d+))?([scboxXuidfegEG])/g;
var a = arguments, i = 0, format = a[i++];
...
return format.replace(regex, doFormat);
```
`format` is `arguments[0]` -- the exported `sprintf()` function's own real first parameter,
correctly identified as `PACKAGE_API_INPUT_REACHABLE` (any caller of `phplike.sprintf(untrusted,
...)` controls `format`). `export_redos_npm_integ.sc`'s frozen classifier flagged the pattern
DANGEROUS via its own documented alternation-branch rule: the `%(\d+\$)?...` branch contains a
quantified portion (`\d+`) with more pattern content after it (`\$`) within the same branch --
textually the SAME shape as CVE-2025-5892's own confirmed-real `\s+:` case.

**Verdict, by direct timing measurement (not reasoning alone) -- CONFIRMED FALSE POSITIVE.**
Per the property's own established discipline ("every SAFE/DANGEROUS label... independently
verified by direct timing measurement before being used as ground truth"), the regex was
extracted verbatim and timed against adversarial input up to 80,000 characters, across three
shapes designed to trigger the flagged branch's own worst case (see `phplike_review/
time_sprintf_regex.js`, `timing_measurement_output.txt`):

    single "%" + N digits, no terminator:       n=40000 -> 0.47ms
    many "%"+digit-run pairs across the string:  n=39984 (1904 segments) -> 0.58ms
    digits, dot, more digits (2nd optional grp): n=80002 -> 0.52ms

**Confirmed linear scaling** (doubling input length roughly doubles time; no quadratic or
exponential growth at any measured size) -- not the confirmed-quadratic behavior CVE-2025-5892's
own real `\s+:` pattern showed on equivalent input.

**Why this differs from the CVE-2025-5892 case, precisely**: `\s` (whitespace) is a COMMON
character -- a long run of it means the regex engine's own per-position match attempts backtrack
at EVERY position within that run, compounding quadratically across the whole string. Here, the
dangerous branch requires a LITERAL `%` to even be entered; each `%` occurrence's own backtrack
is bounded to its own local digit run and never compounds with other `%` occurrences elsewhere in
the string (confirmed directly: Test 2's 1904-segment case, spreading the same total backtracking
work across many independent `%`-anchored segments, is NOT dramatically slower than Test 1's
single-segment case of comparable total length). This is a real, distinct root cause from the
already-documented and already-fixed suffix-delimited-nested-quantifier false positive
(`REDOS_STAGE2_SUFFIX_DELIMITER_FIX.md`) -- not the same bug re-appearing, a genuinely different
gap in the SAME "alternation branch with quantifier followed by more content" rule: that rule does
not currently distinguish a branch requiring a RARE bounding literal (safe, as demonstrated here)
from one reachable via a COMMON character class (the real CVE-2025-5892 shape).

## Decision, per direct instruction point 8

**No real candidate survived manual review.** The measured result is a genuine, disclosed zero,
not glossed over: 21/21 packages scanned successfully; the single raw candidate found is a
confirmed false positive by direct timing evidence, not by assumption. Per direct instruction --
*"If no real candidate appears, report the measured zero and decide whether the frozen complexity
model is too narrow before integrating it"* -- the finding here is not that the model is too
NARROW, but that its existing alternation-branch rule is, in this one confirmed instance, too
WIDE: it does not yet distinguish a bounding literal's own real frequency/rarity in typical input,
the exact structural distinction that made the difference here. This is a real, disclosed,
actionable refinement opportunity for the frozen Stage 2 classifier -- NOT built or attempted in
this pass (the analyzer was not modified after the pre-registered selection was committed, per
direct instruction, and refining Stage 2 itself is a separate, future decision, not implied by
this pilot's own scope).

**Consequence: pipeline wiring and `reportable` enablement both remain out of scope for this
round.** Per direct instruction point 10, `reportable` stays disabled until a real, integrated
package record clears all gates -- no candidate from this pilot did. The `phplike` case is
committed as a real, documented FALSE-POSITIVE regression case (`phplike_review/`) -- useful
evidence for a future Stage 2 refinement decision, exactly the same treatment the property's own
prior suffix-delimiter false positive received.

## What this pilot did establish

- The frozen pipeline runs cleanly end-to-end on 21 real, structurally diverse npm packages
  (21/21 OK, ~15s average per package) -- no crashes, no silent abstentions-as-failures, real
  producer summaries captured for every one (`pilot25_results.json`).
- The pre-registration protocol itself worked as intended: the selection was frozen and committed
  BEFORE any Joern scan ran, and the one real candidate it produced was reviewed and found wanting
  WITHOUT touching the analyzer to "fix" it into non-detection or extend it to catch more --
  exactly the discipline the protocol was designed to enforce.
