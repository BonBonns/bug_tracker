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
dangerous branch requires a LITERAL `%` to even be entered before its own quantifier is reached;
each `%` occurrence's own backtrack is bounded to its own local digit run. **Root cause,
formalized and stress-tested, full writeup in `phplike_review/ROOT_CAUSE_AND_DECISION.md`**: the
real distinguishing structural condition is NOT the gating literal's real-world frequency (an
earlier, now-superseded framing) -- it is whether the gating literal is character-class-DISJOINT
from the quantified atom it precedes. Direct timing proof: a gating literal that OVERLAPS the
quantified class (`a([a-z]+Q)` on all-`a` input, where `a` is common) reproduces the SAME
quadratic blowup CVE-2025-5892 shows (`phplike_review/overlap_test_output.txt`: ~1040x time for
40x input); phplike's own disjoint case (`%` vs `\d`) stays flat regardless of scale. This is a
real, distinct root cause from the already-documented and already-fixed suffix-delimited-nested-
quantifier false positive (`REDOS_STAGE2_SUFFIX_DELIMITER_FIX.md`) -- not the same bug
re-appearing, a genuinely different gap in the SAME "alternation branch with quantifier followed
by more content" rule, which currently has no disjointness check at all (the property's own
EXISTING prefix/suffix-delimiter fixes already require exactly this kind of disjointness check,
just for a different, nested-quantifier shape -- never yet extended to this rule).

## Decision, per direct instruction point 8 and the fix-vs-adjudicate question

**No real candidate survived manual review.** The measured result is a genuine, disclosed zero,
not glossed over: 21/21 packages scanned successfully; the single raw candidate found is a
confirmed false positive by direct timing evidence, not by assumption. Per direct instruction --
*"If no real candidate appears, report the measured zero and decide whether the frozen complexity
model is too narrow before integrating it"* -- the finding here is not that the model is too
NARROW, but that its existing alternation-branch rule is, in this one confirmed instance, too
WIDE.

**Fix-vs-adjudicate: ADJUDICATION, not a structural fix, decided and justified in
`phplike_review/ROOT_CAUSE_AND_DECISION.md`.** A safe general fix needs real character-class
disjointness analysis (proven necessary, not optional, by the overlap stress test above) -- a
genuinely new capability, not a small patch, and an unsafe shortcut version has now been directly
shown to introduce real false negatives. This documented review record stands as the adjudication
(no live `adjudication_registry.py`-style table exists for REDOS yet, since it is not wired into
the npm pipeline). NOT built or attempted in this pass (the analyzer was not modified after the
pre-registered selection was committed, per direct instruction).

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
