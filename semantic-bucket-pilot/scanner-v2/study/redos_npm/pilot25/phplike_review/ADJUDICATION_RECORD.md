# Adjudication record: `phplike@2.5.12`, `PACKAGE_API_INPUT_REACHABLE` finding

**Classification: `CONFIRMED_FALSE_POSITIVE_FOR_FROZEN_COMPLEXITY_MODEL`.**

This record is deliberately narrow. It certifies one specific regex, at one specific site, in one
specific pinned package version, against one specific classification rule, verified by one
specific bounded scaling test on one specific runtime. **It is not a claim that this regex is
universally safe** (see "Scope, precisely" below) and **it must never be generalized into a
"leading disjoint literal is always safe" suppression rule** in the frozen classifier -- the
experiment that produced this record's own disjointness evidence also disproved that general
rule: a leading literal prevents the blowup only under additional semantic conditions (this
record's own overlap counter-test showed a literal that is common but NOT disjoint from the
quantified class reproduces real quadratic blowup), and disjointness alone may still be
insufficient once alternation, flags, Unicode case-folding, surrounding expression context, or
unanchored/global search is involved differently than in this one case. This record adjudicates
this one finding. It authorizes no rule change.

## Identity

| Field | Value |
|---|---|
| Package | `phplike` |
| Pinned version | `2.5.12` |
| Tarball integrity | sha1 `d69cc5c338aa0c9448e646443ce128204d85c0de` (matches the npm registry's own published `dist.shasum` for this exact version; independently re-fetched and re-verified against the registry, not assumed from the original pilot run) |
| Canonical source path | `src/js/string.js` (package-root-relative, i.e. `package/src/js/string.js` inside the tarball) |
| Whole-file sha256 | `cb68bb734bc93223f27cb0494736db19014c0a7e4f20175dea2a0293d9fdbc24` |

## Regex node / site identity

| Field | Value |
|---|---|
| Declaration site | `src/js/string.js:86`, inside `exports.sprintf` (declared `src/js/string.js:85`) |
| Sink call site (real, Joern-resolved) | `src/js/string.js:209`, `return format.replace(regex, doFormat);` |
| Pilot run's own sink node id | `sink_node_id: 30064773793` (from the real Joern-based producer's `pilot25_results.json` record for this package) |
| Tainted argument | `format` = `arguments[0]`, `exports.sprintf`'s own real first parameter -- correctly `EXPORTED_FUNCTION_PARAMETER` per `source_boundary` |
| Sink method | `String.prototype.replace`, one of the frozen Stage 1 sink set |

## Exact regex fingerprint

Full literal (as it appears verbatim in the canonical source, including delimiters and flags):

```
/%%|%(\d+\$)?([-+\'#0 ]*)(\*\d+\$|\*|\d+)?(\.(\*\d+\$|\*|\d+))?([scboxXuidfegEG])/g
```

| Component | sha256 |
|---|---|
| Pattern body only (no delimiters/flags) | `49c72a8b8a68ef8c3e541c7c13ca0bd4b54ab054b0b3b9fcde3e9296f8ab40ac` |
| Full literal (incl. `/`.../`g`) | `01af1055c7d1690658813c1655fbd7dc6ebd2a6c9ba7ecb3e8874f49d03ef5f0` |

Flags: `g` (global). No `i`/`u` (no case-insensitivity, no Unicode mode) on this literal -- see
"Scope, precisely" below for why that matters to this record's own limits.

## Why the frozen classifier flagged it (Stage 2, real, unmodified)

The `%(\d+\$)?...` branch, inside a top-level alternation (`%%|...`), contains a quantified
sub-pattern (`\d+`) followed by more pattern content within the same branch (`\$`, then further
optional groups) -- textually the same shape as CVE-2025-5892's own confirmed-real `\s+:` case.
The frozen `export_redos_npm_integ.sc`'s own `classifyPattern()` was not modified to produce or
evaluate this finding; only the finding's OWN disposition (false positive vs. true positive) is
adjudicated here.

## Disjointness evidence (the real distinguishing condition, formalized and stress-tested)

Root cause, in full, is in `ROOT_CAUSE_AND_DECISION.md` (this directory); summarized precisely
here for the record:

- The dangerous branch requires a literal `%` before its own `\d+` quantifier is ever reached.
  `%` is character-class-**disjoint** from `\d` (the quantified atom) -- a run of digits can never
  itself contain a `%`, so each `%`'s own backtrack search is bounded to its own local digit run;
  there is no cross-position compounding.
- **Positive control (this exact regex, adversarial timing)**: `phplike_review/time_sprintf_regex.js`,
  re-run fresh for this record (`phplike_review/timing_measurement_output_v2.txt`) on
  **Node.js v22.22.2, V8 12.4.254.21-node.39**:
  - single `%` + N digits, no terminator, n=40,000 chars: 0.365ms
  - many `%`+digit-run pairs across the string, n=39,984 chars (1,904 segments): 0.419ms
  - digits + dot + more digits (second optional group), n=80,002 chars: 0.488ms
  - **Linear scaling confirmed at every measured size** (roughly doubling input roughly doubles
    time; no quadratic or exponential growth up to 80,002 characters).
- **Negative control (disproves a general "leading literal" suppression)**:
  `phplike_review/overlap_test.js` -- a synthetic regex `a([a-z]+Q)` where the gating literal `a`
  **overlaps** (is a member of) the quantified class `[a-z]`, run on all-`a` adversarial input.
  Result (`phplike_review/overlap_test_output.txt`): real quadratic blowup, ~1040x time for a 40x
  input-length increase. **A leading literal alone, even a common one, does not prevent the
  blowup; only disjointness from the specific quantified atom does, and even that was tested only
  for this one branch shape, not proven as a general property.**

## Scope, precisely -- what this record does and does not certify

**Certifies**: for THIS pattern, THIS sink, THIS package version, evaluated against THIS frozen
classifier's own DANGEROUS rule (alternation branch with quantifier followed by more content),
the finding is a false positive -- confirmed by direct timing measurement, not reasoning alone,
on the runtime named above.

**Does NOT certify**:
- That `/%%|%(\d+\$)?([-+\'#0 ]*)(\*\d+\$|\*|\d+)?(\.(\*\d+\$|\*|\d+))?([scboxXuidfegEG])/g` is
  safe under a DIFFERENT regex engine, a different Node/V8 version with a different backtracking
  regex implementation, or under Unicode-mode/case-insensitive matching (this literal uses
  neither, so no evidence here bears on either).
- That any OTHER regex containing a disjoint gating literal is safe -- disjointness was shown
  here to be *necessary* evidence for this branch shape to stay linear, not sufficient in general;
  the instruction that produced this record explicitly notes alternation, flags, Unicode folding,
  surrounding expression context, and unanchored/global search could each independently defeat a
  disjointness-based argument in a case not tested here.
- That the frozen classifier's own alternation-branch rule is correct or complete in general --
  only that, in this one confirmed instance, it produced a false positive under its own current,
  unmodified definition.

## Disposition

`MANUALLY_REJECTED` / `CONFIRMED_FALSE_POSITIVE_FOR_FROZEN_COMPLEXITY_MODEL`. No change was made
to `export_redos_npm_integ.sc`, `classify_dangerous()`, or any other classifier code as a result
of this record. No general suppression rule (leading literal, disjoint gating literal, or
otherwise) was added anywhere in this codebase.
