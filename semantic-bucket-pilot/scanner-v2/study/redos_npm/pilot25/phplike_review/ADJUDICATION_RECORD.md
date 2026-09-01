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
| Tainted argument | `format` = `arguments[0]`, `exports.sprintf`'s own real first parameter -- correctly `EXPORTED_FUNCTION_PARAMETER` per `source_boundary` |
| Sink method | `String.prototype.replace`, one of the frozen Stage 1 sink set |

### Persistent adjudication key

Per direct instruction, Joern's own `sink_node_id` is **not** used as the persistent key --
node IDs are assigned by the CPG builder and are not guaranteed stable across a rebuild of the
same source (a different Joern/js2cpg version, a different build order). The stable key is
derived instead purely from source-identity facts (`audit/finding_id.py`, `make_finding_key`):

```
composite_key = redos-finding::phplike@2.5.12::src/js/string.js::01af1055c7d1690658813c1655fbd7dc6ebd2a6c9ba7ecb3e8874f49d03ef5f0::L209
key_hash       = 6b6ce4cf2503a5cfb9e3da6217dbb999f098a1de4b3ba881ca454d809bf41791
```

(`01af1055...` is this record's own full-literal regex fingerprint, below; `L209` is the sink
call line in the canonical source.) **`sink_node_id: 30064773793`** (from the real Joern-based
producer's `pilot25_results.json` record for this package, matching the original pilot run) is
retained below as supporting evidence for that one specific analysis run -- never as this
record's own key.

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
- **Positive control (this exact regex, adversarial timing), complete benchmark record**:

  | Field | Value |
  |---|---|
  | Script (complete, verbatim, reproduced below) | `phplike_review/time_sprintf_regex_v3.js` |
  | Raw output | `phplike_review/timing_measurement_output_v3.txt` |
  | Runtime | Node.js `v22.22.2`, V8 `12.4.254.21-node.39` (captured by the script itself via `process.version`/`process.versions.v8`, not asserted separately) |
  | Input family | 3 adversarial shapes targeting the flagged branch's own worst case (below) |
  | Input sizes | 1,000 / 5,000 / 10,000 / 20,000 / 40,000 / 80,000 (base `n`; actual string length varies by shape, up to 160,002 chars for shape 3 at `n=80,000`) |
  | Repetitions | 5 per (shape, size) pair; min/median/max reported, not a single sample |
  | Timeout policy | entire process bounded by an external `timeout 10s` wrapper (Unix `timeout` command, enforced outside the Node process, not merely an in-script guard); **not reached** -- exit code `0`, largest single measurement 1.104ms, ~9,000x inside the 10,000ms bound |

  **Script, complete, verbatim (49 lines, reproduced in full so the exact benchmark is part of
  this record rather than referenced only by path):**

  ```javascript
  // Complete, repeatable benchmark for the phplike@2.5.12 sprintf() regex adjudication record.
  // Regex is the exact literal at src/js/string.js:86 (canonical path within the tarball), copied
  // verbatim -- never retyped from a description.
  'use strict';
  const regex = /%%|%(\d+\$)?([-+\'#0 ]*)(\*\d+\$|\*|\d+)?(\.(\*\d+\$|\*|\d+))?([scboxXuidfegEG])/g;

  const REPETITIONS = 5; // per input size, per test family
  const SIZES = [1000, 5000, 10000, 20000, 40000, 80000];

  function timeOnce(input) {
    const t0 = process.hrtime.bigint();
    const matches = input.match(regex);
    const t1 = process.hrtime.bigint();
    return { ms: Number(t1 - t0) / 1e6, matchCount: matches ? matches.length : 0 };
  }

  function bench(label, buildInput) {
    console.log(`--- ${label} ---`);
    for (const n of SIZES) {
      const input = buildInput(n);
      const trials = [];
      for (let r = 0; r < REPETITIONS; r++) trials.push(timeOnce(input));
      const times = trials.map(t => t.ms).sort((a, b) => a - b);
      const min = times[0], max = times[times.length - 1];
      const median = times[Math.floor(times.length / 2)];
      console.log(`n=${n} len=${input.length} reps=${REPETITIONS} ` +
        `min=${min.toFixed(3)}ms median=${median.toFixed(3)}ms max=${max.toFixed(3)}ms ` +
        `matches=${trials[0].matchCount}`);
    }
  }

  console.log(`node=${process.version} v8=${process.versions.v8}`);
  console.log(`regex=${regex.source} flags=${regex.flags}`);
  console.log();

  bench('Test 1: single "%" + N digits, no terminator (targets \\d+\\$ backtrack)',
    n => '%' + '1'.repeat(n));

  console.log();
  bench('Test 2: many "%"+digit-run pairs spread across string (cumulative-backtrack worst case)',
    n => {
      const segLen = 20;
      const nSegs = Math.floor(n / (segLen + 1));
      return ('%' + '1'.repeat(segLen)).repeat(nSegs);
    });

  console.log();
  bench('Test 3: digits, dot, more digits (targets the second optional (\\.(\\*\\d+\\$|\\*|\\d+))? group)',
    n => '%' + '1'.repeat(n) + '.' + '1'.repeat(n));
  ```

  **Result summary** (full output, all 5 repetitions per size, in `timing_measurement_output_v3.txt`):
  - Test 1 (single `%` + N digits, no terminator): n=80,000 chars -> min 0.558ms / median 0.666ms / max 0.720ms
  - Test 2 (many `%`+digit-run pairs, cumulative-backtrack worst case): n=79,989 chars (largest) -> min 0.850ms / median 0.893ms / max 0.910ms
  - Test 3 (digits + dot + more digits, second optional group): n=160,002 chars (largest) -> min 0.924ms / median 1.057ms / max 1.104ms
  - **Linear scaling confirmed at every measured size, across all 5 repetitions per point** (roughly
    doubling input roughly doubles time; no quadratic or exponential growth up to 160,002 characters).
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
