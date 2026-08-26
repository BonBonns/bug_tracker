# ATTACKER_CONTROLLED_REGEX_COMPLEXITY: Stage 1 sink semantics, frozen. 9/9 fixture-verified.

New property, built from a real, undisclosed finding (RocketChat's autotranslate.ts quadratic
regex) generalized into a reusable TChecker property, matching the exact fixtures-first, real-AST-
inspection-before-any-rule discipline used for SSRF, path traversal, and command injection.

## Why this property is structurally different from the other three
SSRF/path-traversal/command-injection all trace: does attacker-controlled DATA reach a FIXED,
known-dangerous SINK FUNCTION. This property is different: the sink function itself
(`.test()`/`.match()`/`.search()`/`.replace()`/etc.) is not inherently dangerous -- danger depends
on the STRUCTURE of the regex PATTERN being executed against attacker-controlled input. Two
operands matter, not one: the REGEX_INPUT (the attacker-influenceable matched-against string) and
the REGEX_PATTERN (whose STRUCTURE, not just its presence, determines risk). Stage 1 here is
therefore pure operand identification for BOTH positions -- no danger classification yet.

## Sink families and operand identification
    RegExp.prototype methods (test, exec): receiver IS the pattern, arg1 is the input string
    String.prototype methods (match, matchAll, search, replace, replaceAll): receiver IS the
      input string, arg1 is the pattern

## Pattern resolution: traces to the literal source, or honestly reports it can't
    DIRECT_LITERAL                    -- pattern is a regex literal directly at the call site
    VARIABLE_TO_LITERAL               -- pattern is a variable, traced to `const x = /literal/`
    VARIABLE_TO_NEW_REGEXP_LITERAL    -- traced through `new RegExp('literal string')`
    VARIABLE_TO_NEW_REGEXP_DYNAMIC    -- `new RegExp(nonLiteralValue)` -- genuinely cannot be
                                         statically resolved, correctly reported as such, never
                                         guessed at
    UNRESOLVED_IDENTIFIER / UNRESOLVED_OTHER -- no resolution path found

## Fixture set: 9 cases covering every sink family plus the pattern-resolution spectrum
`redos_sink_characterization/src/sink_shapes.js`. Includes, as real, non-synthetic verification
material: the EXACT pattern from RocketChat's already-disclosed CVE-2025-5892
(`/^:|\s+:/` via `.search()`) and the EXACT pattern from the new autotranslate.ts finding
(`/^\s*<p>|</p>\s*$/gm` via `.replace()`) -- both resolve correctly as DIRECT_LITERAL, confirming
this Stage 1 correctly identifies the two real cases this property was built from.

## Result: 9/9 correct, zero bugs found on the first pass
    testCall                     -> input=userString  pattern=/^[a-z]+$/            VARIABLE_TO_LITERAL
    execCall                     -> input=userString  pattern=/^[a-z]+$/            VARIABLE_TO_LITERAL
    matchCall                    -> input=userString  pattern=/^[a-z]+$/            DIRECT_LITERAL
    matchAllCall                 -> input=userString  pattern=/[a-z]+/g             DIRECT_LITERAL
    searchCall                   -> input=userString  pattern=/^:|\s+:/             DIRECT_LITERAL (= CVE-2025-5892's real pattern)
    replaceCall                  -> input=userString  pattern=/^\s*<p>|</p>\s*$/gm  DIRECT_LITERAL (= the new autotranslate.ts finding's real pattern)
    newRegExpLiteralThenTest     -> input=userString  pattern=^[a-z]+$              VARIABLE_TO_NEW_REGEXP_LITERAL
    dynamicPattern                -> input=userString  pattern=userPattern (dynamic) VARIABLE_TO_NEW_REGEXP_DYNAMIC
    attackerControlsPattern       -> input=fixedString pattern=userPattern (dynamic) VARIABLE_TO_NEW_REGEXP_DYNAMIC
                                      (correctly distinguishes: here the ATTACKER controls the
                                      PATTERN itself, not the matched string -- a structurally
                                      different, arguably worse case, correctly identified as its
                                      own shape rather than conflated with the input-controlled cases)

## What was explicitly NOT done (matching every prior Stage 1 in this project)
No complexity/danger classification of the resolved patterns -- that is Stage 2, next. No wiring
into the adjudicator. No corpus scanning. Full formal regex-safety proof (NFA ambiguity analysis) is
explicitly out of scope for this whole property -- matching how real ReDoS-detection tooling
(safe-regex, recheck, eslint-plugin-redos) operates on heuristic pattern-recognition, not exhaustive
formal proof; Stage 2 will state this limitation precisely rather than overclaim completeness.

## Status
Sink semantics: frozen, 9/9 fixture-verified, zero bugs. Ready for Stage 2: complexity/danger
classification, to be verified against three cases already independently confirmed by direct timing
measurement in the prior investigation -- one real known-dangerous pattern (CVE-2025-5892), one real
newly-found dangerous pattern (autotranslate.ts), and one real confirmed-safe pattern (cors.ts) --
giving Stage 2 empirically-grounded ground truth, not just theoretical classification.
