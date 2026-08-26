# ATTACKER_CONTROLLED_REGEX_COMPLEXITY: property built and frozen, generalized from a real finding

Built from the RocketChat autotranslate.ts discovery, generalized into a reusable TChecker property
with the same fixtures-first, real-AST-first, empirically-grounded discipline as every other
property this session. Stage 1 (sink semantics) and Stage 2 (complexity classification) both
frozen, both fixture-verified.

## Stage 1: sink semantics, 9/9 fixture-verified, zero bugs
Identifies, for every regex-execution call shape (`test`/`exec`/`match`/`matchAll`/`search`/
`replace`/`replaceAll`), which operand is the attacker-influenceable INPUT and which is the
PATTERN, tracing the pattern back through variable assignments and `new RegExp(...)` construction
to its literal source where statically possible -- and honestly reporting when it isn't
(`VARIABLE_TO_NEW_REGEXP_DYNAMIC`), never guessing at an unresolvable pattern's structure. Also
correctly distinguishes the case where the ATTACKER controls the PATTERN itself rather than the
input string -- a structurally different, arguably worse shape, kept separate rather than conflated.

## Stage 2: complexity classification, 7/7 fixture-verified against EMPIRICALLY MEASURED ground
## truth, not theoretical pattern-shape reasoning
Every SAFE/DANGEROUS label in the fixture set was independently verified by direct timing
measurement before being used as ground truth -- including running the exact patterns from the
real, disclosed CVE-2025-5892 and the real, newly-found autotranslate.ts case, and, for the two
cases not already measured in the prior investigation, testing them fresh:

    quantifierAtEndFullyAnchored (/^prefix\s*$/): 100000 chars -> 0.207ms -- confirmed safe
    textbookNestedQuantifier (/^(a+)+$/): n=20 -> 7.4ms, n=25 -> 228ms -- confirmed exponential
      (each +5 chars ~30x the time, matching 2^5 -- genuine exponential blowup, not assumed from
      textbook reputation alone)
    simpleAnchoredAllowlist (/^[a-z0-9_-]+$/): 200000 chars -> 0.554ms -- confirmed safe

## The heuristic, stated precisely -- what it checks and why
    DANGEROUS if: (a) a nested quantifier -- a parenthesized group containing its own +/*, itself
      quantified with +/* (the classic exponential shape), OR (b) a top-level alternation branch
      contains a quantified portion with MORE PATTERN CONTENT after it within that same branch
      (not just an anchor) -- this is the actual mechanism confirmed in BOTH real dangerous cases
      found this session: an unanchored or multi-position scan must retry every possible quantifier
      length at every position when the trailing content fails to match, which is what the
      quadratic timing measurements directly demonstrated.
    SAFE if: fully anchored (^...$), no g/m flags, no nested quantifier, no risky alternation
      branch -- matching the real cors.ts case exactly.
    UNKNOWN otherwise, including any dynamically-constructed pattern that cannot be statically
      resolved to literal text -- never guessed.

## Explicit, stated limitation -- this is a heuristic, not a formal proof
This does NOT perform full regex-safety analysis (NFA construction, ambiguity detection, or
anything approaching a formal proof of worst-case complexity). It checks for two well-established,
empirically-confirmed-relevant structural shapes. Real regexes can be dangerous in ways this
heuristic doesn't catch (e.g. deeply nested groups beyond one level, backreferences, Unicode
property escapes interacting with quantifiers) -- and it can in principle flag a pattern DANGEROUS
that some more sophisticated analysis would show is actually bounded in a specific case. This
matches exactly how real-world ReDoS tooling operates (safe-regex, recheck, eslint-plugin-redos are
all heuristic/pattern-based, not exhaustive provers) -- stated here explicitly rather than left
implicit, the same discipline Stage 2B applied to command-injection's blacklist classification.

## Status
Both stages frozen, fully fixture-verified against real, independently-measured ground truth. Ready
for Stage 3: wiring into the parameterized adjudicator and testing against a real corpus (RocketChat
itself is the natural first target, given this property was generalized directly from a real finding
in it) -- the same sequence every other property in this project followed.
