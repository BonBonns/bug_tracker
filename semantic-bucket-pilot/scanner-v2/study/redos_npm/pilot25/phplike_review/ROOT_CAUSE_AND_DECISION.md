# `phplike`'s `sprintf()` false positive: root cause, and the fix-vs-adjudicate decision

Per direct instruction: "Root-cause exactly why `phplike` was rejected and determine whether it
requires a structural detector fix or merely an adjudication."

## Correction to the earlier framing

`PILOT25_MANUAL_REVIEW.md`'s original explanation ("the dangerous branch requires a LITERAL `%`
to even be entered... a COMMON character class like `\s` does [compound]") described the
mechanism as being about the gating literal's own real-world FREQUENCY/RARITY. That framing is
**superseded, not just refined** -- direct testing below shows frequency is not the actual
variable at all; a COMMON gating literal (`a`, tested below) stays exactly as safe as a rare one
(`%`), provided one specific structural condition holds. That condition, not frequency, is the
real root cause.

## The real root cause: character-class disjointness between the gating literal and the quantified atom

**Hypothesis, formalized and tested** (`hypothesis_test.py`): a top-level alternation branch's
"quantifier followed by more content" shape is only a REAL complexity risk when the quantified
portion is UNGATED -- i.e. it is the branch's own first matchable element, with no required,
non-quantified literal preceding it within the same branch. `phplike`'s flagged branch
(`%(\d+\$)...`) has literal `%` before its first quantifier (`\d+`); CVE-2025-5892's real
`\s+:` branch and autotranslate.ts's real `^\s*<p>` branch do not (the quantifier IS the
branch's own leading element). `hypothesis_test.py` confirms this text-level check classifies all
three real, already-known cases correctly (`hypothesis_test_output.txt`).

**Critical stress test, before trusting this as a general rule** (`overlap_test.js`): does
"gated by ANY leading literal" stay safe when that gating literal OVERLAPS the quantified
character class -- i.e. the gating literal is itself a possible member of what the quantifier
matches? Real, empirical, direct timing measurement, `overlap_test_output.txt`:

    Overlap case:  a([a-z]+Q)  on "a"*N (gating literal 'a' IS a member of [a-z])
      n=1000  -> 0.6ms
      n=5000  -> 10.4ms   (~17x time for 5x input)
      n=40000 -> 643ms    (~1040x time for 40x input -- real quadratic-class blowup)

    Disjoint control: %(\d+Q) on "%"+"1"*N (gating literal '%' is NOT a member of [0-9])
      n=1000  -> 0.08ms
      n=40000 -> 0.07ms   (flat -- confirms the earlier phplike-shaped result, reproduced)

**This is decisive, not a refinement of the earlier framing: "gated by a leading literal" ALONE
is UNSAFE as a general rule.** It is only safe when that leading literal is additionally
DISJOINT from the quantified atom's own character class -- exactly the same kind of
disjointness check the property's OWN prior, already-fixed suffix/prefix-delimited-nested-
quantifier rules already require (`isSafePrefixDelimitedNestedQuantifier`/
`isSafeSuffixDelimitedNestedQuantifier` explicitly verify `!m.group(2).contains(m.group(1))`
before trusting a delimiter as safe) -- but that disjointness check has never been extended to
the ALTERNATION-branch rule this false positive actually triggers.

## Decision: adjudication, not a structural detector fix, for this round

A safe general fix requires real character-class parsing and set-disjointness computation
between an alternation branch's own leading literal(s) and its first quantified atom -- a
genuinely new, non-trivial capability, not a copy of the existing prefix/suffix-delimiter logic
(which operates on NESTED quantifiers, a different shape). Implementing an unsafe shortcut
version (leading-literal-presence alone, without disjointness) has now been directly demonstrated
to introduce a real class of false NEGATIVES -- a strictly worse outcome for a security scanner
than leaving one confirmed false positive adjudicated and disclosed. Per direct instruction's own
framing ("a structural detector fix or MERELY an adjudication"), the disjointness requirement
is real, correctly-scoped future work, not attempted in this round.

**`phplike@2.5.12`'s `sprintf()` (`string.js:209`) is recorded as a documented, adjudicated false
positive** -- the manual review in `PILOT25_MANUAL_REVIEW.md` IS this record (there is no live
`adjudication_registry.py`-style table for REDOS yet, since it is not wired into the npm pipeline;
per direct instruction, pipeline wiring stays out of scope until a real finding survives review,
so this documented review is the correct, disclosed record for now).

## Disclosed, precisely-scoped follow-up (not built here)

A future Stage 2 refinement, if ever undertaken, needs: (1) parse each alternation branch's own
leading literal/character-class content before its first quantifier; (2) parse the quantified
atom's own character class; (3) verify the two are set-disjoint (no code point in common); (4)
only then treat the branch as gated/safe. Absent that verification, the branch must stay
DANGEROUS -- exactly the property's own existing, conservative default.
