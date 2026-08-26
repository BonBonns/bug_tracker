# ReDoS Stage 2: suffix-delimiter false positive fixed, full corpus re-verified

Closes the two open threads from the full-corpus scan: the Stage 2 pattern-classification false
positive is now fixed and frozen as a permanent regression case; the Stage 3 dataflow false
positive is now moot for this specific finding (the sink it pointed at is no longer classified
DANGEROUS at all), though its root cause remains genuinely open and is reported as such, not
claimed resolved.

## The fix
The existing `isSafeDelimitedNestedQuantifier` check (already in place from earlier work this
session, covering the PREFIX-delimiter shape like `(\.\d+)+` from UAParserCustom.js) only handled
patterns where a literal delimiter comes BEFORE the quantified content within a group. RocketChat's
real email-validation regex has the MIRROR-IMAGE shape -- delimiter AFTER the quantified content:
    (?:[A-Z0-9-]+\.)+
The character class `[A-Z0-9-]` cannot itself produce the literal `.` that ends each repetition, so
there is exactly one way to partition a matching string -- structurally safe for the same underlying
reason as the prefix case, just the delimiter position flipped. Added
`isSafeSuffixDelimitedNestedQuantifier`, verified directly against the real pattern before trusting
it (confirmed it extracts the correct character class and delimiter, and that the class genuinely
excludes the delimiter), then combined both checks: `isSafeDelimitedNestedQuantifier = prefix ||
suffix`.

## Frozen as a permanent fixture case, not just a one-off fix
Added `suffixDelimitedNestedQuantifier` (the exact real pattern,
`/\b[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,4}\b/i`) to the Stage 2 fixture set. Its correct
classification is `UNKNOWN`, not `SAFE` -- worth stating precisely why, since this is itself an
honest finding, not a shortfall: the pattern uses `\b` word-boundary anchors, not `^...$`, so it
doesn't qualify for the classifier's SAFE rule (which requires full anchoring as its proof
condition). The fix's job was narrower and specific: stop the FALSE `DANGEROUS` alarm, which it
does -- landing on the conservative, honest `UNKNOWN` middle ground rather than either a false
alarm or an unearned SAFE claim. All 8/8 fixture cases pass with this addition.

## Full corpus re-scanned with the fix
    DANGEROUS pattern sinks: 11  (down from 13 -- the two email-regex occurrences, in
                                   omnichannel/messages.ts and sendTranscript.ts, correctly dropped)
    rows emitted: 18             (down from 20 -- the two spurious request.params-to-email-regex
                                   rows are gone, since that sink is no longer flagged dangerous
                                   at all)
    remaining findings: exactly the two already-investigated cases -- autotranslate.ts (6 rows,
      all message.msg/message.attachments) and BeforeSaveSpotify.ts (12 rows, all message.msg/
      message.urls) -- nothing lost, nothing new introduced by the fix.

## What this means for the Stage 3 dataflow bug
The spurious `request.params`-reaches-email-regex connection is now moot for this specific
finding, since the sink it pointed at no longer qualifies as DANGEROUS in the first place -- the
false alarm is gone regardless of whether that underlying dataflow bug is fixed. The bug itself
(a genuine spurious interprocedural connection somewhere in the corpus) has NOT been root-caused
or fixed -- reported honestly as still open, not silently resolved by the Stage 2 fix that
happened to make it unobservable in this particular case. It could still produce a false positive
against a different, genuinely-dangerous-looking sink in a future scan.

## Full regression sweep
customs.js evidence byte-identical to the established baseline. Both permanent serialize-DoS tests
still pass -- confirmed after this fix, not assumed clean because the change was "just" a regex
heuristic adjustment.

## Status
ReDoS property now stands at: 2 real, source-verified findings across a 1477-file real corpus (one
already-known and re-confirmed, one genuinely new and independently mitigation-verified), 1 false
positive found and permanently fixed with a frozen regression case, 1 separate false-positive
mechanism identified and left honestly open rather than papered over. This is the same standard
applied to every property in this project: verify findings, verify the tool's own mistakes, fix
what can be fixed, and state plainly what's still open.
