# Policy note: when to spend a fresh held-out corpus on the emission-gap/delegation work

**Recommendation: keep closing gaps first; batch a single fresh confirmatory
measurement once this round of development work settles, rather than spending a new
corpus per incremental fix.**

## Why not now

1. **Matches this project's own established rhythm.** The original 4 capabilities
   (cap1-4) were built, frozen, and validated with synthetic controls + Magma dev
   evidence over many rounds *before* the one-time 258-site confirmatory run — never
   measured incrementally after each capability. The emission-gap fix, the V1/V2
   delegation correction, and the cap1 identity integration are the same kind of
   accumulating development batch; splitting them across separate confirmatory draws
   would be a real process regression, not extra rigor.

2. **Held-out data is a scarce, mostly-already-spent resource here.** SecVulEval full
   (25,440 rows, pooled to the 258-corpus) is already consumed as regression/development
   evidence for the emission-gap work (the 276-packet cache). PostCutoff-CVE, BigVul, and
   ARVO are already pooled into the same 258-site confirmatory corpus that's already been
   run once. There isn't an obvious untapped population sitting ready — sourcing a
   genuinely fresh, unseen corpus is its own real task (a later PostCutoff-CVE time
   slice if the dataset gets updated, a different vulnerability database entirely, or a
   hand-curated set like the old TChecker corpus rounds), not a formality.

3. **More changes are already queued** (the underflow-fed-length capability is still
   the biggest, most-corroborated item on the backlog; the `*_Resurrect` factory-allocator
   capability turned out to need a two-part build and isn't done either). Running a
   confirmatory pass now would still leave the *next* batch of changes needing another
   one — better to let the current round of development finish first.

## What would trigger doing it sooner

- If a stakeholder needs a real recall/generalization number specifically *because of*
  the emission-gap fix before other work lands (a genuine external deadline, not just
  curiosity) — in which case spend the draw on just that, documented as a partial
  measurement, same discipline as the original 258-corpus run's own protocol-deviation
  handling.
- If the backlog items (underflow capability, `*_Resurrect`) turn out to be
  substantially delayed or descoped — then "this round" effectively means "now."

## What sourcing a fresh corpus would actually require (scoped, not started)

1. Identify a population genuinely disjoint from everything already touched (258-corpus
   sites, the 276-packet dev cache, and the old TChecker corpus's ~13 hand-picked
   NSS/mozjpeg CVEs).
2. Apply the SAME frozen two-rule freeze process this project has used every time
   (`secvuleval_freeze.py`/`postcutoff_freeze.py`'s pattern: deterministic write-site
   mapping + structural family assignment, BEFORE any scanner output is examined).
3. Re-verify the 12-vulnerable-family gate against the new population specifically (the
   242-family pooled gate was met on the ALREADY-CONSUMED corpus; a fresh corpus starts
   its own gate count from zero).
4. Run once, archive raw, no post-result scanner changes — same protocol as
   `RUN_MANIFEST.json`'s existing attestation.

This is flagged as a real, multi-step undertaking on its own, not something to fold into
"finish the current dev batch first."
