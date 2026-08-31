# Stratified manual review -- pre-registered sample (recorded BEFORE reading any source)

Recorded at 357/494 packages processed by the live R05 corpus scan (PID 6956), before this
review reads any real source code for any sampled item. Fixed seed: `20260831`.

## Bucket 1: positive findings (review ALL, not sampled)

Real corpus-wide count of `VALUE_ACQUISITION_GUARD_MISSING` findings across all 357
packages processed so far: **exactly 1** -- `node-libcurl@5.1.2`, `ReadFunction`,
`acquisition_call_id=30064773338`. No sampling needed; this is the entire population.
Already exhaustively investigated earlier this session (see
`study/resource_guard_r05/NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md`) -- restated in this
review's own findings doc for completeness, not re-derived from scratch.

## Bucket 2: SIZE_ATTACKER_INDEPENDENT

Real corpus-wide count: **exactly 1** contributing package -- `node-crc16@2.0.7`. No
sampling needed; this is the entire real population so far. Already investigated earlier
this session.

## Bucket 3: CONTRACT_NOT_APPLICABLE / BUILD_CONFIGURATION_CONFLICT / _UNRESOLVED

Real corpus-wide count under the LIVE R05 scan: **zero** for all three. Honest reason,
verified directly from the real classification counters above: only 2 of 357 packages ever
reach `R05_ACQUISITION_CALL_RECOVERED` at all (`node-libcurl`, `node-crc16`); of those,
`node-crc16`'s one recovered call is rejected earlier (`SIZE_ATTACKER_INDEPENDENT`, before
ever reaching the applicability gate), and `node-libcurl`'s one recovered call reaches the
applicability gate under the LIVE scan's OWN pre-fix build-config extraction (which
misclassifies it `disabled`, not `enabled` -- the confirmed real bug this whole R06 effort
exists to fix), so it becomes a real finding instead of a `CONTRACT_NOT_APPLICABLE`
abstention under R05. This bucket therefore has NO real corpus-wide population yet under R05
-- it only becomes populated once R06's build-config fix is actually run corpus-wide (the
post-freeze targeted rerun). The one real example available for review is `node-libcurl`
itself, obtained by re-running the FIXED R06 scanner (not the live corpus scan) against its
already-cached real facts -- disclosed as such, not presented as a live-corpus result.

## Bucket 4: acquisition/overload/type abstentions (R05_RECOVERY_RESULT_TYPE_UNRECOGNIZED)

Real corpus-wide count: 23,642 of 23,644 real `R05_RECOVERY_CANDIDATE`s (99.99%) rejected at
this one gate. Eligible pool for sampling: 229 real packages with >=1
`R05_RECOVERY_CANDIDATE`. `random.seed(20260831); random.sample(eligible, 5)` (Python
stdlib `random`, run once, this exact output recorded verbatim before any source was read):

```
fontnik@0.7.7                            (22 candidates, 22 rejected)
libpq@1.11.0                             (44 candidates, 11 recovery-eligible, 11 rejected)
@ipshipyard/node-datachannel@0.26.6      (333 candidates, 333 rejected)
node-libcurl@5.1.2                       (already covered under Bucket 1 -- kept in the
                                           sample as drawn, not resampled)
@ssxv/node-printer@1.1.1                 (46 candidates, 46 rejected)
```

Real, uninvestigated NEW packages for this bucket: `fontnik`, `libpq`,
`@ipshipyard/node-datachannel`, `@ssxv/node-printer`.

## Bucket 5: SOURCE_BOUNDARY_UNRESOLVED (R06-specific)

This is an R06-only concept -- the live corpus scan runs R05 (pre-fix), which has no
`source_boundary_evidence` field at all (only the old, buggy `attacker_influence_evidence`).
R06 has not been run corpus-wide. Honest limitation, disclosed rather than worked around:
the ONLY real instance currently available is `node-libcurl`'s own real R06 output (obtained
by manually re-running the fixed scanner against cached facts, same as Bucket 3). This is a
sample of ONE, not a stratified sample -- a genuine, larger sample of this bucket requires
the post-freeze R06 corpus-wide rerun, exactly as the standing instruction anticipates. No
attempt is made here to synthesize additional "real" instances to pad this bucket.

## What this review will NOT do

- Will not stop, restart, or otherwise touch the live R05 scan (PID 6956).
- Will not claim a larger sample size than what real corpus data currently supports for
  Buckets 3 and 5 -- both are honestly reported as small/single-instance pools, not padded.
- Will not implement further scanner code changes as part of this review; any real bug found
  is recorded for a LATER, separate fix, not fixed inline during the review itself.
