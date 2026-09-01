# Review of task #34's 5 real R06 `VALUE_ACQUISITION_GUARD_MISSING` candidates

Direct instruction: "Review the five R06 GUARD_MISSING candidates. They are the smallest and
highest-signal population. Record exactly why applicability remains undetermined; node-libcurl
should remain a confirmed false positive."

All 5, real, from the 97-package replay (`results/replay_records.jsonl`):

| # | Package | Method | Source path | applicability_status | adjudication_status (before this review) |
|---|---|---|---|---|---|
| 1 | node-libcurl@5.1.2 | ReadFunction | src/Easy.cc | NOT_YET_DETERMINED | NOT_ADJUDICATED |
| 2 | pqclean@0.8.1 | Keypair | native/node_pqclean.cc | NOT_YET_DETERMINED | NOT_ADJUDICATED |
| 3 | pqclean@0.8.1 | Keypair | native/node_pqclean.cc | NOT_YET_DETERMINED | NOT_ADJUDICATED |
| 4 | pqclean@0.8.1 | DecryptKey | native/node_pqclean.cc | NOT_YET_DETERMINED | NOT_ADJUDICATED |
| 5 | pqclean@0.8.1 | DoSign | native/node_pqclean.cc | NOT_YET_DETERMINED | NOT_ADJUDICATED |

## 1. node-libcurl@5.1.2 -- ReadFunction: CONFIRMED FALSE POSITIVE (now recorded, not just known)

The exact same real site `study/resource_guard_r05/NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md`
documents in full -- R06 itself exists because of this finding. Two independent, compounding
real reasons (full account in that document): (1) `size`/`nmemb` are supplied by libcurl
internally, never by JS -- `ReadFunction` is a `curl_easy_setopt(CURLOPT_READFUNCTION, ...)`
callback, not a JS-reachable entry point; (2) a real, working guard already exists via a C++
`try`/`catch (Napi::Error)` around the allocation (exceptions ARE enabled for this build,
confirmed through the real node-addon-api 8.5.0 macro chain), just not the `.IsEmpty()`-shaped
pattern this pipeline's static contract-matching looks for.

**This adjudication was independently, thoroughly established months before this review -- but,
until `adjudication_registry.py` (this same work), NEVER RECORDED on the finding's own
`adjudication_status` field.** `grep` across the whole pipeline before this change confirmed:
no code path anywhere ever assigned `adjudication_status = "CONFIRMED_FALSE_POSITIVE"` for any
real finding -- task #41's own docstring already disclosed this exact gap ("no real, separate,
affirmative applicability step exists yet"). Fixed: `adjudication_registry.py`'s
`KNOWN_ADJUDICATIONS` now carries this exact site (matched on package_name + version +
method_name + source_path, never a pattern or a guess), applied after
`provenance.enrich_record()`, recomputing `reportable` through the veto immediately. `reportable`
was already `False` before this change (via the separate, still-real applicability gap below) --
it is now `False` for the RIGHT, additionally-recorded reason too, not merely an open
precondition that could someday resolve on its own.

## 2-5. pqclean@0.8.1 -- Keypair (x2), DecryptKey, DoSign: genuinely open, correctly so

These are NOT adjudicated, and should NOT be marked `CONFIRMED_FALSE_POSITIVE` by this review --
doing so without the same kind of real, individual, cited manual verification
`NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md` performed would be exactly the kind of guessed/pattern-
matched adjudication `adjudication_registry.py`'s own docstring explicitly refuses to do.

**Why `applicability_status` stays `NOT_YET_DETERMINED` (the real, disclosed reason, not a
scanner defect):** `provenance.finalize_reportability()` only ever *defaults*
`applicability_status` to `"NOT_YET_DETERMINED"` -- nothing in this pipeline, for ANY property,
ever affirmatively sets it to `"APPLICABLE"` for a real corpus finding (confirmed directly: the
one place `"APPLICABLE"` is ever assigned is `check_provenance.py`'s own SYNTHETIC test fixture,
never a real scanner run). This is the exact gap task #41's own docstring already named. It is
not specific to pqclean, and fixing it generally (building a real, separate affirmative-
applicability step) is out of this review's own scope -- these 4 candidates simply surface it on
real data for the first time in this replay.

**Why `adjudication_status` stays `NOT_ADJUDICATED`:** these 4 sites have never been manually
reviewed before this replay -- they are new, first-seen candidates, not a previously-established
finding whose adjudication was merely never recorded (node-libcurl's own case, above). What the
real evidence already shows, factually, without adjudicating it:

- All 4 share the same real structural shape: `traced_to_parameter: "this"`, `hops: 2`,
  `source_boundary: SOURCE_BOUNDARY_UNRESOLVED`, `attacker_controlled: false` -- R06's own
  source-boundary gate already correctly declines to claim attacker influence for any of them
  (the same real correction node-libcurl's own case motivated, applied generally here, not
  specific to pqclean).
- `parameter_type` is `KEM*` (Keypair x2, DecryptKey) or `Sign*` (DoSign) -- these are PQClean's
  own real, package-internal handle/context types, not a raw buffer or length parameter; this is
  consistent with (but does not, on its own, PROVE) the same real class of false positive as
  node-libcurl -- an internal object-identity parameter reached via `this`, not evidence of a
  JS-controlled destination-capacity value.
- All 4 sites are in the SAME file (`native/node_pqclean.cc`) -- a real, disclosed concentration
  signal (same package, same translation unit), not yet independently verified against the real
  pqclean source the way node-libcurl's own case was.

**Recommendation, not a decision made here:** these 4 are real candidates for a future,
individual manual review of the same rigor `NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md` performed --
confirm against the real pqclean@0.8.1 source whether an equivalent real guard exists (the same
two-part check: is `this` genuinely JS-uncontrolled, and does a real applicability-relevant guard
already exist under a shape this pipeline's static matching doesn't recognize). Left open,
honestly, rather than guessed at.

---
*No code in this pipeline was changed to accommodate pqclean's own case -- only node-libcurl's
own, already-established, independently-documented adjudication was newly recorded.*
