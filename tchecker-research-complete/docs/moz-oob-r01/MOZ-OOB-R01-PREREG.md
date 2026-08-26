# MOZ-OOB-R01 — pre-registered corpus (frozen R03, no detector changes)
# Selected BEFORE running TChecker. Recall effort = existing OOB read/write machinery.

## Corrections carried over
- Wording: "Mozilla taxonomy overlap appears LOW IN THE INITIAL SAMPLE" (not "the dominant
  blocker" — premature after a couple of searches).
- CVE-2015-7223 commit mapping corrected: canonical mozilla-central fix = 2948ba54950b;
  af47051962f8 was the Aurora BACKPORT. Kept ONLY as an explicit OUT-OF-TAXONOMY browser
  control (missing-principal/authorization bug -> no corresponding TChecker property).
  It must NOT be counted as a false negative for the supported classes.

## Pre-registered OOB pairs (Firefox/Gecko; class = OOB_READ / OOB_WRITE)
Each: CVE | bug | file:function | memory op | canonical fix | vulnerable parent | verify status

1. CVE-2026-0878 | bug 2003989 | dom/canvas/WebGLTexelConversions.cpp : mozilla::ConvertImage
   op: OOB_READ via `memcpy(dstItr, srcItr, bytesPerRow)` (fast-path row copy); source shared-mem
       mapping length not validated (EnsureMapped stopped enforcing len).
   fix: hg mozilla-central ce700a885a41  (github mozilla-firefox/firefox 1ba9d806f109)
   parent: ce700a885a41^   regressed_by: bug 1942129
   VERIFY: FULLY VERIFIED this turn (ASAN read-in-memcpy @ ConvertImage:483, code + root cause
           confirmed from Bugzilla; csectype-bounds, sec-high). BEST first run candidate for READ.

2. CVE-2015-2729 | bug 1122218 | dom/media/webaudio/AudioParam.cpp : AudioNodeInputValue
   op: OOB_READ, off-by-one when computing oscillator rendering range (READ of size 4).
   fix: hg mozilla-central c48d5ce78376   parent: c48d5ce78376^
   VERIFY: commit pinned from Bugzilla; manual diff read + parent hash still to confirm.

3. CVE-2026-0886 | bug 2005658 | gfx (GfxPatternToCairoPattern / sampling rects)
   op: OOB_READ, sampling rects not validated against data size.
   fix: hg mozilla-central e202bebf4f9e  (github 7e9a33f9e7d1)   parent: e202bebf4f9e^
   VERIFY: commit pinned from Bugzilla; affected function/file + manual diff still to confirm.

4. CVE-2018-5147 | bug 1446365 | media/libtremor/lib/ (tremor codebook decode) : OOB_WRITE
   [CORRECTED: CVE-2018-5146 is the libvorbis OOB write; 5147 is the libtremor port.]
   op: OOB_WRITE via a pointer write using a runtime `n` bound with Duff's-device loop control
       (ported from the libvorbis fix in bug 1446062). NOTE: "self-contained" = buildable/
       independently testable, NOT necessarily detectable: the frozen producer keys mainly on
       fixed extents + sizeof and may lack the runtime destination-capacity / loop-bound
       relationship, so ABSTENTION is a valid, informative outcome (localizes the missing layer).
   fix: hg mozilla-central d3ce388dd3c0d3c7be7df26d5d4de3a0e40c57f3  (sec-critical, csectype-bounds)
        uplifts: beta 0ae512558ada, release edcc87888148, esr52 5cd5586a2f48
   parent: first-parent of d3ce388d... (to pin once source is reachable)
   VERIFY: CVE/commit/class VERIFIED from Bugzilla bug 1446365 this turn. Exact parent hash + pre/
           post source retrieval BLOCKED in sandbox (see RETRIEVAL STATUS).

5. CVE-2014-1497 | bug 966311 | media (mozilla::WaveReader::DecodeAudioData)
   op: OOB_READ in WAV decode. fix: landed FF30 (attachment 8368842)  parent: TBD
   VERIFY: commit hash to pin; manual diff to confirm.

## Stage ledger to record per pair (vulnerable vs patched), frozen producers unchanged
  memory_facts_present? | capacity/bound_facts_present? | OOB candidate emitted (vuln)? |
  OOB candidate suppressed (patched)?
A MISS is evidence: it localizes the blocking layer (facts vs bound vs candidate vs build-context).

## Honest expectation (to be measured, not assumed)
Real Gecko files have unresolved includes/macros; without a compile_commands.json the OOB
producer may not see capacity/bound facts and will ABSTAIN. That abstention, recorded per stage,
IS the baseline result. #4 (self-contained vendored C) is the cleanest place to get a real
non-abstaining run first.

## Sequencing (unchanged from your plan)
Baseline MOZ-OOB-R01 (this corpus, frozen) -> THEN OOB-ADJ-R01 (wire OOB candidates to the
adjudicator/LLM packet, preserve CANDIDATE) -> THEN Gecko models (nsTArray/Span/alloc) ONLY where
the frozen corpus shows a concrete repeated miss, each with vuln/patched/safe controls.


## STATUS (CVE-2018-5147, per verification stage)
- CVE and canonical fix .......... VERIFIED (Bugzilla 1446365; fix d3ce388dd3c0...).
- Primary reviewed patch ......... ARCHIVED + HASH-VERIFIED in-sandbox (2251B / dd7bb27b...).
- Affected file & faulty ops ..... INDEPENDENTLY VERIFIED from the archived primary artifact
                                   (patch read in-sandbox). media/libtremor/lib/tremor_codebook.c,
                                   three functions; every hunk adds a MISSING RUNTIME OUTPUT BOUND:
                                     vorbis_book_decodev_add : j<book->dim -> i<n && j<book->dim  (a[i++])
                                     vorbis_book_decodevs_add: j<step     -> o+j<n && j<step      (a[o+j])
                                     vorbis_book_decodevv_add: i<offset+n -> m=offset+n; i<m       (a[chptr][i])
                                   Write index bounded only by codebook geometry, never by dest capacity n.
    In media/libtremor/lib/tremor_codebook.c the codebook-decode loops write past the
    destination using a runtime `n` bound. The fix ADDS the missing runtime bounds:
      for (j=0; i<n && j<book->dim;) a[i++] += t[j++] >> shift;   // `i<n` was ABSENT (the OOB write)
    and similarly adds `o+j<n` and `i<m` guards in the related decode loops.
    => dest `a` capacity is the RUNTIME `n`; OOB is a loop-carried write index `i` exceeding `n`,
       under Duff's-device control flow. (Not a sizeof/fixed-extent bound.)
- Exact vulnerable parent ........ PENDING retrieval (first-parent of d3ce388d).
- Pre/post source & build ........ BLOCKED pending parent/source retrieval.
- Frozen scan .................... NOT yet run.

## PRIMARY ARTIFACT (reviewed raw patch) — cryptographically pinned
- Bugzilla attachment 8959436 = the authoritative unified diff of media/libtremor/lib/tremor_codebook.c
- Canonical SHA-256: dd7bb27baef5e3aba10a662b363d48ccac723f933ebab59ad55d1c86fd41e2e8  (2,251 bytes)
  (retrieved and pinned out-of-sandbox; this is the authority for step 3.)
- IN THIS SANDBOX the artifact is NOT independently retrievable: bugzilla.mozilla.org is not on
  the bash egress allowlist (curl -> HTTP 403 "Host not in allowlist"), and the web fetcher is
  robots-blocked. So the byte-for-byte parent verification must run wherever bugzilla is reachable,
  or after the patch file is placed in the workspace. The 107-byte denial page was discarded
  (kept as egress-denial-evidence.txt), NOT treated as the patch.
- SYNC STATUS (this session): the file CVE-2018-5147-mozilla-reviewed.patch was reported as
  attached, but did NOT appear in /mnt/user-data/uploads (only the two original .zip uploads are
  present). Until it lands there, in-sandbox verify/archive cannot run. GitHub API core quota also
  observed at 0/60 (hourly reset pending), so the parent commits-by-path search is deferred.
- SYNC STATUS 2: expected transfer CVE-2018-5147-mozilla-reviewed-patch.zip (zip sha256
  d2e357050f64a3868e77f9b2c11469fbf8086bf06d4b36775d946ffca33e452d; inner patch 2251 bytes /
  dd7bb27b...) ALSO did not appear in /mnt/user-data/uploads. Workspaces are isolated; the file
  must be attached to THIS conversation to land in uploads. Nothing archived/verified in-sandbox yet.

## GROUNDED PREDICTION (to test, not asserted)
Because the destination capacity is a runtime `n` and the overflow is a loop-index-vs-n relation
under Duff's-device control flow, the frozen OOB_WRITE producer — which keys mainly on fixed
extents + sizeof — will likely lack a DEST_CAPACITY bound for `a` and ABSTAIN. If so, that is the
successful first result: it localizes the missing layer to runtime destination-capacity /
loop-bound reasoning, while the CVE/fix/faulty-op verification proves the harness is valid.

## RETRIEVAL ATTEMPTS (honest; all currently blocked for exact source)
- hg.mozilla.org rev / json-rev / raw-rev : ALL redirect to hg-edge JS bot-challenge.
- Bugzilla attachment.cgi (diff/raw)      : robots-disallowed for automated fetch.
- GitHub API                              : unauthenticated 60/hr limit exhausted.
- gecko-dev release tags                  : FIREFOX_58/60/61_0_RELEASE do not resolve via ls-remote.
NO source fabricated; NO scan run against reconstructed code.
Do NOT substitute FF58/61 tag trees (thousands of unrelated changes weaken vuln/patched delta).

## PATCH-REPRODUCTION FALLBACK (allowed, but currently also blocked)
Acceptable path: take a CRYPTOGRAPHICALLY-PINNED AUTHENTIC pre-fix tremor_codebook.c and apply
attachment 8959436, ONLY if it applies cleanly (zero offsets, no manual edits) -> that is patch
reproduction, not fabrication. BLOCKER: obtaining the authentic pre-fix FILE needs the same
retrieval channels (all blocked); a unified diff alone cannot reconstruct the full file. Upstream
xiph/tremor codebook.c is a DIFFERENT (renamed/possibly divergent) file, so the patch is not
guaranteed to apply cleanly and must not be assumed equivalent.

## LEDGER STATE (CVE-2018-5147)
- Primary patch ................. PRIMARY_PATCH_ARCHIVED_AND_HASH_VERIFIED
                                   corpus: primary-artifacts/CVE-2018-5147-mozilla-reviewed.patch
                                   2251 bytes, sha256 dd7bb27b... (ZIP d2e35705... both verified in-sandbox).
- Canonical hg revision ......... VERIFIED (d3ce388dd3c0...).
- Exact parent .................. PENDING.
- Authentic pre/post complete files ... PINNED (patch-reproduction, internally exact).
    VULN    = FIREFOX_58_0_RELEASE tremor_codebook.c  (10718 B, sha256 66a39749...)
    PATCHED = VULN + archived patch (applied clean, --fuzz=0, zero offsets; 10770 B, sha256 71b8a06e...)
    VULN->PATCHED delta = EXACTLY the 6 security hunks (o+j<n / i<n / m=offset+n,i<m); no other changes.
    CAVEAT: FF58 is authentic pre-fix at all 6 patched sites (proven by clean apply) but is NOT
    confirmed to be the exact parent d3ce388d^ (patched(FF58) vs FF61 differ by one cosmetic blank
    line). The vuln/patched PAIR is internally exact, which is what the scan comparison needs.
    Exact-parent pin remains PENDING (GitHub API commits-by-path / git-cinnabar).
- Frozen scan (R03, OOB_WRITE) .. RUN. RESULT BELOW.
- Local ASan ground truth ....... NOT run (bug triggerability externally confirmed: sec-critical
                                   CVE-2018-5147 with Mozilla ASan reports on the sibling bug
                                   1446062). A local ASan harness needs the full libtremor build +
                                   a crafted Ogg/Vorbis packet -> separate sub-project.
This is progress, not a failed row.

## PARENT RETRIEVAL PLAN (no user credential needed yet)
1. Do NOT request a GitHub token: the unauthenticated limit is temporary, and a token does not
   translate a Mercurial hash anyway.
2. After the GitHub rate limit resets, search mozilla/gecko-dev commit history by Bugzilla number
   1446062 (parent libvorbis bug) or the patch title -> obtain the Git commit for the libtremor
   landing -> its first parent = the vulnerable parent.
3. VERIFY that Git commit's tremor_codebook.c diff BYTE-FOR-BYTE against the preserved Bugzilla
   patch (sha256 dd7bb27b...). Only a clean match confirms the pair.
4. If history search fails, use git-cinnabar as the Mercurial->Git bridge to resolve d3ce388d
   and its first parent directly against mozilla-central (no GitHub tag guessing).
5. Only then: fetch authentic pre/post complete files -> build -> ASan ground truth
   (vuln triggers / patched clean) -> run frozen R03 -> record stage ledger
   (memory loc | dest capacity | reaching def | candidate/abstention | patched).
   Then CVE-2026-0878 as the first Gecko row. No model changes until both rows complete.
Do NOT substitute FF58/61 tag trees.


## ================= MOZ-OOB-R01 ROW 1 — RESULT (frozen R03, no model changes) =================
Pair (internally exact; delta = only the 6 security hunks):
  VULN    FF58 tremor_codebook.c        sha256 66a39749...  (10718 B)
  PATCHED FF58 + archived patch (clean) sha256 71b8a06e...  (10770 B)
  Patch applied --fuzz=0, zero offsets; archived patch sha256 dd7bb27b... (2251 B).

Stage-by-stage ledger (identical for VULN and PATCHED):
  source recognized? ............ YES  (c2cpg parsed 48 fns incl. vorbis_book_decodev_add /
                                        decodevs_add / decodevv_add — the three patched fns)
  memory locations .............. 0
  destination-capacity facts .... 0
  reaching-def / bound facts .... 0   (bound=0)
  OOB_WRITE candidate (vuln)? ... NO (abstains)
  patched suppressed? ........... N/A — abstains IDENTICALLY on patched (zero discrimination)

VERDICT: MISS (abstain, identical vuln/patched). The frozen OOB_WRITE producer does NOT detect
CVE-2018-5147.

BLOCKING LAYER (precisely localized): the OOB write is a compound-assignment INDEX write
`a[i++] += t[j++] >> shift` through a POINTER PARAMETER `a` whose capacity is the RUNTIME length
argument `n`. The frozen memory/capacity extractor models fixed local buffers + sizeof only, so it
emits no memory-location / destination-capacity / bound fact for a runtime-sized parameter array —
hence nothing to bound and no candidate. This is the missing layer to build next (OOB-ADJ-R01 comes
AFTER; models added only where the corpus shows a repeated concrete miss, each with controls).

HARNESS VALIDITY: confirmed. Authentic hash-pinned pre-fix source; patch applies clean; vuln/patched
delta is exactly the fix. A clean abstain here is a valid, informative first result — not a failure.
No implementation changes made (discipline held).


## ROW 1 — CORPUS VERIFICATION (against authoritative tremor_codebook.c source)
Per-function guard check confirms the pair:
  decodevs_add : VULN o+j<n=0  -> FIXED o+j<n=2     (patch added)
  decodev_add  : VULN i<n=0    -> FIXED i<n=2       (patch added)
  decodevv_add : VULN i<m=0    -> FIXED i<m=2       (patch added)
  decodev_set  : i<n=2 in BOTH  (ALWAYS guarded; NOT in the patch)  <- reconciles the earlier
                 FF58 grep count of 2 (it was decodev_set, never the vulnerable path).
Signatures confirm the blocking layer with certainty:
  vorbis_book_decodev_add(codebook*, ogg_int32_t *a, oggpack_buffer*, int n, int point)
  -> destination `a` is a caller-provided POINTER sized by the RUNTIME arg `n`
     ("dim granularity guarding is done in the upper layer"); no in-function extent for `a`,
     so a sizeof/fixed-buffer capacity extractor yields nothing -> memory_locations=0 / destcap=0.
Row 1 verdict (MISS/abstain, blocking layer = runtime-sized caller-pointer array writes) STANDS,
now corroborated by the authoritative source. No model changes (discipline held).

## ================= MOZ-OOB-R01 ROW 2 — RESULT (CVE-2026-0878, frozen R03) =================
Bug 2003989 / CVE-2026-0878, OOB READ, sec-high, csectype-bounds. EXACT parent pinned (API).
  fix commit  1ba9d806f109 (github mozilla-firefox/firefox) = hg ce700a885a41
  parent      17c5069730feada0
  fix touches ONLY gfx/layers/SourceSurfaceSharedData.cpp (+4/-0):
      + if (mBufHandle.Size() < aLength) { return false; }
  OOB READ site is in a DIFFERENT file/subsystem:
      dom/canvas/WebGLTexelConversions.cpp : ConvertImage  ->  memcpy(dstItr, srcItr, bytesPerRow)
  pinned: SSSD_VULN 317ff0e2  SSSD_FIXED fd43a390  WGTC(read-site) 31f6dc56

Stage ledger:
  SourceSurfaceSharedData.cpp (fix file)   VULN: memloc=12 bound=0 srccap=0 OOB_READ=0
                                           FIXED:memloc=12 bound=0 srccap=0 OOB_READ=0  -> NO discrimination
  WebGLTexelConversions.cpp (read site)    memloc=21 bound=0 srccap=0 OOB_READ=0 (abstain; identical vuln/patched)
  patched suppressed? .... N/A BY CONSTRUCTION: fix and read site are in DIFFERENT files, so a
                          per-file frozen scan cannot show suppression.

VERDICT: MISS (abstain). BLOCKING LAYER = INTERPROCEDURAL / CROSS-TU capacity flow: the read
extent (bytesPerRow) in ConvertImage cannot be tied to the source buffer's real capacity, which is
(un)validated in a different translation unit (SourceSurfaceSharedData::Init), many frames away.

## ================= ROW 1 vs ROW 2 — WHAT THE MISSES SHARE / DIFFER =================
Shared root: capacity is a RUNTIME value, never sizeof/fixed-extent -> both abstain because the
  frozen extractor models fixed local buffers + sizeof only. => runtime-capacity modeling is the
  common prerequisite gap.
Distinct:
  ROW 1 (libtremor OOB write): INTRA-function. dest capacity = runtime pointer-PARAMETER length n;
         write is a[i++]+= loop-index; needs runtime-capacity-on-param + loop-index bound reasoning.
  ROW 2 (WebGL OOB read): INTER-file. source capacity is validated in a DIFFERENT TU from the read;
         needs runtime-capacity PLUS interprocedural/cross-TU capacity propagation.
=> Implication for prioritization: runtime-capacity modeling is necessary for BOTH but sufficient
   for NEITHER. Row 2 strictly needs cross-TU flow on top. The two disclosed positives are
   heterogeneous -> do NOT over-invest in one narrow model expecting broad recall. This is the
   kind of evidence OOB-ADJ-R01 / model work must be gated on. No model changes made (discipline).


## ================= MOZ-OOB-R01 ROW 3 — RESULT (CVE-2022-28281, frozen R03) =================
POSITIVE CONTROL: fixed-size buffer + sizeof capacity (the shape the producer is built for).
Bug/mfsa2022-13, OOB WRITE, WinWebAuthnManager::Register, dom/webauthn/WinWebAuthnManager.cpp.
  fixed buffer:  WEBAUTHN_EXTENSION rgExtension[1] = {};              (line 175)
  OOB write:     rgExtension[cExtensions].pwszExtensionIdentifier = ...  (line 298), cExtensions++
  vuln bound:    only MOZ_ASSERT(cExtensions < sizeof(rgExtension)/sizeof(rgExtension[0]))  (debug-only)
  fix:           adds runtime `if (Extensions().Length() > sizeof-capacity) { abort; return; }`
  pinned: VULN FF98 ff20559c...  FIXED FF99 23ee6517...
  CAVEAT: FF98->FF99 for this file has TWO deltas — the CVE length-check AND an unrelated `zeroGuid`
          change in the GUID-handling region. The latter is analytically irrelevant to the rgExtension
          write; exact-parent isolation pending API reset. Result below is unaffected (see reason).

Stage ledger:  VULN  memloc=21 bound=0 destcap=0 OOB_WRITE=0
               FIXED memloc=21 bound=0 destcap=0 OOB_WRITE=0
VERDICT: MISS (abstain), IDENTICAL on vuln/patched. The producer does NOT fire even on its
designed-for fixed-buffer/sizeof shape here.

CONTROL (proves the machinery is NOT broken; run on isolated C):
  memcpy(buf[8], src, n)          -> destcap=8 (CPP_FIXED_ARRAY_CAPACITY, EXACT), 1 OOB_WRITE candidate
  memcpy(buf[8], src, sizeof buf) -> STATIC_EXTENT_SAFE, no candidate (correct suppression)
  int buf[1]; buf[i]=5            -> destcap=0, no candidate  (index store NOT modeled)
=> DETECTION SURFACE = memcpy/memmove length-vs-capacity ONLY. Array-index stores are not modeled.

## ================= 3-ROW SYNTHESIS (frozen R03; no model changes) =================
All three disclosed Mozilla OOBs MISS, for three now-precise reasons:
  ROW 1 libtremor  OOB write  a[i++]+=      -> ARRAY-INDEX store, not memcpy  -> out of surface
  ROW 3 WinWebAuthn OOB write rg[cnt].f=    -> ARRAY-INDEX store, not memcpy  -> out of surface
  ROW 2 WebGL      OOB read   memcpy(...)   -> IN surface, but capacity is CROSS-TU -> no srccap
The capacity extractor itself WORKS (fixed-array sizeof capacity proven by the control). The gaps,
ranked by corpus coverage:
  (1) ARRAY-INDEX-STORE modeling (indexed write vs the array's own capacity) — covers ROWS 1 & 3
      (2 of 3). Highest value. For Row 3 the capacity side is already derivable; only the write-site
      recognition (indexed store as a bounded write) is missing.
  (2) CROSS-TU capacity propagation for the memcpy surface — covers ROW 2.
Discipline held: frozen scanner throughout; NO analyzer changes. OOB-ADJ-R01 and any new model
(esp. array-index-store) are now evidence-gated by this baseline; each must ship with vuln/patched/
safe controls.


## ================= OOB-INDEX-R01 — first evidence-gated capability (Row 3 flip) =================
Built AFTER the frozen baseline (per discipline). NEW standalone producer (oob_index_write_verdict.py);
frozen analyzer + its 20+ gates UNCHANGED. Detects OOB writes via indexed stores into fixed-size
arrays `arr[idx]` (incl. arr[idx].field); count N read syntactically so OPAQUE element types work.

Control matrix (gate_oob_index_r01.py = 6/6):
  Row 3 CVE-2022-28281  VULN -> CANDIDATE   FIXED -> suppressed     (positive control FLIPS MISS->CANDIDATE)
  controls              bad_unbounded FLAG; safe_loop/safe_const/guarded SUPPRESS
  Row 1 (pointer-param) no FP;   Row 2 (memcpy read) no FP
Suppression is sound on the matrix: const-in-bounds, OR a direct non-assert `idx < K` bound, OR a
non-assert sizeof(arr) capacity guard. Assert-family comparisons excluded (compiled out). Per-fn
scoping via enclosing_function_id. Emits CANDIDATE only.

Honest limits (recall traded for precision, field-read-revert discipline): rule (a) suppresses on
ANY `idx < K` even if K>N (loop-bound-exceeds-capacity is a FALSE NEGATIVE); guard analysis is
intraprocedural/heuristic, not dominator-based. Row 1 (runtime pointer-param capacity) and Row 2
(cross-TU capacity) are NOT addressed and remain separate gaps.

Corpus outcome after this addition: Row 3 detected (vuln) + suppressed (patched); Rows 1 & 2 still
honest MISSES with their distinct blocking layers documented. Next (still evidence-gated):
OOB-ADJ-R01 (wire CANDIDATE -> adjudicator/LLM packet, preserve CANDIDATE).

## ================= OOB-ADJ-R01 — OOB candidates now reach the review pipeline =================
The OOB index-store CANDIDATE (OOB-INDEX-R01) is now staged into the shared tchecker-llm-packet/1.0
pipeline via adjudicator/adjudicate_oob.py + property_configs/oob_index_write.json — the same schema
and SAFE|UNSAFE|UNKNOWN advisory contract the JS classes use. Gate OOB_ADJ_R01=10/10.
Row 3 CVE-2022-28281: VULN -> 1 review packet (candidate_class OOB_WRITE preserved; deterministic
UNKNOWN; QUESTION asks whether cExtensions stays < 1 on all paths; never asserts VULNERABLE);
FIXED -> 0 packets; a HIGH-confidence SAFE hint resolves the candidate without a packet.
End-to-end for Row 3 now: producer detects (VULN) / suppresses (patched) -> adjudicator emits a
review packet preserving CANDIDATE. Rows 1 & 2 remain honest MISSES (distinct blocking layers).
Discipline held: frozen analyzer + 20+ gates UNCHANGED; no VULNERABLE upgrade anywhere.


## ============ CANONICAL END-TO-END VERIFIED (scan_repo public entry point) ============
Run from CLEAN dirs via the public command only (no manual intermediate scripts, no file moving):
  scan_repo.py <vuln_dir>    -> side.oob_review.packets == 1  (packet: OOB_WRITE / UNKNOWN / no VULNERABLE)
  scan_repo.py <patched_dir> -> side.oob_review.packets == 0
TRUSTED-HINT RULE (verified): a SAFE hint suppresses ONLY from a trusted source
(CURATED_ATTESTATION/HUMAN_REVIEW) at HIGH confidence. A model-generated (source=LLM) or unsourced
SAFE is ADVISORY ONLY and does NOT erase the deterministic candidate:
  source=LLM SAFE/HIGH  -> packets=1, CANDIDATE_OPEN (ADVISORY_ONLY_UNTRUSTED_SOURCE)
  source=CURATED SAFE/HIGH -> packets=0, RESOLVED_SAFE_BY_ACCEPTED_HINT
Gates: OOB_INDEX_R01=6/6, OOB_ADJ_R01=14/14. Frozen analyzer + 20+ gates UNCHANGED.

STATUS (accurate): an END-TO-END OOB candidate-to-review-packet pipeline through TChecker's CANONICAL
interface (NOT yet a full semantic-review pipeline: that requires a reviewer to consume the packet
and return an advisory result through the same interface), for the fixed-array index-store class. Detect (vuln) / suppress (patched) ->
auto-stage a CANDIDATE review packet; LLM answers remain advisory (cannot change the deterministic
verdict). Rows 1 & 2 remain honest MISSES with distinct blocking layers; those gaps stay
evidence-gated. Firefox-scale still needs a real compile_commands.json (mach build).


## ================= OOB-ADJ-R02 — channel-based trust + operational controls =================
Trust is established by the INGESTION CHANNEL, not by any 'source' field inside a hint.
HINT-LOADING PATH: scan_repo (--oob-hints=advisory/UNTRUSTED, --oob-trusted-attestations=TRUSTED)
 -> load_channels() strips & overwrites any self-declared source; tags UNTRUSTED_CHANNEL vs
    CURATED_ATTESTATION_CHANNEL -> disposition() trusts ONLY trusted-channel membership.
Controls (hermetic OOB_ADJ_R01=12/12 + canonical scan_repo C1-C4):
  - forged source=CURATED via --oob-hints -> stays advisory (packet emitted)   [label != proof]
  - trusted channel SAFE/HIGH -> suppresses
  - output-dir reuse: vuln then patched -> no stale packet (1 then 0)
  - producer/adjudicator fault -> NONZERO scan exit (never silent packets=0)
WORDING (accurate): this is an end-to-end candidate-to-review-packet pipeline through the canonical
interface. It becomes an end-to-end SEMANTIC-REVIEW pipeline only when a reviewer actually consumes
the packet and returns an advisory result through that same interface. Analyzer frozen throughout.


## ================= OOB-ADJ-R03 — candidate-binding audit (attestation applies to ONE candidate) =
Old pid was ordinal only ("oob-index-{i}") -> a stale SAFE could suppress changed code. FIXED:
property_id = "oob-index:{fingerprint}.index_within_capacity", fingerprint = sha256 over
{analyzer_version, repo_rev, file, candidate_class, subclass, array, elem_count, index_expr, line}.
A trusted attestation is keyed by this fingerprint and binds to the EXACT reviewed candidate.
Hermetic OOB_ADJ_R03=15/15 + canonical scan_repo C1-C4:
  matching fingerprint suppresses; changed repo_rev/file/index/capacity/location/analyzer re-fingerprint
  and invalidate the stale attestation (packet re-emitted); ambiguous duplicate fingerprints never
  suppress; declared-fact mismatch rejected; scan_repo computes+forwards repo_rev and clears a prior
  report at start so an adjudicator fault after success leaves NO stale-current report.
Analyzer frozen throughout. With R03 passing, the appropriate next frontier is connecting an actual
reviewer that consumes the packet and returns an advisory result through the same interface (only
that step upgrades this from a candidate-to-review-packet pipeline to a semantic-review pipeline).


## ========= OOB-ADJ-R04 — identity is DERIVED by trusted runtime, not caller labels =========
R03 fingerprint used a commit-id repo_rev + caller-passable file_name/analyzer string (a
source:CURATED-style hole). FIXED: the fingerprint now binds (a) content_sha256 = full SHA-256 of
the ACTUAL scanned bytes (working tree; covers uncommitted/untracked/dirty edits) computed by
scan_repo from the exact bytes fed to the frontend; (b) analyzer_identity = full SHA-256 over
component files (producer+adjudicator+config+frontend normalizer+exporter); plus function identity
and source span. Full 64-hex sha-256; explicit canonical JSON. Unverified content -> FAIL CLOSED.
No CLI/packet/hint field can select analyzer/content/repo identity; suppression recomputes the
fingerprint from producer facts (never echoes a packet fingerprint).
Gate OOB_ADJ_R04=20/20 + canonical C1-C3: dirty-worktree edit with IDENTICAL candidate fields
(line/array/index) but changed bytes re-fingerprints and invalidates a stale attestation; a
commit-id anchor would have wrongly suppressed. Analyzer frozen throughout.
OOB gate suite: OOB_INDEX_R01=6/6, OOB_ADJ_R01=10/10, OOB_ADJ_R03=5/5, OOB_ADJ_R04=20/20.
