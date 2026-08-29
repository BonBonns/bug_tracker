# Bounded pilot — mozilla/nss + mozilla/mozjpeg (exploratory, not held-out)

> **CORRECTION (post-publication, see "Capability-count correction" below): this pilot
> ran Capability 1, BOTH Capability-2 models, and Capability 3 — NOT "capabilities 1-4".
> Capability 4 (`cap_decoder_contract.py`) does not exist at the pinned base commit
> `8b77705` at all; it was introduced later on the same branch. The "capabilities 1-4"
> line below is the original (wrong) label, struck through rather than silently edited —
> see the correction section for the verification and the honest relabeling.**

Ran the FROZEN scanner-v2 producers — base v1/v2 write-capacity comparison + ~~capabilities
1-4 (`cap_addr_indexed`, `cap_wrapper_summary`, `cap_member_pointer_walk`,
`cap_counted_loop_writer`)~~ **[WRONG, see correction] Capability 1
(`cap_addr_indexed`), both Capability-2 models (`cap_wrapper_summary`,
`cap_counted_loop_writer`), and Capability 3 (`cap_member_pointer_walk`)** —
**unmodified**, imported read-only from the definitive branch
(`claude/previous-conversation-context-6gr99h` @ `8b77705`), against current heads of two
Mozilla C/C++ projects. This is vulnerability-discovery/portability work, run alongside
Capability 4 development; it does **not** touch, extend, or reference the frozen held-out
corpus (258 vulnerable sites / 42 families) and makes no accuracy/generalization claim. No
CVE list was consulted to select or promote any finding below — every candidate the
producers emitted on the scanned scope is reported.

## Toolchain

- joern-cli / c2cpg **v4.0.608** (`/tmp/joern-cli`) — same pin as `TOOLCHAIN_FROZEN.md` on
  the definitive branch.
- Frontend: `export_c_cpp_facts_v03.sc` → `normalize_c_cpp_facts_v03.py` (both read
  unmodified from `tchecker-research-complete/.../tests/gates/cpp-r06/frontend/`).
- Driver: `run_moz_scan.py` (this repo, `moz-exploratory-scan/commands/`) — imports the
  five producer modules and calls their public `analyze_*` entry points as-is; it changes
  no producer/capability/rule/route. It adds only reporting glue: a disposition→bucket
  classifier built from each producer's *own* existing vocabulary (`disposition`/`route`
  for cap1-4 and v2-refined records; `analysis_status`/`reason_code`/`uncertainty_bucket`
  for v1-passthrough records), and a best-effort `(file, function, line, dest)` identity
  string per finding (see caveat below).

## Scope pinning

| Repo | URL | Pinned commit | Clone |
|---|---|---|---|
| mozilla/nss | github.com/mozilla/nss | `7b5f00bfd3835fee76be428c55e60cdb3366182c` | `--depth 1` |
| mozilla/mozjpeg | github.com/mozilla/mozjpeg | `08265790774cd0714832c9e675522acbe5581437` | `--depth 1` |

Each pinned twice — `git ls-remote <url> HEAD` before cloning, `git rev-parse HEAD` after —
and the two agree in both cases (see `sources_pin/*.md`).

## Bounded pilot (this round)

- **mozjpeg — full source tree, minus `jchuff.c`.** `jchuff.c` was excluded from the
  c2cpg source scan (`--exclude jchuff.c`), not silently dropped after the fact: its
  Huffman encoder body is the same heavily macro-unrolled function documented in
  `moz-scan-paired-cve-validation-round1.md` round 2 (`encode_one_block`, ~50k CPG nodes
  after macro expansion). Re-encountered here as a **normalize-time cost blowup**, not a
  parse failure this time — the earlier session's fix was a capacity-constant-folding
  evaluator in the TChecker producers, which this scanner-v2 pipeline does not share;
  `normalize_c_cpp_facts_v03.py`'s reachdef pass on that one function grew unbounded
  (>4GB RSS and climbing before being killed at the 240s mark). **This is a real, reproduced
  scanner-v2 coverage/performance gap on macro-heavy real code, recorded here, not patched**
  (patching it now would be tuning the scanner on a file this same session is about to
  scan with it — exactly the training-on-test problem the definitive branch's own rules
  forbid). Every other file in the tree parsed and normalized cleanly (build-configured via
  `cmake -B build_cfg`, no full compile needed — c2cpg only needs the generated headers).
- **nss — `lib/freebl/` only** (123 `.c` files: the crypto-primitive tree; matches the area
  prior sessions' `/tmp/nss-crypto-scan` work also found tractable). `--include`d
  `lib/util`, `lib/freebl/mpi`, `lib/freebl/ecl` for header resolution via
  `--with-include-auto-discovery`; no NSPR/build.sh build was run (parse-only, not link).
  The rest of `nss/lib/` (ssl, softoken, pk11wrap, …) is **not yet scanned** — see
  "Scoping the complete feasible source scope" below.

## Results

| Target | Candidates | DETERMINISTIC | OPEN_RELATIONSHIP | MISSING_EVIDENCE | UNSUPPORTED_REPRESENTATION |
|---|---:|---:|---:|---:|---:|
| mozjpeg (tree − jchuff.c) | 118 | 28 | 1 | 88 | 1 |
| nss/lib/freebl (pilot) | 352 | 16 | 92 | 236 | 8 |

**Bucket definitions** (from the producers' own output, not a new scoring scheme):
- `DETERMINISTIC` — `disposition ∈ {deterministic_complete, proven_oversized}` (or the v1
  passthrough equivalent `analysis_status == deterministic_complete`): the write-length/
  count vs. destination-capacity relationship **is** established — safe or provably
  oversized, either way decided.
- `OPEN_RELATIONSHIP` — `relationship_unresolved` / `capacity_relation_not_established`
  (routes `range_arithmetic_review`, `semantic_relationship_review`): capacity is bound,
  but the length/count expression's relationship to it is not.
- `MISSING_EVIDENCE` — `additional_evidence_required` / `required_evidence_absent`:
  capacity itself (base array, allocation extent, or destination identity) is not bound.
- `UNSUPPORTED_REPRESENTATION` — the producer recognized a write-shaped call at all, but
  the specific representation defeats it structurally: `unknown_allocator_contract`
  (`sizeof`-driven heap size whose semantics aren't modeled) or cap3's
  `binding=mismatch/unavailable` (structural for-loop proof unavailable for that write).

By producer (candidate counts) — **corrected labels; see "Capability-count correction"
below for how the original version of this table mislabeled the last row as "cap4"**:

| Producer | Real capability | mozjpeg | nss/freebl |
|---|---|---:|---:|
| base_v1v2 (frozen v1 + stack-capacity v2) | frozen cursor producer (pre-numbering) | 19 | 287 |
| cap1 — `&(base[index])` | **1** | 0 | 12 |
| cap2a — transparent wrapper summaries | **2** (delegation-wrapper model) | 31 | 27 |
| cap3 — advancing-pointer struct-member walks | **3** | 68 | 17 |
| cap2b — counted-loop writers | **2** (counted-writer/loop model — NOT capability 4) | 0 | 9 |

## What the DETERMINISTIC findings actually are (sanity check, not promotion)

- **mozjpeg, all 28**: `GETENV_S` (a `strncpy`-based env-var read wrapper, resolved via
  cap2's interprocedural wrapper summary) into fixed 2- and 30-byte local buffers in
  `init_simd`/`main`/`jinit_memory_mgr` — length is a literal ≤ the destination capacity in
  every case. Correctly decided safe; not a candidate for anything.
- **nss/freebl, 16**: a mix of `s_mp_mul_comba_{4,8,16,32}` (bignum multiply into a
  fixed-size local limb array, count matches array size), several EC `sign_digest`/
  `verify_digest` functions writing a fixed-width digest/signature into a
  correctly-sized local buffer, and `eme_oaep_decode`/`camellia_setup192`/`fe_frombytes`
  — same shape. All read as genuinely safe on inspection; none flagged oversized in this
  pilot. (A `proven_oversized` finding would be the interesting case to hand-verify next;
  none occurred here.)

## OPEN_RELATIONSHIP — where a human/LLM review would actually add value

nss/freebl's 92 open-relationship candidates are dominated by `capacity_relation_not_established`
on real cryptographic buffer writes where the *destination* is bound (a local/stack array of
known size) but the *length expression* is symbolic — e.g. `AESKeyWrap_Winv` writing
`outLen` bytes into `output`, `AESKeyWrap_EncryptKWP` writing `inputLen` bytes into `newBuf`,
`blake2b_Compress` writing `BLAKE2B_BLOCK_LENGTH` bytes into a 16-`uint64_t` array (length
expression's relationship to the byte-vs-element unit isn't simplified). These are exactly
the class the producers are designed to flag and hand off (`llm_eligible: true` on all of
them) rather than resolve themselves — not evidence of a bug, evidence of "worth a closer
look," consistent with the frozen scanner's own posture everywhere else it's been run.

## MISSING_EVIDENCE / UNSUPPORTED_REPRESENTATION — coverage gaps, not findings

- `unknown_allocator_contract` (1 mozjpeg, 8 nss) — heap-context-resurrect functions
  (`BLAKE2B_Resurrect`, `MD2_Resurrect`, `MD5_Resurrect`, `SHA256_Resurrect`,
  `SHA512_Resurrect`, …) writing `sizeof(*ctx)`/`sizeof(ContextType)` bytes into a
  pointer whose allocation-site semantics the producers don't model. Same shape as the
  `unknown_allocator_contract` gap the definitive branch's own capability-plan docs
  already track (heap capacity from an allocator whose contract isn't in the frozen list).
  Nothing new; corroborates a documented gap on different real functions.
- cap3's 68 mozjpeg / 17 nss `MISSING_EVIDENCE` findings are dominated by
  `cursor_advance_ambiguous` / `cursor_advance_non_unit` / `destination_identity_ambiguous`
  / `cursor_trajectory_reset` — real advancing-pointer struct-member writes cap3
  recognized the *shape* of but where the structural for-loop proof (or the cursor's
  advance-by-exactly-one-element property) doesn't hold cleanly on the real code's control
  flow. Recorded as coverage data for cap3's own future tightening, not acted on here.

## Caveats on this report's own tooling (not the frozen scanner's)

- **`file` attribution is a best-effort name join**, not the frozen `physical_write_identity`
  (which resolves through the CPG's declaration-reference edges). A function name that
  collides across files in the same translation unit set (common for `static` helpers
  with generic names, or per-arch variants like `init_simd`) is reported as
  `AMBIGUOUS(name-collision:N files)` rather than guessed — this hit **7** mozjpeg findings
  and **~15%** of the nss set. `physical_write_identity_simplified` in each finding record
  is `file|function|line|dest_expr`, explicitly labeled non-authoritative in the driver's
  own docstring; cap2/cap4's own `underlying_write` field (present on their records) *is*
  the frozen WSD identity and should be preferred wherever it's populated.
- Full findings (all 470 candidates, every field) are in
  `raw_outputs/{mozjpeg,nss_freebl}.moz_scan_findings.json` (not duplicated in this report).

## Scoping the complete feasible source scope (decision needed before spending more compute)

- **mozjpeg**: this pilot **is** effectively the complete feasible scope for the current
  source tree (one file excluded and documented above; everything else parsed). No further
  mozjpeg scanning is planned unless `jchuff.c` gets a bespoke exclusion-narrowed pass
  (e.g. c2cpg `--exclude-regex` down to just `encode_one_block`, scanning the rest of that
  one file) — cheap, but low value: it's exactly the pointer-increment write shape already
  documented as out of scope for this producer set.
- **nss**: `lib/freebl/` (this pilot) is **one of 20 top-level `lib/` modules**. Two paths
  to widen it:
  1. **Header-only, include-auto-discovery** (what this pilot used) — cheap (~30s c2cpg,
     ~2min normalize per module at freebl's size) but only as reliable as each module's
     headers being locally resolvable; freebl worked because its dependencies (`util`,
     `mpi`, `ecl`) are sibling directories. `ssl`/`pk11wrap`/`softoken` pull NSPR types
     (`PRFileDesc`, `PRLock`, …) that aren't in the source tree at all — this path would
     need NSPR's public headers only (not a full NSPR build) added as an `--include`.
  2. **Full build via `build.sh`** (NSPR checkout + gyp/ninja) — this is what a prior
     session's `/tmp/nss-crypto-scan`/`/tmp/nss-ssl-scan` artifacts (dated Aug 26-27,
     found on disk, not reused here — this pilot re-clones and re-pins fresh per the
     "pin each repository commit" requirement) appear to have done, given a real
     77MB `cpp.json` with resolved facts across `src/` including `ssl`. Slower to set
     up, but the only reliable path to `ssl`/`softoken`/`pk11wrap`.
- **Recommendation**: path 1 (NSPR public headers via `--include`, no build) probably
  reaches most of the remaining `lib/` modules cheaply; `ssl` and `softoken` are the two
  most real-world-relevant modules not yet covered given NSS's known bug history
  (`pk11wrap`, `softoken` came up repeatedly in the old TChecker NSS corpus). Not started
  this round — flagging for the next one rather than silently expanding scope without
  reporting back first, per "run a bounded pilot first, then the complete feasible source
  scope" as two explicit, separately-reportable steps.

---

## Capability-count correction (reconciliation, not a rewrite)

The original version of this report labeled the run "capabilities 1-4." That was wrong.
Caught externally, verified here against the git object graph and the modules' own
docstrings/frozen boundary doc rather than taken on trust — including re-running the
whole pilot from a **second, independent, freshly-created worktree pinned at `8b77705`**
with `PYTHONPATH` cleared (`env -i`), to positively rule out module contamination as the
cause rather than merely assert it wasn't the cause.

### What was actually wrong

`run_moz_scan.py` (v1, `commands/`) assumed a numbering from the four `cap_*.py`
filenames it found (`cap_addr_indexed`, `cap_wrapper_summary`, `cap_member_pointer_walk`,
`cap_counted_loop_writer`) and labeled them capability 1/2/3/4 by file-listing order. It
never checked the modules' own docstrings or the frozen boundary doc. The real mapping,
per each module's own `"""Capability N — ..."""` docstring and
`CAP2_CAP3_BOUNDARY_FROZEN.md` (frozen *before* capability 3 began):

| File | Docstring says | Real capability |
|---|---|---|
| `cap_addr_indexed.py` | `Capability 1 — address-of indexed destination` | **1** |
| `cap_wrapper_summary.py` | `Capability 2 — transparent wrapper summaries` | **2** (delegation-wrapper model) |
| `cap_counted_loop_writer.py` | *(no capability number in its own docstring)* | **2** (counted-writer/loop model — the SECOND of "two models, both cap2" per `CAP2_CAP3_BOUNDARY_FROZEN.md`, introduced by commit `f71fac0` "Split cap2 into two distinct proof models") |
| `cap_member_pointer_walk.py` | `Capability 3 -- advancing-pointer STRUCT-MEMBER writes` | **3** |
| `cap_decoder_contract.py` | `Capability 4 -- EXTERNAL DECODER CONTRACTS` | **4 — introduced at commit `111b653`/`6eb1f42`, both STRICTLY AFTER `8b77705`. Confirmed absent from the pinned base commit; never imported or run by this pilot.** |

So: this pilot ran capability 1, both capability-2 models, and capability 3. It did not
and could not have run capability 4 — the file didn't exist yet in the checkout it was
built from. Every one of the requested checks below confirms this is (1) a labeling
mistake on this driver's part, not (2) an untracked file, and not (3) a PYTHONPATH import
mixup.

### Verification (run against the real branch state, not asserted)

```
$ git rev-parse HEAD                                    # the exploratory branch tip
2f6668e98980381511991be3ddd29d4d118e0582
$ git status --short                                     # clean
$ git fetch origin claude/previous-conversation-context-6gr99h
   8b77705..6eb1f42  claude/previous-conversation-context-6gr99h -> origin/...
$ git merge-base --is-ancestor 8b77705 6eb1f42c08b5025f1342901956d6410c207efdd3 && echo YES
YES        # confirms 6eb1f42 (real cap4) is a STRICT DESCENDANT of 8b77705 (this pilot's base)
$ git ls-tree -r 8b77705 --name-only | grep cap_decoder_contract
           # (no output) -- NOT PRESENT at the commit this pilot actually built from
$ git ls-tree -r 6eb1f42 --name-only | grep cap_decoder_contract
semantic-bucket-pilot/scanner-v2/cap_decoder_contract.py
semantic-bucket-pilot/scanner-v2/cap_decoder_contract_test.py
$ git ls-tree -r 8b77705 --name-only | grep cap_counted_loop_writer
semantic-bucket-pilot/scanner-v2/cap_counted_loop_writer.py     # genuinely tracked at 8b77705,
semantic-bucket-pilot/scanner-v2/cap_counted_loop_writer_test.py # not a stray/untracked file
```

### Module provenance (captured from the running process, not asserted)

Re-ran both targets from a **second, brand-new worktree** (`git worktree add
/tmp/clean-repro 8b77705 --detach`, never touched by the original run) with `env -i`
(clears `PYTHONPATH` and every other inherited env var) and `SCANNER_DIR` pointed
explicitly at that fresh worktree. `run_moz_scan_v2.py` records each producer module's
live `__file__` + SHA-256 at call time:

| module | resolved path | sha256 | under `SCANNER_DIR`? |
|---|---|---|---|
| base_v1v2 | `oob_runtime_capacity_v2.py` | `b1867edf...9dfbef` | yes |
| cap1_addr_indexed | `cap_addr_indexed.py` | `6885e589...0e29a6` | yes |
| cap2a_wrapper_summary | `cap_wrapper_summary.py` | `2f67bdd9...2fca3493` | yes |
| cap2b_counted_loop_writer | `cap_counted_loop_writer.py` | `d67b03ce...926200fb` | yes |
| cap3_member_pointer_walk | `cap_member_pointer_walk.py` | `32588e58...585747714` | yes |
| cap_write_site_dedup | `cap_write_site_dedup.py` | `85ef6ff5...4970ee44` | yes |

Every module resolved inside the fresh worktree's own `scanner-v2/` directory — none
shadowed from elsewhere on the path. Rules out scenario 3 (PYTHONPATH contamination)
directly, not by assertion. Full hashes and paths: `raw_outputs/module_provenance.json`.

### Totals reproduced exactly, from the clean worktree

| Target | v1 total (original) | v2 total (clean worktree, PYTHONPATH cleared) |
|---|---:|---:|
| mozjpeg | 118 | **118** |
| nss/freebl | 352 | **352** |

Identical counts confirm this was purely a labeling error (scenario 1), not contamination
or double-counting — the same records, correctly attributed, from an independently
rebuilt environment.

### Raw producer records vs. deduplicated physical-write operations

The v1 totals (118 / 352) are **raw producer records — one row per producer's own
finding, not deduplicated across producers.** The frozen codebase provides a real
cross-producer physical-write identity + precedence dedup
(`cap_write_site_dedup.dedup()`, precedence `cursor_producer > direct(cap3) >
call_site_summary(cap2)`), but **only two of the five producers here actually carry that
identity**: cap2's two models (via `underlying_write`) and cap3 (each per-walk record's
`member_writes` list is individually a `WSD.physical_write_identity()` result, flattened
here into one pseudo-record per constituent write — the identity cap3's own analysis
already computed, not re-derived). **Capability 1 and the base v1/v2 cursor producer
carry no WSD identity anywhere in the frozen codebase** (cap1 never imports
`cap_write_site_dedup`; the base producer predates it) — deduplicating them here would
mean inventing an identity scheme for a frozen producer, which this driver must not do.
They are reported as raw counts only, explicitly flagged as not deduplicated, rather than
silently folded into a combined "unique operations" number that would misrepresent them
as covered by the same guarantee.

| Target | cap2a+cap2b+cap3 raw records | verifiable | unverifiable (never merged) | **unique physical-write operations** | cap1 (not dedup-integrated) | base_v1v2 (not dedup-integrated) |
|---|---:|---:|---:|---:|---:|---:|
| mozjpeg | 323 | 284 | 39 | **272** | 0 | 19 |
| nss/freebl | 71 | 70 | 1 | **49** | 12 | 287 |

(mozjpeg's 323 in-scope raw records is larger than cap2a+cap3's 31+68=99 top-level
records because cap3's 68 per-walk records aggregate multiple member writes each — 292
individual writes flatten out of those 68 walks, plus cap2a's 31, minus 0 from cap2b.)

Full deduplicated operation lists: `raw_outputs/{mozjpeg,nss_freebl}_v2_findings.json`
(`deduped_operations` key).

### Report-branch verification

Re-checked from a fresh `git fetch` (not the cached worktree state) that
`moz-exploratory-scan/` is present on `origin/claude/moz-scan-exploratory` and correctly
**absent** from `origin/claude/how-claude-code-works-j9lpw0`:

```
$ git ls-tree -r origin/claude/how-claude-code-works-j9lpw0 --name-only | grep moz-exploratory-scan
           # (no output) -- correctly absent
$ git ls-tree -r origin/claude/moz-scan-exploratory --name-only | grep moz-exploratory-scan
moz-exploratory-scan/README.md
moz-exploratory-scan/... (all 12 files)
```

This report and all archived artifacts are only ever on `claude/moz-scan-exploratory`.
No link or reference to `claude/how-claude-code-works-j9lpw0` for this content was found
anywhere in this session's own output; if a specific broken link is meant, it wasn't
reproducible from git state and would need to be pointed out directly.
