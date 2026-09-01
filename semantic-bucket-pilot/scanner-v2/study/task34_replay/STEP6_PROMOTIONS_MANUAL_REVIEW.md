# Manual review: the 13 real findings newly promoted by roadmap step 6's reachability tiers

Per the SAME precedent as `TRANSITIVE_PROMOTIONS_MANUAL_REVIEW.md` ("the next highest-value
review population is the... promotions... manually validate those candidates first"),
`rerun_aggregator_step6.py`'s own real rerun (`TIER_CALLBACK_OR_WORKER_PROVEN`/`TIER_MODULE_
LOAD_EXECUTION_PROVEN` newly wired into `staged_enablement.py`'s allowlist) newly promoted 13
real findings to `reportable=True` across 6 distinct real function-level sites (2
`lock_balance_findings`, 4 `oob_write_candidates`, 7 `oob_index_write_candidates`). Reviewed with
the same rigor as `NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md`/`TRANSITIVE_PROMOTIONS_MANUAL_REVIEW
.md`/`NODE_SNAP7_NAN_MANUAL_REVIEW.md` -- every real published tarball fetched directly from the
npm registry, hash-verified against its own real `shasum`, and read directly.

**Verdict: all 13 are FALSE POSITIVES**, across two real, distinct root causes.

## 1-2. `ggml_graph_compute_secondary_thread` (`@fugood/whisper.node@1.1.3`, `smart-whisper@0.8.1`) -- 2 `lock_balance_findings`

Both packages independently vendor `ggml` (whisper.cpp's own dependency); the flagged function
is byte-for-byte the same real shape in both (`ggml-cpu.c:3206` / `ggml.c`'s own copy). Real
source (`ggml-cpu.c`, confirmed against @fugood/whisper.node's own pinned, hash-verified
tarball):

```c
static thread_ret_t ggml_graph_compute_secondary_thread(void* data) {
    ...
    while (true) {
        while (threadpool->pause) {
            ggml_mutex_lock_shared(&threadpool->mutex);      // :3219 -- the FLAGGED lock call
            if (threadpool->pause) { ggml_cond_wait(&threadpool->cond, &threadpool->mutex); }
            ggml_mutex_unlock_shared(&threadpool->mutex);     // :3225 -- unconditional unlock
        }
        if (threadpool->stop) break;
        ggml_graph_compute_check_for_work(state);
        ...
    }
    return (thread_ret_t) 0;                                  // :3239 -- the "unsafe" return
}
```

**Root cause: a real CFG-precision gap, not a missing unlock.** The flagged lock (`:3219`) sits
inside the inner `while(threadpool->pause)` loop and is unconditionally matched by
`ggml_mutex_unlock_shared` at `:3225` -- the very last statement in that loop body, executed on
every real path through it (no `break`/`return`/`goto` between the lock and its own unlock).
The function's own `return` at `:3239` is only reachable AFTER that inner loop has already
exited (`threadpool->pause` false) and the outer loop's own `if(threadpool->stop) break;` fires
-- at which point the mutex was never held. `lock_balance_verdict.py`'s own function-scoped
"does this function's own body reach a return without an unlock anywhere" check does not appear
to model the nested-loop structure precisely enough to see that the lock/unlock pair always
completes together before any return path -- a real, disclosed algorithmic gap (matching
roadmap step 7's own scope: "OOB cross-variable type/extent equivalence" and lock-shape
precision are the SAME class of issue -- the scanner's own structural reasoning not yet
matching real, more complex control flow), not the "primitive-wrapper" shape task #34's earlier
5 promotions found. Recorded as a real, distinct root cause in `adjudication_registry.py`.

## 3-4-5-6. `GetLanguageFromName` (`@elchetz/cld@2.8.5`) -- 4 `oob_write_candidates`

Real source (`deps/cld/internal/lang_script.cc`, confirmed against the package's own pinned,
hash-verified tarball):

```c
int len = strlen(src);
if (len >= 16) { return UNKNOWN_LANGUAGE; }   // :406-area guard -- len < 16 from here on
char temp[16];
int hyphen1_offset = hyphen1 - src;           // hyphen1 = strchr(src, '-') -- points INTO src
int hyphen2_offset = hyphen2 - src;           // hyphen2 = strchr(hyphen1+1, '-') -- likewise
memcpy(temp, src, len);
temp[hyphen2_offset] = '\0';                  // :427 (flagged)
...
int len2 = len - hyphen2_offset;
memcpy(&temp[hyphen1_offset], hyphen2, len2); // :434-area (flagged, "hyphen1_offset+len2")
temp[hyphen1_offset + len2] = '\0';           // :436 (flagged)
...
temp[hyphen1_offset] = '\0';                  // :442-area (flagged)
```

(Line numbers above reference the surrounding statements; the 4 flagged sites are the 4 real
writes into `temp[16]` at offsets `hyphen2_offset`, `hyphen1_offset+len2`, and `hyphen1_offset`
(twice, once per code path) -- `site_id`s `GetLanguageFromName:406:memcpy`,
`:426:memcpy`, `:434:memcpy`, `:442:memcpy`.)

**Root cause: a real bound-propagation gap, not an actual overflow.** `len < 16` is enforced by
an explicit early-return guard immediately before `temp[16]` is even declared. Every later
offset written is provably `< len` by real pointer arithmetic: `hyphen1`/`hyphen2` are both
`strchr()` results pointing INTO `src` (before its own null terminator), so
`hyphen1_offset`/`hyphen2_offset` are both `< len` by construction; `hyphen1_offset + len2 =
hyphen1_offset + (len - hyphen2_offset) < len` since `hyphen2_offset > hyphen1_offset` (hyphen2
is searched for starting AFTER hyphen1). Every flagged write is therefore real, in-bounds.
`CPP_FIXED_ARRAY_INDEX_UNBOUNDED`'s own `SYNTACTIC_ELEM_COUNT` derivation could not propagate
the earlier `if(len>=16) return;` guard (a control-flow fact, not a syntactic one) through to
these later offset computations -- a real, disclosed scanner limitation, not a real
vulnerability in a well-known, widely-used Google-authored language-detection library.

## 7-13. Three functions in vendored SQLite (`@appthreat/sqlite3@9.0.1`) -- 7 `oob_index_write_candidates`

Real source (`deps/sqlite-amalgamation-3530400/{shell.c,sqlite3.c}`, confirmed against the
package's own pinned, hash-verified tarball):

- **`sha1QueryFunc`** (`shell.c:5515-5616`, `array=x[9]`, `index_expr="j"`): `unsigned char
  x[9]; ... for(j=8; j>=1; j--){ x[j] = ...; }` -- `j` ranges `[1,8]`, always in-bounds for
  `x[9]` (valid indices `0..8`). A trivially provable, small, decrementing-loop bound the
  scanner's own static extent reasoning did not resolve.
- **`lsModeFunc`** (`shell.c:10257-10284`, `array=z[16]`, `index_expr="1 + i*3"`): `char z[16];
  ... for(i=0; i<3; i++){ char *a = &z[1+i*3]; a[0]=...; a[1]=...; a[2]=...; }` -- for
  `i=0,1,2`: writes at offsets `1..3`, `4..6`, `7..9`, all `< 16`; `z[10]='\0'` also in-bounds.
  Same class of gap: a small, compile-time-constant loop bound (`i<3`) not propagated.
- **`sqlite3_get_table_cb`** (`sqlite3.c:158023-158085`, `array`s `colv`/`argv`,
  `index_expr="i"`, `length_param_name="nCol"`): `for(i=0; i<nCol; i++){ ... colv[i] ...
  argv[i] ... }` -- `nCol` is the EXACT real parameter documented by the `sqlite3_exec()`
  callback API's own standard contract as the length of both `argv` and `colv`; `i` is directly
  bounded by it. This is precisely the well-formed case `CPP_PARAM_LENGTH_PAIR_INDEX_UNBOUNDED`'s
  own `PARAM_LENGTH_PAIR` rule is meant to recognize as safe, yet it was promoted as an
  unresolved `CANDIDATE` here -- a real, disclosed precision gap in that rule specifically
  (worth a closer look as part of roadmap step 7's own OOB-precision work), not a real defect
  in one of the most heavily-audited, fuzzed C codebases in existence.

**Not entered into `adjudication_registry.py`.** `oob_index_write_candidates` findings carry no
populated `site_id` field (confirmed directly: every one of these 7 candidates' own `site_id` is
`None`) -- a real, disclosed, pre-existing gap in that property's own scanner output (unlike
`oob_write_candidates`, which does populate `site_id`). Entering an adjudication keyed on a
shared `None` site_identity would silently veto EVERY future `oob_index_write_candidates`
finding for these two packages, not just the 7 actually reviewed here -- exactly the kind of
fuzzy match `adjudication_registry.py`'s own docstring forbids. These 7 stay real, documented
false positives in this review, `reportable=True` in the live pipeline (correctly, since no
adjudication exists) until `oob_index_write_candidates` gets its own real, unique per-site
identity field -- a real, separate, disclosed follow-up gap, not fixed here.

## Real result after adjudication

6 of the 13 (both `lock_balance_findings`, all 4 `oob_write_candidates`) are suppressed via
`adjudication_registry.py`'s own real, cited veto -- `reportable` correctly returns to `False`
for those on any future replay. The remaining 7 (`oob_index_write_candidates`) stay
`reportable=True`, correctly documented as false positives here but not (yet) mechanically
suppressible -- disclosed explicitly, not silently left ambiguous.
