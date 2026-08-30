# PostCutoff-CVE write-mapping audit — RULE 1 recall gap found and fixed

Manual audit of the frozen PostCutoff-CVE `mapped` corpus (`c3007c0`, 21 sites / 9
families) against the real diffs at the real pinned commits (not just the blinded/
regex-classified data), done BEFORE any build-and-scan measurement — following this
project's own precedent (`MAGMA_WRITE_MAPPING.md`'s "recall sensitivity check": re-screen
what the frozen rule rejected/accepted, fix a demonstrated regex gap, recompute; the rule
itself stays frozen).

## What the audit found: most "mapped" wolfSSL sites were not write bugs at all

Checked all 8 wolfSSL `mapped` sites against `git diff <parent> <fix>` at the real commits:

| Site | CVE | Actual root cause | Genuine write-capacity bug? |
|---|---|---|---|
| `case_037fb711` (eccsi.c) | CVE-2026-5466 | Missing signature range/infinity checks (forged-signature acceptance) | No — crypto validation |
| `case_624ccdb4` (tls.c/tls13.c) | CVE-2026-0819 | Missing ECH confirmation-presence check | No — protocol logic |
| `case_644b3e3c` (dtls13.c) | CVE-2026-5264 | Missing mutex lock around list traversal | No — thread-safety |
| `case_684d26f7` (dh.c) | CVE-2026-5295 | `#endif` moved so a pubkey check always runs | No — missing validation, zero writes in the file |
| `case_e062ef20` (dtls13.c) | CVE-2026-5264 | Missing mutex unlock before early return | No — thread-safety |
| `case_c2b0a072` (renesas_tsip_sha.c) | CVE-2026-55958 | `XMEMCPY` moved inside an `else` so it can't run unguarded | **Yes** |
| `case_8762ecc4` (pkcs7.c) | CVE-2026-5295 | `XMEMCPY(output, encryptedContent, sz)`, no prior `sz > outputSz` check | **Yes** |
| `case_faac9f02` (pkcs7.c) | CVE-2026-5295 | `XMEMCPY(oriOID, ..., oriOIDSz)`, no size-cap check | **Yes** |

**Only 3 of 8 (37%) were actual destination-capacity write bugs.** The other 5 carry a
write-family CWE alongside several *other* CWEs on the same multi-CVE record, and RULE 1
(a text regex over the diff hunk, no capability, no manual interpretation) picked up an
*incidental* `*x = ...` / `arr[i] = ...` pattern nearby that has nothing to do with the
actual fix — e.g. `*prevNext = rn->next;` inside a mutex-lock fix, matched as `pointer_deref`
though the CVE is about the missing lock, not that store.

## Root cause: the genuine bugs were invisible to RULE 1, for a concrete, checkable reason

The two genuine `XMEMCPY(...)` bugs (`case_8762ecc4`, `case_faac9f02`) did **not** classify
as `copy_sink` — they fell through to a spurious `pointer_deref` match instead, because
`secvuleval_freeze.py`'s `COPY` regex only lists bare lowercase libc names (`memcpy`,
`memmove`, `strcpy`, ...). It has no entry for wolfSSL's own portability copy-macros, which
is wolfSSL's pervasive convention for every copy operation in the codebase. Confirmed by
reading the real macro definitions, not assumed:

```
wolfssl/wolfcrypt/types.h:1078  #define XMEMCPY(d,s,l)    memcpy((d),(s),(l))
wolfssl/wolfcrypt/types.h:1079  #define XMEMSET(b,c,l)    memset((b),(c),(l))
wolfssl/wolfcrypt/types.h:1081  #define XMEMMOVE(d,s,l)   memmove((d),(s),(l))
wolfssl/wolfcrypt/types.h:1084  #define XSTRNCPY(s1,s2,n) strncpy((s1),(s2),(n))
wolfssl/wolfcrypt/types.h:1091  #define XSTRNCAT(s1,s2,n) strncat((s1),(s2),(n))
wolfssl/wolfcrypt/types.h:1202  #define XSNPRINTF snprintf   (one branch of an #ifdef ladder)
wolfssl/wolfcrypt/types.h:1207  #define XSPRINTF sprintf
```

Same (dest, src, len) argument order and semantics as the bare libc call in every case —
this is the identical wrapper-macro class this project already found and fixed once, on
the *scanner* side, for NSS's `PORT_Memcpy`/`PORT_Memmove` (`dad8f00`). Here it was the
*dataset-freeze tool itself* that had the gap, one layer upstream of anything measured.

**A real, checkable consequence of the gap, not just a misclassification:** one PostCutoff
site (`case_bd048ac6`, wolfSSL CVE-2026-0819, `ecc.c`) was `no_write_found` under the old
regex — completely invisible, not even mismapped — because its *only* write in the diff is
`XMEMCPY(key->pubkey_raw, (byte*)in, inLen);` with no prior `inLen <= sizeof(key->pubkey_raw)`
check. A genuine destination-capacity write bug was silently dropped from the corpus
entirely, not just misfiled.

## The fix

Added the confirmed wrapper set to `COPY` in `secvuleval_freeze.py` (shared by
`postcutoff_freeze.py`): `XMEMCPY`, `XMEMSET`, `XMEMMOVE`, `XSTRNCPY`, `XSTRNCAT`,
`XSNPRINTF`, `XSPRINTF`, plus the already-verified NSS `PORT_Memcpy`/`PORT_Memmove`
(carried over from `dad8f00`, not new speculation). Deliberately **excluded** same-family
macros that are reads/compares, never writes — adding those would fabricate write sites,
not recognize missed ones:
- `XMEMCMP` → `memcmp` (compare)
- `XSTRCMP`/`XSTRNCMP` → `strcmp`/`strncmp` (compare)
- `XSTRSTR`/`XSTRNSTR`/`XSTRSEP` → `strstr`/`strsep` (read/search)

Re-ran `postcutoff_freeze.py` against the byte-identical dataset snapshot (same pinned
repo commit `b5d7b19d`, same `blind_inputs.jsonl` sha256 `94d90473...`) — a pure recount
under the corrected rule, nothing else changed.

## Result: fewer sites, but honest ones — RULE 1's uniqueness requirement did its job

| | before | after |
|---|--:|--:|
| mapped | 21 | **18** |
| ambiguous | 34 | 40 |
| no_write_found | 57 | 54 |
| vulnerable families | 9 | **8** |
| wolfSSL mapped | 8 | 5 |
| copy_sink | 2 | 3 |
| 12-family gate | BELOW | BELOW (still) |

The 3 genuine wolfSSL sites did **not** simply flip to `copy_sink` and stay mapped — RULE 1
correctly demoted `case_c2b0a072`, `case_8762ecc4`, and `case_faac9f02` to `ambiguous`,
because now-recognized `XMEMCPY` calls elsewhere in the same diff (the fix touches multiple
files, e.g. `tests/api.c` alongside the real source) make the destination write no longer
*unique* across the whole hunk. This is RULE 1 working as designed — abstain rather than
guess which of several writes is the fix-relevant one — not a bug in this fix. The 5
confirmed-spurious sites are gone; one previously **entirely invisible** genuine bug
(`case_bd048ac6`, `ecc.c`) is now correctly `mapped` as `copy_sink`. Net: a smaller,
more trustworthy corpus, not a bigger one — consistent with this project's standing
preference for an honest small yield over an inflated one (cf. the SecVulEval freeze,
accepted as "insufficient" rather than gamed).

## Round 2: the comment-text-matching artifact (flagged above), fixed

`case_037fb711` (eccsi.c) was left mapped after round 1, `pointer_deref` with `write_dest`
literally `"component.  With s"` — not an expression, a fragment of the doc comment
`/* Validate s is in [1, q-1]... * component.  With s=0, [s](...) yields the point at
infinity... */`. `DEREFW`/`IDXW`/`COPY` all ran on raw diff-hunk text with no comment
stripping, so `DEREFW`'s bare `\*...=` pattern matched the `*` comment-continuation
marker plus the prose's own incidental `s=0`. Verified: `DEREFW.search()` on that exact
line returns a match; the CVE this site is tagged with is a signature-validation bug with
zero real writes anywhere in its diff (confirmed in the round-1 table above) — so this was
never a real write site, comment or not.

**Fix:** added `strip_comments()` to `secvuleval_freeze.py` — blanks `//` and `/* */`
(including multi-line block) comment text in place, preserving line count/order so
`map_write`'s line-index correlation against `locate_label` stays valid. Wired into
`writes_in()`'s input in both `map_write` (comment-stripped for write-detection, original
text kept for label matching) and `postcutoff_freeze.py`'s direct call. Verified against
the reproduced eccsi.c comment (now correctly `no_write_found`, matching the round-1 manual
finding) and a battery of real-write/real-comment mixed cases (trailing `//`, same-line and
multi-line `/* */`, all correctly stripped without touching genuine code on the same or
following lines).

**A second, distinct pre-existing bug this surfaced directly (fixed too, same round,
concrete evidence, not speculative scope creep):** removing the comment noise promoted a
previously-`ambiguous` site (`case_5b60666e`, `openwrt/openwrt`) to `mapped`,
`pointer_deref`, dest `"ctx"` — matched from `PROV_AES_SIV_CTX *ctx = (PROV_AES_SIV_CTX
*)vctx;`, a **pointer declaration with an initializer**, not a dereference-store. (The
"source" here is actually upstream OpenSSL code reproduced inside an OpenWrt package
patch file — `package/libs/openssl/patches/010-fix-aes-gcm-siv-cipher.patch` — a version
bump with no real destination-capacity write in the diff at all.) `DEREFW` cannot tell
`Type *var = expr;` from `*var = expr;`. Fixed by rejecting a `DEREFW` match when the
character immediately preceding the matched `*` (skipping whitespace) is a word
character/underscore (a type name glued to the declarator) or another `*` (a multi-level
declarator chain, `int **pp = ...`, where `.search()` lands on the second `*`). Verified
against 8 cases: single- and multi-level declarations rejected; genuine dereference-writes
(including after a prior statement, mid-statement, struct-field-typed) still accepted.

## Combined result (both rounds, same byte-identical dataset snapshot)

| | round 1 (baseline) | round 1 fix (copy-macros) | round 2 fix (+ comments/decls) |
|---|--:|--:|--:|
| mapped | 21 | 18 | **17** |
| ambiguous | 34 | 40 | 32 |
| no_write_found | 57 | 54 | 63 |
| vulnerable families | 9 | 8 | **11** |
| copy_sink | 2 | 3 | **6** |
| 12-family gate | BELOW | BELOW | BELOW (11/12 — one short) |

Family diversity nearly doubled (8 → 11, one short of the gate) once the declaration-star
false positives stopped competing with (and sometimes masking, via ambiguity) genuine
`copy_sink`/`index_write` matches. `case_faac9f02` (the `pkcs7.c` `oriOID` XMEMCPY bug,
confirmed genuine in round 1 but demoted to `ambiguous` by the copy-macro fix alone) is now
correctly `mapped` as `copy_sink` once the declaration-noise around it also clears. Spot-
checked 3 of the newly-mapped/changed sites across 2 more repos (zephyr, wolfSSL) against
real diffs: all are genuine write operations in the diff (one, `case_9eff7b57`, matches a
real `memset` that is very likely *not* the CVE's actual root cause — a shared-vs-per-
connection buffer bug, not a memset-size bug — which is RULE 1 behaving exactly as
designed: it finds *a* write mechanically, never claims semantic certainty that it is *the*
fix-relevant one. That imprecision is inherent to RULE 1's design, pre-dates both fixes in
this document, and is not something either one claims to solve).

## What remains out of scope here (separate, pre-existing)

- RULE 1's "finds *a* write, not necessarily *the* fix-relevant write" imprecision (see
  `case_9eff7b57` above) — inherent to a purely mechanical, no-manual-interpretation rule;
  narrowing it further would mean adding semantic bug-localization, a different and much
  larger undertaking, not a regex fix.
- `DEREFW`'s capture character class doesn't include `*` or `(`, so cast-and-dereference
  forms like `*(int*)dst = 5;` don't match at all (verified: pre-existing, unaffected by
  either fix in this document).
- The blanket `"==" not in l` exclusion in `writes_in()` drops an entire line's write if it
  contains `==` *anywhere*, even a genuine write on the same line after an unrelated
  comparison (e.g. `if (a == b) *p = c;`) — verified pre-existing, unaffected here.
- No re-freeze of the SecVulEval pilot corpus (`study/secvuleval/FROZEN_heldout.json`) —
  same shared `COPY`/`DEREFW` code, so the identical classes of gap likely apply there too,
  but its source `random_subset.json` was not re-fetched; the existing SecVulEval freeze is
  already documented as "insufficient" and not gating anything, so left as is.
- Recognition measurement (build wolfSSL/ImageMagick/etc. from source, run the real
  scanner, score `mapped` sites) — not yet done. This audit was a precondition for it, not
  a substitute.
