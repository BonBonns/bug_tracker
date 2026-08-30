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

## What this fix does NOT address (separate, pre-existing, out of scope here)

- `case_037fb711` (eccsi.c) remains mapped as `pointer_deref` with `write_dest` literally
  `"component.  With s"` — a fragment of a **code comment**, not an expression. `DEREFW`/
  `IDXW`/`COPY` all operate on raw diff-hunk text with no comment stripping, so a comment
  containing e.g. `* p = ...`-shaped text can match. This is a distinct, pre-existing gap
  (comment-blind matching), not the copy-macro gap this round fixes; flagging it rather
  than silently also patching it, since it needs its own audit of how many other sites it
  affects before a fix is evidence-supported.
- No re-freeze of the SecVulEval pilot corpus (`study/secvuleval/FROZEN_heldout.json`) —
  same shared `COPY` regex, so the identical class of gap likely applies there too, but its
  source `random_subset.json` was not re-fetched this round; the existing SecVulEval freeze
  is already documented as "insufficient" and not gating anything, so it was left as is.
- Recognition measurement (build wolfSSL/ImageMagick/etc. from source, run the real
  scanner, score `mapped` sites) — not yet done. This audit was a precondition for it, not
  a substitute.
