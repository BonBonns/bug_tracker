# Manual audit — AES key-wrap and CTS/CBC tail handling (triage items 2 & 3)

Both resolve the same way, and reveal a real NSS-wide API convention the frozen scanner
doesn't model: functions in this style declare `(outbuf, outlen, maxout, inbuf, inlen,
...)` and open with `if (maxout < <needed>) { PORT_SetError(...); return SECFailure; }` —
a genuine, unconditional, non-assert runtime check, not the compiled-out-in-release
pattern `hmacct.c`'s write 1 turned out to hinge on. Every write the scanner flagged in
these two functions executes strictly after that check.

## AES key-wrap (`lib/freebl/aeskeywrap.c`)

- **`AESKeyWrap_Winv`, line 411** (`memcpy(output, &R[1], outLen)`, flagged as
  `AESKeyWrap_Winv:411 dest=output len=outLen`): guarded by `if (maxOutputLen < outLen)
  return SECFailure;` at line 363, unconditionally, before this write. Both public
  entry points (`AESKeyWrap_Decrypt`, `AESKeyWrap_DecryptKWP`) pass their own
  caller-supplied `maxOutputLen` straight through — the guard is real at every call
  depth, not bypassable.
- **`AESKeyWrap_EncryptKWP`, line 535** (`PORT_Memcpy(newBuf, input, inputLen)`,
  flagged as `dest=newBuf len=inputLen`): safe **by construction**, not by a runtime
  check — `newBuf = PORT_ZAlloc(paddedInputLen)` immediately above (line 531), and
  `paddedInputLen = inputLen + padLen` where `padLen = BLOCK_PAD_POWER2(...) >= 0`
  always. `paddedInputLen >= inputLen` holds unconditionally from the arithmetic, no
  guard needed. This is exactly the class of relational-symbolic-capacity reasoning
  (`allocation size expression B` provably `>= write length A` where both derive from
  the same base variable) neither this pipeline's `cap1`/base producer nor the old
  TChecker corpus's producers attempt — the destination's heap provenance is
  recognized (`base_capacity_symbolic`) but the relationship to the length is never
  chased. Same documented gap, new example.

## CTS/CBC tail handling (`lib/freebl/cts.c`)

- **`CTS_EncryptUpdate`** (flagged: `lastBlock:134`, `Cn_2:228`, `Cn_1`, `Cn`,
  `lastBlock:245/246` — the multi-hit cluster from the pilot): `if (maxout < inlen)
  return SECFailure;` at line 104, unconditional, before every subsequent write. The
  `lastBlock[MAX_BLOCK_SIZE]` write at 134 copies the post-`fullblocks` remainder
  (`inlen -= fullblocks` at line 117), which is `< blocksize` by construction of
  `fullblocks = (inlen/blocksize)*blocksize` — safe by the same
  same-function-arithmetic pattern as the AES case above.
- **`CTS_DecryptUpdate`**: identical guard at line 198 (`if (maxout < inlen) return
  SECFailure;`), same structure. `Cn_2`/`Cn`/`lastBlock` writes are all `blocksize`-
  or `pad`-bounded copies where the bound is derived from `inlen` (already
  `<= maxout`) via the same in-function arithmetic.

## Bottom line

Both triage items are **false positives for exploitability** — every flagged write in
both functions is guarded, either by a real runtime check (`maxout`/`maxOutputLen`
pattern, present at every real call depth traced) or by a provable same-function size
relationship. No hardening patch is warranted for either — unlike `hmacct.c`'s write 2,
there is no latent gap here to close; these are just cases the scanner correctly
recognizes as unresolved (it doesn't do relational-capacity or interprocedural-guard
reasoning) without any actual bug behind the flag.

**One real, reusable finding for the scanner-improvement backlog**: NSS has a
consistent, greppable `(dest, *outlen, maxout, src, srclen, ...)` API convention across
at least `AESKeyWrap_*`, `CTS_*`, and (per the earlier `hmacct.c` audit) similar
`mdOutMax`/`maxResultLen`-style parameters elsewhere. A narrow capability recognizing
"a `max*`-named parameter checked with `if (maxParam < lenExpr) return err;` before a
write of `lenExpr` into the associated dest parameter" would resolve this whole class at
once — cheaper than general interprocedural capacity propagation, narrower in scope than
the `*_Resurrect` allocator pattern, and corroborated by every triage item this round.
