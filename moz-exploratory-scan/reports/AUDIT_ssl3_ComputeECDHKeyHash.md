# Manual audit — `lib/ssl/ssl3ecc.c::ssl3_ComputeECDHKeyHash()`

Hand-chased lead from `NSS_SCOPE_EXPANSION_softoken_ssl.md` ("ECDH key-hash buffer
writes sized by `SSL3_RANDOM_LENGTH` and two length fields off `ec_params`/
`server_ecpoint` — attacker-influenced key-exchange parameters... the single most
attacker-adjacent candidate in this batch"). Traced by hand against the pinned
`mozilla/nss@7b5f00b` tree — no CVE list consulted.

## The flagged writes

```c
// ssl3ecc.c:112-161
PRUint8 buf[2 * SSL3_RANDOM_LENGTH + 2 + 1 + 256];   // 64 + 2 + 1 + 256 = 323 bytes

bufLen = 2 * SSL3_RANDOM_LENGTH + ec_params.len + 1 + server_ecpoint.len;
if (bufLen <= sizeof buf) {
    hashBuf = buf;                    // stack path
} else {
    hashBuf = PORT_Alloc(bufLen);     // heap fallback, EXACTLY bufLen bytes
    if (!hashBuf) return SECFailure;
}
memcpy(hashBuf, client_rand, SSL3_RANDOM_LENGTH);
pBuf = hashBuf + SSL3_RANDOM_LENGTH;
memcpy(pBuf, server_rand, SSL3_RANDOM_LENGTH);
pBuf += SSL3_RANDOM_LENGTH;
memcpy(pBuf, ec_params.data, ec_params.len);
pBuf += ec_params.len;
pBuf[0] = (PRUint8)(server_ecpoint.len);
pBuf += 1;
memcpy(pBuf, server_ecpoint.data, server_ecpoint.len);   // the attacker-adjacent write
```

**This function already self-defends dynamically**: `bufLen` is computed from the REAL
`ec_params.len`/`server_ecpoint.len` before any write, and every subsequent `memcpy`
writes into a buffer sized to exactly `bufLen` (either the fixed stack `buf`, verified
`<=` its size first, or a freshly `PORT_Alloc(bufLen)`'d heap buffer otherwise) — this
is not the "trust a fixed capacity" shape the rest of this exploratory scan has been
chasing. The real question is whether `ec_params.len`/`server_ecpoint.len` can ever be
manipulated to defeat the `bufLen <= sizeof buf` check itself (an integer-overflow-in-
the-bound-computation shape) or exceed what `PORT_Alloc` can safely satisfy -- not
whether the buffer is fixed-size.

## Every caller's actual bound on `ec_params.len` / `server_ecpoint.len`, traced

Two call sites, both traced to their argument origin:

**Site 1 -- `ssl3_HandleECDHServerKeyExchange` (line 619), CLIENT parsing the SERVER's
key-exchange message (network-controlled, the attacker-adjacent path):**
```c
// ssl3ecc.c:539-541,559
ec_params.len = sizeof paramBuf;   // = 3, a C compile-time constant, never variable
rv = ssl3_ConsumeHandshake(ss, ec_params.data, ec_params.len, &b, &length);
...
rv = ssl3_ConsumeHandshakeVariable(ss, &ec_point, 1, &b, &length);
```
`ec_params.len` is **always exactly 3** -- `ssl3_ConsumeHandshake` reads a FIXED number
of bytes (the CONTENTS are attacker-controlled; the LENGTH is a compile-time constant,
never derived from wire data). `ec_point.len` (passed as `server_ecpoint`) comes from
`ssl3_ConsumeHandshakeVariable`'s `1`-byte-length-prefix argument -- the wire format
itself encodes this length in a single byte, so the PARSER structurally cannot produce
`ec_point.len > 255` no matter what an attacker sends; this is the same constraint the
function's own comment states ("ECPoint needs to fit in 256 bytes because the spec
says the length must fit in one byte") -- confirmed here at the actual parse site, not
just asserted at the point of use.

**Site 2 -- `ssl3_SendECDHServerKeyExchange` (line 732), SERVER generating its OWN key
share:** `ec_params` is 3 literal bytes this code itself constructs
(`ec_params.data[0..2]`, `ec_params.len = sizeof(paramBuf) = 3`). `server_ecpoint` is
`pubKey->u.ec.publicValue` -- NSS's own locally-generated EC public key encoding,
bounded by the largest curve NSS supports (P-521's uncompressed point encoding is 133
bytes -- well under 256) -- not attacker-influenced at all beyond which named curve got
negotiated, itself limited to the enumerated `ssl_named_groups` table.

So in BOTH real callers, `ec_params.len` is always exactly 3 and `server_ecpoint.len`
is always `<= 255` (structurally, at Site 1; by curve-size construction, at Site 2).

## The one thing worth flagging precisely (not a bug, but non-obvious): the stack buffer's own sizing comment doesn't match its own code, and only coincidentally still holds

`buf`'s declared size uses **"+ 2"** for the params slot
(`2 * SSL3_RANDOM_LENGTH + 2 + 1 + 256` = 64+2+1+256 = **323**), but every real caller's
`ec_params.len` is **3**, not 2 (traced above) -- the "two bytes" in the function's own
comment ("ec_params takes up only two bytes") does not match `sizeof(paramBuf) == 3`
anywhere it's actually constructed. Computing the REAL worst case: `bufLen_max = 64 + 3
+ 1 + 255 = 323`. `sizeof(buf) = 323`. These are equal only because the buffer's
"+256" for the point slot over-provisions by exactly 1 byte relative to the point's
TRUE maximum (255, not 256 -- an 8-bit length prefix's max value is 255) which happens
to exactly offset the sizing comment's undercount of `ec_params.len` by 1 (2 vs. the
real 3). **The bound holds (`bufLen <= sizeof buf` is true with EXACT equality at the
real-world maximum), but by an arithmetic coincidence between two separate off-by-ones,
not because the comment's stated reasoning is correct.** Not exploitable regardless --
even if this coincidence didn't hold, the `else` branch's `PORT_Alloc(bufLen)` fallback
would still size the buffer correctly -- but worth a doc/comment fix independent of any
safety fix, since the NEXT person reading this code and trusting the "two bytes"
comment while changing `ec_params`'s real width would not get an automatic warning; the
dynamic `bufLen <= sizeof buf` check is the thing actually keeping this safe, not the
comment's stated invariant.

## `pBuf[0] = (PRUint8)(server_ecpoint.len);` -- truncation, but lossless given the traced bound

This narrows `server_ecpoint.len` (an `unsigned int`) to a single byte before writing
it as the wire-format length prefix. Given the traced bound above (`server_ecpoint.len
<= 255` in every real caller), this cast is always lossless -- not a bug through either
real call path. Would silently produce a WRONG (wrapped) length byte, not a memory
overrun, if some future third caller ever supplied `server_ecpoint.len > 255` (the
subsequent `memcpy` still copies the REAL, untruncated `server_ecpoint.len` bytes,
correctly sized via `bufLen`'s own computation -- only the wire-encoded length PREFIX
would then misrepresent the payload that follows it, a hash/protocol-correctness bug,
not a buffer overflow).

## Verdict: false positive for memory safety -- correctly self-defends via dynamic sizing, every real caller's lengths are additionally bounded upstream

Not a vulnerability. `bufLen` is computed from real, not assumed, argument lengths
before any write, with a genuine heap fallback for the case the stack buffer doesn't
fit -- the general shape this whole exploratory scan has been chasing (a WRITE trusting
a FIXED capacity it never re-derives) does not apply here. Both real callers
additionally bound their arguments upstream by construction (a fixed 3-byte read, a
1-byte wire length prefix, or a small curve-size-bounded local value), so even the
edge-case coincidence noted above is never actually exercised at its boundary by
attacker-controlled input. Worth a documentation fix (the "two bytes" comment doesn't
match `sizeof(paramBuf) == 3`) but not a security patch.
