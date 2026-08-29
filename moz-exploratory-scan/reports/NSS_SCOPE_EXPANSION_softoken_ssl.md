# NSS scope expansion — `lib/softoken` + `lib/ssl`

Extends the `lib/freebl` pilot to the two modules with the most historical bug density
per the old TChecker NSS corpus (`pk11wrap`/`softoken` and `ssl` came up repeatedly
there). Same pinned commit (`mozilla/nss@7b5f00b`), same joern v4.0.608 toolchain.
**Scanner state used**: `claude/cap1-wsd-identity` tip (post cap1-identity-integration,
post V1/V2 delegation fix) — a newer scanner snapshot than the original `lib/freebl`
pilot, so counts aren't directly comparable to that report; noted for provenance, not
a discrepancy.

## Build integration

- `lib/softoken`: `--include`d `lib/util`, `lib/freebl` (+ `mpi`), `lib/certdb`, plus
  NSPR's public headers (`nspr/pr/include`, fetched fresh via a sparse clone of
  `mozilla/nspr` — no NSPR build, headers only). Parsed clean, 154MB `cpp.json`.
- `lib/ssl`: `--include`d `lib/util`, `lib/certdb`, `lib/certhigh`, `lib/pk11wrap`,
  `lib/cryptohi`, same NSPR headers. Parsed clean, 127MB `cpp.json`.

## Results

| Target | Raw records | Unique ops (cap2a+cap2b+cap3, dedup'd) | DETERMINISTIC | OPEN_RELATIONSHIP | proven_oversized |
|---|---:|---:|---:|---:|---:|
| softoken | 408 | 46 | 9 | 35 distinct sites | 0 |
| ssl | 147 | 49 | 1 | 18 distinct sites | 0 |

**Zero proven-oversized findings in either module** — same negative result as the
`lib/freebl` pilot, now covering the modules most likely to have real bugs.

## The 10 deterministic-safe findings

softoken (9): `nsspkcs5_PFXPBE`'s `state` writes, `sftk_CryptInit`'s `newdeskey`/
`newdeskey+16`, `NSC_DeriveKey`'s `des3key`/`des3key+16` (×2), `sftk_forceAttribute`'s
`att_val` — mostly **cap1 (`&(base[index])`) recognitions on real bare-array-offset key
material writes**, the newly-identity-integrated capability doing real work on real code
for the first time. ssl (1): `tls_ClientHelloExtensionPermutationSetup`'s `builders`.
All read as genuinely safe on inspection (fixed-size key-material buffers, literal
offsets within bounds).

## Notable open-relationship candidates (not verified — `llm_eligible` flags, not findings)

- **`sslsock.c::ssl_WriteV`** (2 sites, lines 3629/3673/3636/3677) — the SAME function
  the old TChecker corpus already manually confirmed safe (a preceding while-loop's exit
  condition), and already documented there as exposing a real scanner-design gap
  ("guard-crediting is whole-function-scoped, not dominance-aware" — a guard
  suppresses a site it doesn't actually control-flow-dominate). Corroborates that
  finding on a different, newer scanner generation; not re-verified here, already
  settled.
- **`pkcs11c.c::sftk_doSSLMACInit`** (`sslmacinfo->key` sized by
  `keyval->attrib.ulValueLen`) — a PKCS#11 attribute-length-driven key copy; worth a
  look given this session's own `hmacct.c` audit already found a real (if narrow)
  gap in a related MAC-key-handling path (`SetupMAC()`'s `secretLength` bound).
  Not chased further this round.
- **`ssl3ecc.c::ssl3_ComputeECDHKeyHash`** (4 sites) — ECDH key-hash buffer writes
  sized by `SSL3_RANDOM_LENGTH` and two length fields off `ec_params`/`server_ecpoint`
  (attacker-influenced key-exchange parameters). Not chased further this round —
  flagged as the single most attacker-adjacent candidate in this batch given the
  length fields originate from parsed, network-supplied EC parameters.

## Scope note

Neither module was scanned to completion of NSS's full module list — `pk11wrap` proper
(only pulled in as headers for `ssl`), `nss` (the top-level cert/policy glue), and the
legacy `dbm`/`jar` modules remain unscanned. Given two negative (0 proven-oversized)
results across freebl + softoken + ssl now, and the ECDH/MAC candidates above being the
most promising unverified leads, recommending a pause on further raw module coverage in
favor of chasing those two candidates by hand next, rather than scanning more modules
for their own sake.
