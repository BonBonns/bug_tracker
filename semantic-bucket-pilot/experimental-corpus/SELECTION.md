# Confirmatory-corpus CVE selection (PRE-REGISTERED before scanning)

Per the expansion rules, the new cases are selected **before** observing any
scanner bucket or LLM output. Selection is on DISCLOSED properties only.

## Selection criteria (fixed in advance)

1. Disclosed memory-safety fix in NSS (Mozilla security bug; CVE where assigned),
   in C.
2. Vulnerability shape = a buffer **write** into a destination with a
   capacity/length relationship (the family the frozen scanner recognizes) —
   judged from the disclosed fix, NOT from scanner output.
3. Known fix commit. patched = the fix commit; vuln = its parent (`^`). Same
   case family holds both revisions.
4. Diversity: spread across NSS modules (softoken, freebl, base, certdb); not a
   function already in the corpus.
5. Whatever the scanner emits for these (candidate / abstain / nothing) is a
   result to report, not a selection criterion. Some may yield 0 routable
   candidates — that is recorded, not hidden.

## Pre-registered set (frozen at this commit)

| id | Mozilla bug | title | file | patched | vuln (parent) |
|----|-------------|-------|------|---------|---------------|
| E1 | Bug 1869493 | Heap-buffer overflow in AES Keywrap | lib/softoken/pkcs11c.c | `87b60a905` | `86e9cefa4` |
| E2 | Bug 1835425 | Improve length check of RSA input to avoid heap overflow | lib/freebl/rsapkcs.c | `e3178b228` | `ce49301b5` |
| E3 | Bug 1396616 | nssUTF8_Length RFC 3629 + fix buffer overrun | lib/base/utf8.c | `d9efe9397` | `d3e9bbf4f` |
| E4 | Bug 2026311 | avoid integer overflow in RSA_EMSAEncodePSS | lib/freebl/rsapkcs.c | `338814524` | `6d84d8779` |
| E5 | Bug 2028954 | CERT_DecodeAVAValue integer overflow in output buffer sizing | lib/certdb/secname.c | `9ba8ffc50` | `c7d09b2cf` |

Repo: `github.com/mozilla/nss`. Frontend: joern-c2cpg 4.0.608 (see
JOERN_PROVENANCE.md). Scanner + bucket schema stay frozen v1; only these fact
inputs are added.

CVE numbers are not all individually confirmed here; the Mozilla bug id is the
authoritative disclosed identifier and is recorded as such. Outcomes will be
independently verified from source before any A/B/C use, and the vuln/patched
differential established per family.

## Process from here (fixed order)

1. Freeze this selection (this commit).
2. For each id and side: extract the module subtree at the pinned revision,
   scan via the frozen pipeline, run the frozen producers.
3. Record what the scanner emits (routable or not) — no back-selection.
4. Independently verify each family's outcome (vuln vs patched) from source.
5. Only then assemble the balanced confirmatory corpus and run A/B/C with the
   frozen prompt generator v2.
