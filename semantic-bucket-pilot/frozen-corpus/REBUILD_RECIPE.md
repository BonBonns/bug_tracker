# Rebuilding the input fact files

The frozen corpus is derived from 12 normalized fact files (`cpp.json`, ~9–99 MB
each, ~360 MB total). Those are **not vendored** — too large, and the source
trees are third-party (Mozilla NSS / mozjpeg, not redistributed here for
licensing + bloat reasons). `manifest.json` records the sha256 of every input,
which proves *which* bytes were used but does not by itself make them
obtainable. This file is the deterministic rebuild recipe that closes that gap:
anyone can regenerate byte-equivalent inputs from public sources.

## Provenance gap, stated honestly

The fact files themselves do **not** stamp their source revision
(`report.json` → `repo_rev_informational: "UNVERSIONED"`). The source revisions
below are recorded externally, in
`moz-scan-paired-cve-validation-round1.md`, where each paired CVE was validated
at a named commit. A regenerated fact file will match structurally and
reproduce the same scanner records; it is not guaranteed byte-identical to the
cached `cpp.json` unless the same joern-c2cpg build is used (see toolchain).

## Toolchain (from fact-file metadata + scan pipeline)

- Frontend: **joern-c2cpg**, version **4.0.608** (`metadata[0].version` in each `cpp.json`)
- Facts schema: **portable-program-facts/0.3** (`schema` in each `cpp.json`)
- Scan pipeline: `tchecker-research-complete/gates/scan_pkg.sh <checkout_dir> <out_dir>`
  (builds the CPG, runs the exporter `.sc` scripts under
  `portable-engine-full-review-package/frontends/` +
  `tchecker-property-adjudicator/producers/`), at the scanner commit recorded
  in `manifest.json`.

## Per-input source revisions

For each CVE, `patched` = the anchor commit, `vuln` = its parent (`^`). Only the
listed source file is needed for the operation under study, but the scan was run
over the full checkout.

| label | repo | vuln rev | patched rev | source file |
|-------|------|----------|-------------|-------------|
| cve-2019-17006 | github.com/mozilla/nss | `0bf553163^` | `0bf553163` | lib/freebl/rsapkcs.c |
| cve-2019-11745 | github.com/mozilla/nss | `0271ef66e^` | `0271ef66e` | lib/softoken/pkcs11c.c |
| cve-2019-11759 | github.com/mozilla/nss | `deb6103d0^` | `deb6103d0` | lib/softoken/pkcs11c.c |
| cve-2016-1950  | github.com/mozilla/nss | `994c45e80^` | `994c45e80` | lib/util/secasn1d.c |
| cve-2021-43527 | github.com/mozilla/nss | `73a449016^` | `73a449016` | lib/cryptohi/secvfy.c |
| mjpg-cve-huff  | github.com/mozilla/mozjpeg | `a06aeb25^` | `a06aeb25` | jchuff.c |

## Regenerate one input

```sh
# example: cve-2019-17006 vulnerable revision
git clone https://github.com/mozilla/nss nss && cd nss
git checkout 0bf553163^          # vuln; use 0bf553163 (no ^) for patched
# scan the checkout with the pinned frontend, producing work/cpp.json
JOERN_HOME=<joern-cli 4.0.608> \
  <repo>/tchecker-research-complete/gates/scan_pkg.sh . /tmp/cve-2019-17006/vuln/scan
# -> /tmp/cve-2019-17006/vuln/scan/work/cpp.json
```

Then point `build_frozen_corpus.py`'s `CORPUS[...]["path"]` at the regenerated
`cpp.json` (or restore the cached paths) and re-run. The manifest's per-input
sha256 lets you confirm you reproduced the same facts before trusting the
regenerated corpus.

## What is guaranteed

- **Given the cached inputs** (same sha256) + this repo at the scanner commit,
  the builder emits byte-identical corpora (producers are deterministic;
  verified by a second run and by the analysis-record gate).
- **Given regenerated inputs** from the revisions above with the same
  joern-c2cpg build, the scanner records reproduce; exact `cpp.json` bytes
  depend on the frontend build and are not promised.
