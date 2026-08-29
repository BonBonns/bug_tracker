# Exploratory Mozilla source scan (NOT confirmatory / NOT held-out corpus)

Runs the FROZEN scanner-v2 producers (base v1/v2 write-capacity comparison +
capabilities 1-4, unmodified) against current heads of `mozilla/nss` and
`mozilla/mozjpeg`, purely as a vulnerability-discovery / real-code-portability
exercise. This directory and its findings are **separate from** the thesis
held-out evaluation (`semantic-bucket-pilot/scanner-v2/study/pooled/`,
258 vulnerable sites / 42 families) and from Capability 4 development.

## Non-goals (explicit)

- **Not added to the frozen held-out corpus.** No accuracy, recall, or
  generalization claim is made from these results.
- **No producer, capability, rule, or route is changed** to chase a finding
  here — a coverage gap surfaced by this scan is recorded, not patched
  in-place (that would be training-on-test with respect to any future
  held-out use of these repos).
- **No CVE list is used to select or promote findings.** Every candidate the
  producers emit on the scanned scope is reported; nothing is filtered to
  "does this match a known bug."
- **Nothing here is committed to the definitive scanner branch**
  (`claude/previous-conversation-context-6gr99h`, pinned at `8b77705`) or to
  `claude/how-claude-code-works-j9lpw0`. This work lives only on
  `claude/moz-scan-exploratory`.

## What's in here

- `sources_pin/` — exact pinned commit + clone command per repository.
- `commands/` — the literal c2cpg / joern-export / normalize / producer
  invocations, byte-for-byte, per scan target.
- `raw_outputs/` — per-target `cpp.json` + producer findings JSON (large
  files may be summarized here with a pointer to the working directory
  instead of committed in full, noted per-file).
- `reports/` — the human-readable candidate report: grouped by producer /
  reason / route / file / function / physical-write identity, split into
  DETERMINISTIC / OPEN_RELATIONSHIP / MISSING_EVIDENCE /
  UNSUPPORTED_REPRESENTATION.

## Toolchain (frozen, matches the definitive scanner branch)

- joern-cli / c2cpg **v4.0.608** (`/tmp/joern-cli`), the same pin as
  `TOOLCHAIN_FROZEN.md` on the definitive branch. 4.0.462 rejected there for
  the same reason it would be rejected here.
- Scanner code: `semantic-bucket-pilot/scanner-v2/*.py` at commit `8b77705`,
  used read-only (imported, never edited) by `run_moz_scan.py` in this
  directory's parent working tree.
