# JS↔C/C++ transition corpus (pulled from CVEfixes v1.0.8)

A real, ground-truth-labeled corpus of CVEs where a single fix commit (or, in one case, a
single CVE ID) spans both JavaScript/TypeScript and C/C++ code. Pulled to test how a
vulnerability "transitions" between the two languages -- built from a real, existing
dataset rather than curated one CVE at a time by hand, unlike the wolfSSL-based tracks
elsewhere in `study/`.

## Source and provenance

[CVEfixes](https://github.com/secureIT-project/CVEfixes) v1.0.8 (Bhandari et al., "CVEfixes:
Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software"), pulled
via its Hugging Face parquet mirror
([`hitoshura25/cvefixes`](https://huggingface.co/datasets/hitoshura25/cvefixes),
`refs/convert/parquet`, 3 shards, ~1.2 GB total, downloaded 2026-08-30). This is the full
dataset as published -- 12,987 rows, each one (`cve_id`, fix commit `hash`, dominant
`language` of that commit) -- not a HF-side sample. Each row already carries the ground
truth: `cwe_id`/`cwe_name`, `cve_description`, `commit_message`, `diff_stats`,
`diff_with_context`, and separately-extracted `vulnerable_code`/`fixed_code` snippets. The
raw Zenodo release (12.7 GB SQL dump, DOI `10.5281/zenodo.4476563`) was not pulled -- the
parquet mirror carries the same 12,987 records at a fraction of the size.

## How the corpus was built

Queried the full 12,987-row table two ways:

1. **Same CVE ID, independently fixed in a JS/TS codebase and a C/C++ codebase.** Grouped
   all rows by `cve_id` and kept CVEs with at least one JavaScript/TypeScript row and at
   least one C/C++ row. Out of 12,987 rows this matched exactly **one** CVE. There is no
   causal code boundary here -- it isn't one codebase's JS calling into its own C/C++ -- but
   it's a real CVE independently patched across language ecosystems, with the ground truth
   (CWE, both diffs, both commit hashes) already in the dataset. See `same_cve_cross_repo`.

2. **A single C/C++-language fix commit whose own `file_paths` also touch a `.js`/`.ts`
   file.** This is the "real transition" query -- one fix, one fixed CWE-labeled root
   cause, but its file list crosses the language boundary within the same commit. Matched
   25 rows (24 unique `cve_id`+`hash` pairs) out of 12,987. Split into categories below.

No new code was written to *detect* anything here -- this is corpus pulling and
categorization only, saved as `js_c_transition_corpus.json` for whatever's built against it
next.

## `js_c_transition_corpus.json` structure

Top-level keys, each a list of full CVEfixes rows (all fields preserved: `cve_id`, `hash`,
`repo_url`, `language`, `file_paths`, `cwe_id`, `cwe_name`, `commit_message`,
`cve_description`, `diff_stats`, `diff_with_context`, `vulnerable_code`, `fixed_code`):

- **`js_engine`** (16 rows) -- the JS *engine itself* is implemented in C/C++, and the
  `.js` file in the commit is a regression test that reproduces a memory-safety bug in the
  interpreter (the closest thing here to a real "JS input transitions into a C/C++ bug"):
  ChakraCore ×3, Facebook Hermes ×9, JerryScript ×1, nginx njs ×1, SerenityOS LibJS ×1.
  CWEs include CWE-119/125/787 (OOB read/write), CWE-416 (use-after-free), CWE-843/670
  (type confusion), CWE-476 (null deref), CWE-190 (int overflow), CWE-681 (incorrect
  conversion), CWE-755 (missing exception handling). Real, independently-callable-from-JS
  memory-safety bugs, each with a `.js` file in the same commit that triggers it.
- **`native_addon`** (4 rows) -- a JS package wrapping a C/C++ library via a native
  binding (the literal FFI-boundary case): MuhammaraJS (PDF library, C++ binding) ×3,
  `detect-character-encoding` (wraps ICU via `icuWrapper.cpp`) ×1.
- **`test_only`** (3 rows) -- the fix itself is entirely in C/C++; the `.js` file in the
  commit is an added/updated *test* proving the fix, not part of the vulnerability
  mechanism: ArangoDB (C++ REST handler + JS integration test), MongoDB (C++ shell history
  + JS test), Cockpit (C bridge + JS test). Kept separate rather than folded into
  `js_engine` -- these are C/C++-only bugs with incidental JS test coverage, a different
  shape from a JS-triggerable engine bug.
- **`excluded_noise`** (1 entry, metadata only -- not a usable row) -- `CVE-2021-4300`
  (Halcyon/Bitcoin-fork cryptocurrency wallet): `diff_with_context` was 14.9 MB, a
  generic full-repo bulk-import/mirror commit rather than a scoped fix. Dropped rather than
  silently kept as a 25th row; recorded here so the exclusion is visible, not hidden.
- **`same_cve_cross_repo`** (2 rows) -- `CVE-2023-48795`, the "Terrapin" SSH transport
  attack (CWE-354, improper integrity-check validation in the SSH Binary Packet Protocol's
  extension-negotiation/sequence-number handling). A protocol-level design flaw,
  independently patched in dozens of real SSH implementations; this dataset's rows happen
  to include a C fix (TeraTerm, `ttssh2/ttxssh/{kex,ssh}.c`) and a JavaScript fix
  (`mscdex/ssh2`, a widely-used Node.js SSH client, `lib/protocol/{Protocol,kex}.js`). Also
  present in the full row set (not extracted here): Go (`golang/crypto`), Java
  (`connectbot/sshlib`), Python (`jtesta/ssh-audit`) fixes for the same CVE.

## Honest caveats

- **Thin.** 16 + 4 + 3 + 2 = 25 usable rows total, out of 12,987 -- this property is rare
  in CVEfixes as collected. Don't expect this to scale the way the wolfSSL-based tracks did.
- **`js_engine`/`native_addon` are the closest matches to a real code-level "transition"**
  (untrusted JS reaching unchecked C/C++); `test_only` and `same_cve_cross_repo` are real
  CVEs but weaker matches for that framing (test-harness-only, and no shared codebase,
  respectively) -- kept because they're real and labeled, not because they're the best fit.
- **Not independently verified against real Joern/CPG facts.** Every other corpus under
  `study/` in this project was frozen against real exported CPG facts before being used to
  test a capability. This corpus is CVEfixes' own extracted `vulnerable_code`/`fixed_code`
  snippets and diffs as published -- useful for orientation and manual review, but treat
  the exact line ranges as CVEfixes' extraction, not something re-derived here.
