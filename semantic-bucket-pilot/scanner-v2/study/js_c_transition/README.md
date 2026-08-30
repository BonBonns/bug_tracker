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

## Measurement: does the write-property scanner (`oob_runtime_capacity_v2.py`) catch any
## of these? (`check_js_c_transition.py`, 1/1)

Of the 25 usable rows, exactly 2 carry a CWE in the scanner's write family
(`{787, 122, 120, 121, 124, 680, 805, 806}`, per `postcutoff_freeze.py`'s `WRITE_CWE`):
`CVE-2020-1896` and `CVE-2023-23556`, both Facebook Hermes, both CWE-787. Both were
inspected against real pre-fix source (fetched at the exact parent commit of each fix);
only one turned out to be a real, in-scope test.

**`CVE-2023-23556` — the CWE label doesn't point at a write.** The official NVD text says
"An error in BigInt conversion to Number ... due to an out-of-bound write," which maps to
this fix commit's `BigIntSupport.cpp` change: `toDouble()` now clamps a malformed NaN
payload coming out of `llvh::APInt::roundToDouble()`. But `roundToDouble()` itself --
where the actual out-of-bounds write would have to live -- is vendored LLVM code, not
touched by this diff at all; the fix is a downstream mitigation, not the buggy write site.
(The same commit hash also carries 2 unrelated fixes bundled into one "re-sync" commit --
an `Array.cpp` descriptor-computation reordering, and the real `CVE-2023-24833` UAF fix in
`Operations.cpp` -- neither of which is CWE-787-shaped either.) Not run through the
scanner: there is no write statement in the diff to run it against.

**`CVE-2020-1896` — a real write-capacity bug, but not a shape the scanner models.** Real
pre-fix `hermesBuiltinApply` (`lib/VM/JSLib/HermesBuiltin.cpp`, revision `82f0f971`, the
direct parent of the fix commit) computes `len` from a JS array's `.length` (fully
attacker-controlled from JS), constructs a `ScopedNativeCallFrame` that allocates `len`
register slots on Hermes's bounded native register stack -- and on overflow, that
constructor sets `overflowed_` and leaves the frame **unallocated**, requiring the caller
to check `overflowed()` before touching it. `hermesBuiltinApply` doesn't check: it writes
`len` `HermesValue`s into `newFrame->getArgRef(i)` in an unconditional loop. Extracted the
real function into a minimal fixture (real code verbatim; every referenced type stubbed
with real member/method signatures pulled from `Runtime.h` at the same revision -- see
`raw_case_hermes_apply/fixture_source.cpp`), ran it through the real pipeline (`c2cpg.sh`
→ `export_c_cpp_facts_v03.sc` → `normalize_c_cpp_facts_v03.py`, real Joern v4.0.608, clean
parse, no warnings), and ran `analyze_operations_v2` against the resulting `program.json`.

**Result: zero operations recorded — not "judged safe," never even considered a
candidate.** `oob_runtime_capacity_v2`'s operation extraction (both v1 and v2) is entirely
keyed on `CALLEE_CONTRACTS`, a fixed dict of 7 recognized callee names (`memcpy`,
`memmove`, `wmemcpy`, `PORT_Memcpy`, `PORT_Memmove`, `PORT_Memset`, `HMAC_Finish`) plus
capability 1's own direct-indexed-array-write pattern. `newFrame->getArgRef(i) = ...` is
neither: it's an assignment through a C++ operator-> and a method call on a custom RAII
class, and the "capacity" being violated is that class's own constructor-time allocation
logic, not a declared fixed array or a call to a name in that list. Confirmed this isn't a
parse/pipeline failure -- Joern's own reaching-def pass log shows `hermesBuiltinApply` was
fully parsed and analyzed (131 reaching-definition facts recorded for it) -- the function
was seen in full; the scanner's write-recognition vocabulary just has no entry for this
shape. Pinned as `check_js_c_transition.py`'s one assertion: an honest, evidenced coverage
gap, not a scanner bug and not a claim the bug was caught.

This is a **5th write-representation shape**, distinct from all 4 in `CAPABILITY_PLAN.md`
(fixed stack array w/ direct index; transparent memcpy-family wrapper; pointer-walk
`*p++=`/`p[k]=`; external decoder contract) -- a bounded-capacity RAII resource whose
allocation can fail, gated behind a caller-checked flag, with the unsafe write coming from
skipping that check. Not attempted here; would need its own capability (in the shape of
Capability 1's own missing-unlock-before-return pattern from `THREAD_SAFETY_R01.md`, more
than the CWE-787 write-property track's existing 4).

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
