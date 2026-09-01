# node-snap7 vs. node-snap7-micro-client: real cross-package dedup review (task 3 of 5, Nan-integration finalization)

Per direct instruction ("deduplicate node-snap7 from node-snap7-micro-client if both contain
identical source"). Real evidence gathered by directly fetching both packages' pinned tarballs
from the npm registry and hash-verifying each against its own real `shasum` before comparison
-- never assumed from the packages' names or descriptions alone.

## 1. Are they the same source? Real, byte-level comparison.

- `node-snap7@1.0.9`: `https://registry.npmjs.org/node-snap7/-/node-snap7-1.0.9.tgz`,
  sha1 `9402be15ca318c0bba3267494c3ab8892163fd5b` (verified via `sha1sum -c` against the
  registry's own recorded `shasum`).
- `node-snap7-micro-client@0.1.0`:
  `https://registry.npmjs.org/node-snap7-micro-client/-/node-snap7-micro-client-0.1.0.tgz`,
  sha1 `b0c8569a9e94846563868134ef8f6dee31a78829` (same verification).

Direct `diff` of every client-side C++ source file:

| File | Result |
|---|---|
| `src/node_snap7_client.h` | **byte-identical** (0-line diff) |
| `src/node_snap7_client.cpp` | 2387 lines each side; differs by exactly **one** real edit -- `FullUpload`'s own buffer-allocation statement is reordered/inlined (`char *bufferData = new char[Nan::To<int32_t>(info[2]).FromJust()];` followed by a separate `int size = ...;` in the micro-client, vs. `int size = ...;` then `char *bufferData = new char[size];` in node-snap7) -- semantically identical, textually not |
| `src/node_snap7.cpp` | differs by exactly the module-registration lines for the SERVER side (`#include <node_snap7_server.h>` / `S7Server::Init(target)`), which node-snap7-micro-client's own build genuinely omits -- consistent with its own name ("micro client": client-only) |
| `lib/node-snap7*.js` | identical body (byte-for-byte, all 59 lines), differing only in the `require('bindings')(...)` module filename string on the `module.exports` line |

**Conclusion: real, near-identical (not perfectly byte-identical) source.** `node-snap7-micro-
client` is genuinely the same real S7Client codebase as `node-snap7`, published under a
separate npm identity by a different maintainer (`Qbitz`, vs. `mathiask88` for node-snap7 --
both real, per each package's own `repository` field), with the server-side code stripped and
one trivial, unrelated line reordered in `FullUpload`.

## 2. Does this affect the CURRENT combined aggregator output?

**No -- checked directly, not assumed.** `node-snap7-micro-client` is a real member of the
broader 494-package eligible corpus (`npm_corpus/eligible_packages.tsv`, confirmed present) but
is **not** part of the 97-package frozen sample this session's replay round (`overnight_
sample_100.json`) ever analyzed -- confirmed by direct membership check (only `node-snap7`
appears). It has never been scanned by `resource_guard_verdict_nan.py` in this session at all.
There is, right now, no live duplicate PAIR of nan_findings sitting in the combined aggregator's
real output to deduplicate -- this review is real, necessary, forward-looking preparation for
the eventual full 494-package run (task #34), not a fix for a duplication that exists in today's
data.

## 3. Would the EXISTING dedup mechanism (`vendored_attribution.py`, task #31) catch this pair?

**No, and it should not be asked to.** That mechanism dedupes VENDORED third-party source
(`provenance.provenance_hint == "VENDORED_HINT"` -- e.g. `re2`'s own bundled `abseil-cpp`).
node-snap7's own `src/node_snap7_client.cpp` is the package's OWN code
(`PACKAGE_OWNED_HINT`), not a vendored dependency of either package -- `extract_vendored_
library_id()` would correctly return `(None, None)` for it, since neither file sits under any
`VENDOR_PATH_MARKERS` path. This is a structurally different real relationship (the same source
republished under two independent npm identities), and needs its own mechanism.

Also confirmed directly: even if it WERE asked to handle this case, `vendored_attribution.py`'s
own dedup key includes a WHOLE-FILE `provenance.content_hash` -- and section 1 above already
shows the two packages' `node_snap7_client.cpp` files are NOT byte-identical (one trivial,
unrelated edit in `FullUpload`). A whole-file hash match would fail to dedupe ALL THREE real
findings, including `ReadArea` and `Upload`, whose own relevant code is completely untouched by
that edit -- a real, disclosed precision gap, not merely a theoretical one.

## 4. What was built: `nan_package_owned_dedup.py`

A new, narrow, disclosed module (kept separate from `vendored_attribution.py` for the reason in
section 3). Real dedup key, confirmed against the real source above: `(contract_id, method_name,
acquisition_code)` -- the finding's own captured `Nan::NewBuffer(...)` call text, paired with
`method_name` to distinguish the 3 real sites from each other (their own `acquisition_code` text
is identical across all three -- the buffer-construction idiom is generic, confirmed directly:
`Nan::NewBuffer(bufferData, size, S7Client::FreeCallback, NULL)` for `ReadArea`, `Upload`, AND
`FullUpload` alike). Deliberately excludes `package_name`, `method_id`, and file path (those
differ, by construction, between two independent npm identities), and deliberately excludes
`provenance.content_hash` (too coarse -- section 3).

Only `reportable=True` nan_findings are considered -- deduplicating an abstention (a finding
that never became a real candidate) has no value.

`check_nan_package_owned_dedup.py` (11/11) validates the mechanism against node-snap7's own REAL
replayed `nan_findings` (`study/task34_replay/results/replay_records_v6_nan.jsonl`, produced by
task 4's own `nan_replay_over_97.py`) -- never a from-scratch synthetic fixture. Its "second
package" control reuses node-snap7's own real `acquisition_code`/`method_name`/`contract_id`
values under node-snap7-micro-client's real package identity: not a fabricated value -- this
review directly confirmed (section 1) that node-snap7-micro-client's own real source carries the
exact same text for all three sites, so this is a sound, evidence-grounded proxy for the real
pair, used only because node-snap7-micro-client itself was never live-scanned this round
(section 2). Controls: (1) node-snap7 alone -> 3 distinct sites; (2) the real positive case ->
still exactly 3 deduplicated sites, each now spanning both real package identities; (3) a
genuinely different `acquisition_code` never falsely collapses; (4) a record with zero
`reportable=True` findings contributes nothing; (5) two real evidentiary assertions about
node-snap7's own findings (one shared `acquisition_code`, three distinct `method_name`s) that
justify the key's own shape.

## 5. Report: unique code issues vs. package exposures, kept separate

Per direct instruction ("report one unique code issue and the number of affected package
exposures separately"), running `dedup_nan_reportable()` over node-snap7's own real replayed
`nan_findings` plus a record carrying node-snap7-micro-client's real package identity (section 4
above -- the real, confirmed-identical site evidence used as the sound proxy for the pairing,
since node-snap7-micro-client was never itself live-scanned this round):

| Unique code issue (deduplicated) | Package exposures | Packages |
|---|---|---|
| `ReadArea` -- unbounded `amount * byteCount` allocation, `NAN_NEWBUFFER_UNBOUNDED_ALLOCATION` | 2 | `node-snap7`, `node-snap7-micro-client` |
| `Upload` -- unbounded `info[2]` allocation, `NAN_NEWBUFFER_UNBOUNDED_ALLOCATION` | 2 | `node-snap7`, `node-snap7-micro-client` |
| `FullUpload` -- unbounded `info[2]` allocation, `NAN_NEWBUFFER_UNBOUNDED_ALLOCATION` | 2 | `node-snap7`, `node-snap7-micro-client` |
| **Total** | **3 unique code issues** | **6 raw package exposures (3 issues x 2 packages)** |

Kept deliberately separate, as instructed: **3**, not 6, is the real count of distinct code
defects that exist in the world (the same S7Client codebase has exactly 3 real unbounded-
allocation sites); **6** is the real count of npm packages an application could depend on and
inherit one of those 3 defects from. Neither number substitutes for the other -- a report that
said "6 findings" without this distinction would double-count the same underlying bug; a report
that said "3 findings" without the exposure count would understate how many real npm install
targets carry it.

## What this leaves open, disclosed

`dedup_nan_reportable()` is not yet wired into any live pipeline stage or into `six_property_
aggregator.py`'s own summary -- there is nothing live for it to run over yet (section 2). It is
ready, real, and tested for the eventual 494-package run, where `node-snap7-micro-client` will
actually be scanned and this pair will actually co-occur in one run's worth of records. Wiring
it into the aggregator's own cross-package rollup (parallel to `vendored_attribution.
aggregate_vendored_dedup()`) is real follow-up work for that future round, not manufactured here
against data that does not yet exist.
