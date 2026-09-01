# Manual security review: node-snap7's 3 real Nan candidates (task 2 of 5, Nan-integration finalization)

Per direct instruction ("manually adjudicate the three node-snap7 candidates against the current
pinned source"), reviewed with the same rigor as `NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md` and
`TRANSITIVE_PROMOTIONS_MANUAL_REVIEW.md` -- the real published tarball fetched directly from the
npm registry, hash-verified against its own real `shasum` (`9402be15...`, npm registry metadata,
confirmed via `sha1sum -c`), and read directly. No assumption from the scanner's own output
taken on faith.

**Verdict: all 3 are REAL, genuine static candidates -- NOT false positives.** No
`adjudication_registry.py` entry is added; `reportable=True` is the correct, unrebutted state
for all three, and stays that way after this review.

## Source

`node-snap7@1.0.9`, refetched from `https://registry.npmjs.org/node-snap7/-/node-snap7-1.0.9.tgz`,
sha1 `9402be15ca318c0bba3267494c3ab8892163fd5b` (matches the registry's own recorded `shasum` --
the same tarball this session's Nan capability was designed and validated against, and the same
one the Nan replay's own re-fetch-and-verify step (`nan_replay_over_97.py`) independently
verifies via `tarball_sha256`/`source_tree_sha256`). C++ implementation:
`src/node_snap7_client.cpp`. JS entry point: `lib/node-snap7.js` (59 lines, read in full).

## 1. `ReadArea` -- `src/node_snap7_client.cpp:1255-1293`

```cpp
int amount = Nan::To<int32_t>(info[3]).FromJust();
int byteCount = s7client->GetByteCountFromWordLen(Nan::To<int32_t>(info[4]).FromJust());
int size = amount * byteCount;
char *bufferData = new char[size];
```

`info[3]` (`amount`) is validated ONLY as `IsInt32()` (`node_snap7_client.cpp:1261-1263`) -- any
int32 value, including negative, is accepted. `GetByteCountFromWordLen` (`:726-740`) is a real,
closed `switch` returning only `{0, 1, 2, 4}` regardless of its own input, so the WordLen axis is
bounded -- but `amount` itself is NOT. Two real, distinct consequences, both genuinely present:

- **Uncontrolled memory allocation (CWE-789):** an attacker/caller-controlled `amount` up to
  `INT32_MAX` (with `byteCount` up to 4) drives `new char[size]` toward multi-gigabyte
  allocations with zero library-level cap -- a real denial-of-service shape (allocation failure
  -> uncaught `std::bad_alloc` -> process termination, or a successful huge allocation ->
  memory-pressure DoS on the host process).
- **Integer overflow (CWE-190):** `amount * byteCount` is computed as a plain `int` product with
  no overflow check; a large `amount` with `byteCount == 4` can wrap. A NEGATIVE `amount` (a
  legal `int32`, only rejected by `IsInt32()`, not by sign) makes `size` negative, and `new
  char[size]` implicitly converts that negative `int` to a huge `size_t` -- the same failure-or-
  huge-allocation outcome as above, from the opposite direction.

**Reachability, confirmed by direct reading of `lib/node-snap7.js` in full (not merely
`grep`-checked):** `snap7.S7Client.prototype.DBRead = function (dbNumber, start, size, cb) {
return this.ReadArea(this.S7AreaDB, dbNumber, start, size, this.S7WLByte, cb); }`
(`lib/node-snap7.js:10-12`) forwards its OWN caller-supplied `size` argument directly into
`ReadArea`'s `info[3]` with **no validation at the JS layer either** -- same for `MBRead`,
`EBRead`, `ABRead`, `TMRead`, `CTRead` (lines 18-51, all six read wrappers share this exact
shape). This is the real `js_reachability_tier="confirmed_call"` evidence
`resource_guard_verdict_nan.py` itself traced (`this.readAreaLike(...)`-shaped chain in the
capability's own design notes) -- now independently confirmed by reading the call site itself:
any application calling `client.DBRead(0, 0, userControlledSize, cb)` (a completely ordinary,
documented usage pattern) with a size value derived from untrusted input has a real,
unmitigated vulnerability. The underlying vendored Snap7 core (`deps/snap7/src/core/
s7_micro_client.cpp:2761`, `TSnap7MicroClient::ReadArea`) performs no additional bounds check
either -- it forwards `Amount` into `Job.Amount` and hands off to `PerformOperation()`
unchanged.

**Verdict: TRUE. A real static candidate**, matching `NAN_NEWBUFFER_UNBOUNDED_ALLOCATION`'s own
contract exactly (JS-argument-controlled length, no detected upper-bound check). Not evaluated
further (per the contract's own disclaimer) is whether a specific downstream consequence is
*reachable at runtime* in a specific deployment -- that remains a real, disclosed limit, not a
gap this review closes.

## 2-3. `Upload` / `FullUpload` -- `src/node_snap7_client.cpp:1727-1750` / `:1760-1783`

```cpp
// Upload
char *bufferData = new char[Nan::To<int32_t>(info[2]).FromJust()];
int size = Nan::To<int32_t>(info[2]).FromJust();
...
// FullUpload
int size = Nan::To<int32_t>(info[2]).FromJust();
char *bufferData = new char[size];
```

Structurally IDENTICAL in both methods, and even more directly unbounded than `ReadArea`:
`info[2]` is used AS the allocation size with no multiplication and no per-component bound at
all -- only `IsInt32()` is checked (`:1728-1730`, `:1761-1763`). Same two consequences as
`ReadArea` (uncontrolled allocation; a negative `info[2]` sign-extends to a huge `size_t`).

**Reachability, confirmed by direct reading:** neither `Upload` nor `FullUpload` appears
anywhere in `lib/node-snap7.js` (confirmed: zero matches for either name across all 59 lines) --
the package's own bundled convenience wrapper never calls them. But `lib/node-snap7.js:8`
(`module.exports = snap7 = require('bindings')('node_snap7.node');`) unconditionally re-exports
the ENTIRE native binding object -- the same `target` the C++ side attaches `S7Client`'s
prototype methods onto via `Nan::SetPrototypeMethod` (confirmed structurally during capability
design, `NAN_CAPABILITY_FREEZE.md`). This means `Upload`/`FullUpload` are ordinary, standard,
directly-callable methods on `new snap7.S7Client()` for ANY consumer of the package -- e.g.
`client.Upload(blockType, blockNum, attackerControlledSize, cb)` -- exactly as reachable as any
method the wrapper DOES call, just not exercised by the package's own convenience layer. This is
the real, correctly-weaker `js_reachability_tier="exported_registration"` evidence (no confirmed
call observed, but the whole native module is unconditionally public) -- confirmed here by
reading the exact export statement, not merely trusting the scanner's own structural check.

Traced one level further than the scanner's own contract requires (its own disclaimer: "does
not trace the downstream native write call to confirm it actually happens"): the vendored Snap7
core's `Upload`/`FullUpload` (`deps/snap7/src/core/s7_micro_client.cpp`) receive the SAME `size`
value the N-API layer already used for its own `new char[size]` allocation (passed by pointer,
`&size`, and updated by the underlying protocol response) -- so the write into `bufferData`
stays within the allocation the same `size` value sized; the vulnerability is in the
UNBOUNDED ALLOCATION ITSELF (the DoS/uncontrolled-memory-allocation shape), not a secondary
out-of-bounds write beyond that allocation.

**Verdict: TRUE for both. Real static candidates**, correctly reported at the weaker
`exported_registration` tier (disclosed as such, never conflated with a confirmed call).

## Conclusion

All three findings represent a real, consistent, structural gap in node-snap7@1.0.9: JS-
controlled size parameters (`amount`, `info[2]`) flow directly into raw `new char[]`
allocations with zero upper-bound validation, both at the JS wrapper layer (where one exists)
and the native layer. `ReadArea` is reachable via a confirmed, ordinary call chain
(`DBRead`/`MBRead`/etc., none of which validate `size` either); `Upload`/`FullUpload` are
reachable via the package's own unconditional whole-module re-export. None is a scanner
artifact, a misattributed vendored-library issue, or an unreachable code path -- each is
exactly the shape `resource_contracts_nan.py`'s `NAN_NEWBUFFER_UNBOUNDED_ALLOCATION` contract
describes, confirmed against the real, current pinned source, not merely trusted from the
capability's own earlier structural design work.

**No `adjudication_registry.py` change is made.** The module's own real mechanism is a
one-way `CONFIRMED_FALSE_POSITIVE` veto (its own docstring: no "confirmed true positive"
status exists or is needed -- `reportable=True` with `adjudication_status="NOT_ADJUDICATED"`
already IS the correct terminal state for a real, unrebutted static candidate). This review's
outcome is documentary: a human security review has now looked at the real, current source for
all three findings and found no basis to suppress any of them.
