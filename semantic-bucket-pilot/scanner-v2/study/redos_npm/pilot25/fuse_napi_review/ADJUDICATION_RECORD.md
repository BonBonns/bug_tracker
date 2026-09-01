# Adjudication record: `fuse-napi@2.3.1`, `PACKAGE_API_INPUT_REACHABLE` finding (surfaced by R02)

**Classification: `CONFIRMED_FALSE_POSITIVE_FOR_FROZEN_COMPLEXITY_MODEL`.**

Surfaced only after R02's capability 2 (object-literal shorthand export recognition) correctly
resolved `module.exports = { MACFUSE_URL, wrapMacFuseLoadError }` -- R01 had abstained on this
export shape entirely (`UNRESOLVED_RHS_SHAPE`), so no finding existed to review before this run.
As with `phplike`'s record, this one is narrow: it certifies this one site, this one pinned
version, evaluated two independent ways (real reachability AND real timing), and authorizes no
general rule change.

## Identity

| Field | Value |
|---|---|
| Package | `fuse-napi` |
| Pinned version | `2.3.1` |
| Tarball integrity | sha1 `ed1d0bef9bdb0ea2a09c4e5352b148fa8a52f938` (matches the npm registry's own published `dist.shasum` for this exact version, re-fetched fresh and re-verified, not assumed from the pilot run) |
| Canonical source path | `lib/macfuse.js` |
| File sha256 | `38d83b9e6f952a0b6e15bb74ea1564390e869db3328ea3c36fe661a5a0b889e7` |

## Regex node / site identity

| Field | Value |
|---|---|
| Declaration + sink call site | `lib/macfuse.js:5`, `if (!/(?:macfuse\|libfuse3(?:\.\d+)*\.dylib)/i.test(message)) return err` |
| Tainted argument | `message` = `err && err.message ? err.message : String(err)`, `wrapMacFuseLoadError`'s own real first parameter (`err`) |
| Sink method | `RegExp.prototype.test`, frozen Stage 1 sink set |
| Pilot run's own sink node id (supporting evidence only, not the key -- see below) | `sink_node_id: 30064777006` |

### Persistent adjudication key

```
composite_key = redos-finding::fuse-napi@2.3.1::lib/macfuse.js::3a8b322b856621a3d4f756b15ddcf93933022e6cb8037b24a4304a15a5903276::L5
key_hash       = eca1593f5ccf5e19bad93d2e4347072dfe6df287478e1b56f1a4197c279431cb
```
(`3a8b322b...` is this record's own full-literal regex fingerprint, below.)

## Exact regex fingerprint

Full literal, verbatim: `/(?:macfuse|libfuse3(?:\.\d+)*\.dylib)/i`

| Component | sha256 |
|---|---|
| Full literal (incl. `/`.../`i`) | `3a8b322b856621a3d4f756b15ddcf93933022e6cb8037b24a4304a15a5903276` |

Flags: `i` (case-insensitive). No `g`/`m`/`u` -- relevant to this record's own scope limits below.

## Why the frozen classifier flagged it (real, unmodified `classifyPattern`)

Via the `NESTED_QUANTIFIER` rule (a DIFFERENT code path from `phplike`'s alternation-branch rule):
`(?:\.\d+)*` -- the group `(?:\.\d+)` itself contains a quantifier (`\d+`), and the whole group is
followed by an outer `*`. This is exactly the frozen rule's own stated DANGEROUS shape
(`\([^()]*[+*][^()]*\)[+*]`). Real, unmodified match; not disputed.

## TWO independent grounds for rejection, both real, both directly verified

### Ground 1: no real external reachability (structural, source-level)

`wrapMacFuseLoadError` is called exactly **once** in the entire package, at `index.js:18`:
```js
try {
  binding = loadNativeBinding(__dirname)
} catch (err) {
  throw IS_OSX ? wrapMacFuseLoadError(err) : err
}
```
`err` here is the `catch` variable from `loadNativeBinding()`'s own internal failure (a Node
native-addon load error) -- never a value any external caller of `fuse-napi`'s public API
supplies. `index.js` never re-exports `wrapMacFuseLoadError` (confirmed: `grep` for the name
across the whole package finds only its own declaration, its one internal call site, and its
`module.exports` in `lib/macfuse.js` itself -- no re-export anywhere). `package.json`'s own real
`"exports"` map:
```json
"exports": { ".": {"types": "./index.d.ts", "require": "./index.js", "default": "./index.js"}, "./package.json": "./package.json" }
```
`"./lib/macfuse"` is not a listed subpath -- Node's own module resolution rejects
`require('fuse-napi/lib/macfuse')` outright once a package declares an `"exports"` map. **No
external caller can reach this function with a value they choose, under any real invocation
path.** This is the same real-world reachability argument
`COMPLEXITY_ONLY_CATEGORIZATION.md` already recorded for this exact site under R01
(`INTERNAL_UNDER_PACKAGE_API_MODEL`) -- confirmed unchanged by re-fetching and re-reading the
real, current source, not assumed to still hold.

### Ground 2: linear timing, confirmed independently of ground 1

Per the property's own established discipline, timing was measured directly regardless of the
reachability finding above (never stop at the first plausible explanation):

| Field | Value |
|---|---|
| Script (complete, verbatim) | `fuse_napi_review/time_macfuse_regex.js` |
| Raw output | `fuse_napi_review/timing_output.txt` |
| Runtime | Node.js `v22.22.2`, V8 `12.4.254.21-node.39` (captured by the script itself) |
| Repetitions | 5 per input size; min/median/max reported |
| Input family | `"libfuse3" + ".1".repeat(n)`, with and without a trailing non-matching character, adversarial against the `(?:\.\d+)*` nested quantifier |
| Sizes | 1,000 / 5,000 / 10,000 / 20,000 / 40,000 / 80,000 |

**Result: linear scaling at every measured size** -- n=80,000 (len 160,008): min 0.288ms /
median 0.385ms / max 1.808ms; no quadratic or exponential growth.

**Why, structurally**: the same disjointness principle `phplike_review/ROOT_CAUSE_AND_DECISION.md`
established applies here too, in its nested-quantifier form -- the group `(?:\.\d+)` is delimited
by a literal `.` that is character-class-disjoint from the quantified atom `\d`. A run of digits
can never itself contain a literal `.`, so each iteration's own boundary is unambiguous; there is
no cross-position compounding. (This is offered as a consistent, corroborating explanation for the
directly-measured result above, not as a substitute for it, and not as a new rule -- see "Scope,
precisely" below.)

## Scope, precisely -- what this record does and does not certify

**Certifies**: for THIS pattern, THIS sink, THIS package version -- both under the frozen
classifier's own DANGEROUS rule and under real adversarial timing -- the finding is a false
positive, on two independent grounds (unreachable in practice; linear even if it were reached).

**Does NOT certify**: that this pattern is safe under a different regex engine or Node/V8 version;
that any other regex with a `.`-delimited nested quantifier is safe in general (disjointness was
shown necessary here, not sufficient in general -- see `phplike_review/ADJUDICATION_RECORD.md`'s
own identical caveat); that R02's own object-literal-shorthand export recognition is wrong to have
surfaced this site at all -- resolving the export correctly and then rejecting the FINDING on
real-world grounds is exactly the intended, disciplined division of labor between the adapter and
manual review.

## Disposition

`MANUALLY_REJECTED` / `CONFIRMED_FALSE_POSITIVE_FOR_FROZEN_COMPLEXITY_MODEL`. No change was made
to `export_redos_npm_integ_r02.sc`, `classifyPattern`, or any adapter/classifier code as a result
of this record. No general suppression rule was added anywhere in this codebase.
