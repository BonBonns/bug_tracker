# Adjudication record: `multi-spec-parser@0.4.2`, `PACKAGE_API_INPUT_REACHABLE` finding (surfaced by the frontend-coverage correction)

**Classification: `CONFIRMED_FALSE_POSITIVE_FOR_FROZEN_COMPLEXITY_MODEL`.**

Surfaced only after `frontend_coverage_check.py` recovered `dist/src/spec-validation.js` (and its
siblings) into the CPG -- jssrc2cpg's own default `dist`-folder exclusion had previously dropped
the package's entire real source (see `audit/FRONTEND_COVERAGE_FIX.md`,
`audit/REMAINING_SIX_NO_COMPLEXITY_CANDIDATE.md` section 4). **Unlike `fuse-napi` and `phplike`,
this record's reachability IS real and confirmed** -- the rejection here is on timing grounds
alone, the closest match to `phplike`'s own disposition type. As with both prior records, this one
is narrow and authorizes no general rule change.

## Identity

| Field | Value |
|---|---|
| Package | `multi-spec-parser` |
| Pinned version | `0.4.2` |
| Tarball integrity | sha1 `1556a0684599812af84e35a4c3fb118c1d3feb5f` (matches the npm registry's own published `dist.shasum`, re-fetched fresh and re-verified) |
| Canonical source path | `dist/src/spec-validation.js` (this package ships ONLY compiled `dist/` output -- there is no parallel `src/`; this IS the real, canonical, sole location of this code) |

## Regex node / site identity

| Field | Value |
|---|---|
| Declaration + sink call site | `dist/src/spec-validation.js:57`, inside `function isHtml(contentType, head)`:<br>`\|\| /<!doctype\s+html\|<html[\s>]/i.test(head);` |
| Tainted argument | `head` = `text.slice(0, MAX_VALIDATION_HEAD_BYTES)` (`MAX_VALIDATION_HEAD_BYTES = 4 * 1024`, `spec-validation.js:2`) -- itself derived from `text`, `validateSpecText(text, contentType)`'s own real parameter |
| Sink method | `RegExp.prototype.test`, frozen Stage 1 sink set |
| Pilot run's own sink node id (supporting evidence only, not the key) | `sink_node_id: 30064779210` |

### Persistent adjudication key

```
composite_key = redos-finding::multi-spec-parser@0.4.2::dist/src/spec-validation.js::e4d5e1ca4855a19f105444ccc3134d31501101174a7e06424cf4cd1b4521e3de::L57
key_hash       = 33292b821441f5594cb0396bd54e2c8f41113ee752ce71ec12bc2bdd78fa758e
```

## Exact regex fingerprint

Full literal, verbatim: `/<!doctype\s+html|<html[\s>]/i`

| Component | sha256 |
|---|---|
| Full literal (incl. `/`.../`i`) | `e4d5e1ca4855a19f105444ccc3134d31501101174a7e06424cf4cd1b4521e3de` |

Flags: `i` only.

## Why the frozen classifier flagged it (real, unmodified `classifyPattern`)

Via the alternation-branch rule (the SAME code path `phplike`'s finding used): the top-level
alternation `<!doctype\s+html|<html[\s>]` splits into branches `<!doctype\s+html` and
`<html[\s>]`. The first branch contains a quantifier (`\s+`) followed by more content in the same
branch (`html`) -- the frozen rule's own stated DANGEROUS shape. Real, unmodified match; not
disputed.

## Real, confirmed reachability (unlike the other two records reviewed alongside this one)

Traced directly against the real, fetched source, all the way to a public export:

```js
// dist/src/parse-spec.js:34-50
export async function fetchSpecText(url, signal) {
  validateSpecUrl(url);
  ...
  const res = await fetch(url, { headers: {...}, signal: requestSignal });
  ...
  const text = await readBoundedResponseText(res, MAX_SPEC_BYTES);
  assertValidSpecText(text, res.headers.get("content-type"));
  return text;
}
```
```js
// dist/src/spec-validation.js
export function validateSpecText(text, contentType = null) {
  ...
  const head = text.slice(0, MAX_VALIDATION_HEAD_BYTES);   // MAX_VALIDATION_HEAD_BYTES = 4096
  if (isHtml(contentType, head)) { ... }
  ...
}
function isHtml(contentType, head) {
  ...
  return Boolean(contentType && /text\/html/i.test(contentType)) ||
         /<!doctype\s+html|<html[\s>]/i.test(head);
}
```
`fetchSpecText(url)` is a real, exported public API function. A consumer calling it with a
`url` whose response is influenced by an untrusted party (the classic case: a service that lets a
user submit "the URL of the API spec to import") has that response's own content -- server- or
attacker-controlled -- fetched, then its first 4,096 characters checked by `isHtml()` against this
regex. **This is a genuine `EXPORTED_FUNCTION_PARAMETER` -> dangerous-regex path, correctly
established by the property's own current source model** -- not a resolution artifact like the
other two records reviewed alongside this one.

## Real timing measurement -- both adversarial and at the actual bounded size

| Field | Value |
|---|---|
| Script (complete, verbatim) | `multi_spec_parser_review/time_ishtml_regex.js` |
| Raw output | `multi_spec_parser_review/timing_output.txt` |
| Runtime | Node.js `v22.22.2`, V8 `12.4.254.21-node.39` (captured by the script itself) |
| Repetitions | 5 per input size; min/median/max reported |

**Adversarial, unbounded (characterizing the regex's own asymptotic behavior, independent of the
real 4,096-char cap)**:
- Single long whitespace run, no `html` terminator: n=80,000 (len 80,009) -> min 0.067ms / median
  0.070ms / max 0.161ms -- roughly linear (67x time for 80x input, not the ~6,400x a real O(n^2)
  blowup would show).
- Many repeated `"<!doctype"+50 spaces` blocks (paying the per-position backtrack cost at MANY
  starting points, not just one -- the stronger adversarial shape): n=16,000 blocks (len 944,000)
  -> min 1.464ms / median 1.474ms / max 2.802ms -- linear scaling confirmed up to ~944K characters.

**At the REAL bounded size** (`isHtml` never sees more than `text.slice(0, 4096)`): the worst-case
input that fits in that cap (`"<!doctype"` + spaces filling the remaining 4,087 characters) ->
min 0.004ms / median 0.004ms / max 0.009ms. **Negligible, regardless of the regex's own asymptotic
class.**

**Confirmed linear scaling at every measured size, in both the unbounded-adversarial and the
actually-reachable-in-practice bounded case. No quadratic or exponential growth.**

**Why, structurally** (offered as corroboration, not a substitute for the measurement above): the
same disjointness principle established in `phplike_review/ROOT_CAUSE_AND_DECISION.md` applies
here in an even stronger form -- the branch's quantified atom `\s` is bracketed by literals on
BOTH sides (`"doctype"` before, `"html"` after), and BOTH are character-class-disjoint from
whitespace. `\s+` is also not nested inside another quantified group (unlike the classic
catastrophic-backtracking shape `(x+)+`), which independently bounds any single starting
position's own backtracking cost. Whether CVE-2025-5892's own real `\s+:`-shaped vulnerable
pattern lacked one or both of these protections was not re-derived here; this record only
establishes THIS pattern's own real, measured behavior.

## Scope, precisely -- what this record does and does not certify

**Certifies**: for THIS pattern, THIS sink, THIS package version, with reachability real and
confirmed, direct timing measurement (both adversarial and at the actual bounded input size) shows
no quadratic or exponential blowup -- a genuine false positive under the frozen classifier's own
current rule, not a reachability artifact.

**Does NOT certify**: that this pattern is safe under a different regex engine, Node/V8 version,
or an UNBOUNDED input (real-world safety here rests partly on `MAX_VALIDATION_HEAD_BYTES = 4096`,
a fact specific to this package's own code, not the regex's own asymptotic behavior alone -- though
the adversarial-unbounded test above shows linear scaling even without that cap); that any other
`\s`-quantifier-with-disjoint-bookends pattern is safe in general (see the identical caveat in both
prior records); that the frontend-coverage correction should have somehow avoided recovering this
package's real source to prevent this finding from ever surfacing -- recovering real code the
pipeline was blind to, and then correctly rejecting a specific finding on real evidence, is exactly
the intended, disciplined outcome.

## Disposition

`MANUALLY_REJECTED` / `CONFIRMED_FALSE_POSITIVE_FOR_FROZEN_COMPLEXITY_MODEL`. No change was made
to `frontend_coverage_check.py`, `export_redos_npm_integ_r02.sc`, `classifyPattern`, or any
adapter/classifier/frontend-correction code as a result of this record. No general suppression
rule was added anywhere in this codebase.
