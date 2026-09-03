# Bounty-corpus scan 1 — Mozilla Firefox

`reportable=false`. No security impact, severity, exploitability or attacker
behaviour is assessed anywhere in this document. Nothing here is submitted.

## What was run

The frozen ESCAPE-PARITY-BOUNDARY layers (parser layer, then reachability
layer) were run once over each of two pinned commits of the same vendor tree,
with no change to the analyser between them.

| | pre-fix snapshot | live tree |
|---|---|---|
| repository | mozilla/gecko-dev | mozilla-firefox/firefox |
| commit | `5836a062` | `8a99ef92` |
| commit date | 2025-07-08 | 2026-09-01 |
| file set sha256 | `7fea6f9d…` | `8d44d240…` |
| C/C++ files analysed | 1,504 | 1,528 |
| C/C++ parse coverage | **1.00** | **1.00** |
| parser-layer records | 26 | 26 |
| **candidates** | **1** | **0** |

JavaScript was run separately over the live tree: 29 of 29 files covered
(1.00), 9 records, 0 candidates, 1 abstention
(`UNRESOLVED_REGEX_CONSTRUCTION` in `netwerk/base/ascii_pac_utils.js`).

Coverage is measured as a set intersection between the frozen manifest and
the FILE nodes in the CPG, not as a ratio of two independently-counted
populations. Every run above covered every file in its manifest.

The manifests were re-frozen once, and every number in this document comes
from the re-run. The first pass counted four tooling dotfiles
(`.prettierrc.js`, `.stylelintrc.js`, `.babel-eslint.rc.js`,
`security/.eslintrc.mjs`) as JavaScript source, which put JS coverage at
0.879 — the frontend had correctly ignored them. `freeze_target.py` now
excludes dotfile configs, named build scripts and generated bundles as a
uniform rule about what counts as library source, applied to every target
alike and decided before any finding was looked at. The C/C++ analysed file
set is byte-identical across the two freezes, and all three runs reproduced
their earlier classifications exactly; only the manifest hashes and the JS
coverage figure changed.

## The one candidate, and what happened to it

Pre-fix snapshot, `dom/base/MimeType.cpp`, `TMimeType::SplitMimetype`, line
256, `SINGLE_POSITION_INDEX_CHECK`:

```cpp
if (c == '\"' && (i == 0 || aMimeType[i - 1] != '\\')) {
  inQuotes = !inQuotes;
}
```

The boundary rule inspects exactly one preceding position, so it cannot
establish the parity of a consecutive escape run: `\\"` (an escaped
backslash followed by a real quote) is misread as an escaped quote.

Live tree, same file, same method, line 263, `PARITY_ESTABLISHED_IN_METHOD`:

```cpp
// https://fetch.spec.whatwg.org/#collect-an-http-quoted-string : a
// backslash only escapes inside a quoted string, and it consumes the code
// point that follows it, so an escaped backslash does not escape the next
// character.
if (inQuotes && c == '\\') {
  ++i;
} else if (c == '"') {
  inQuotes = !inQuotes;
}
```

The escape is now consumed as a **pair**, which is precisely the rule this
property tests for, and the analyser clears the site.

The two runs produce **identical site sets** — no site appears in one and not
the other — with exactly one classification flip, at the line that changed.

## Mozilla fixed this independently, before this scan

From the public mozilla-central file log for `dom/base/MimeType.cpp`
(`hg-edge.mozilla.org`), and the raw changeset:

- changeset `8e738b555997f8685d6b9fbbe3eba1570edfe868`
- **Bug 2063814 — "Handle \ correctly in SplitMimetype"**, r=necko-reviewers,kershaw
- author Valentin Gosu, created 2026-08-19 13:21 UTC, pushed 2026-08-19 21:08 UTC
- Differential Revision D319097
- followed same day by Bug 2064026, "Check if iterator has reached the end of
  the string"

The published diff is exactly the change above. Its comment cites the same
WHATWG Fetch clause — *collect an HTTP quoted string* — that this property's
earlier analysis identified as the governing rule, reached independently from
the specification text rather than from the fix.

So the deviation was found and corrected by Mozilla roughly two weeks before
this scan ran. This was not reported by us and is not ours to claim.

Observation recorded without interpretation: the Bugzilla REST API returns
`code 102, "You are not authorized to access bug …"` for both 2063814 and
2064026. That is what the API returned; no inference about why is drawn here,
and none should be read into it.

## Consequence for the standing instruction

The standing instruction was: *do not submit the current Mozilla
`MimeType::SplitMimetype` result; it establishes parser disagreement, not
reachable security impact.* That still holds, and it now holds for a second,
simpler reason: **the code is already fixed upstream**, by the vendor, from
their own independent discovery. There is nothing to report.

The frozen Mozilla policy is consistent with this on its own terms — it asks
for a security bug demonstrating an unauthorized action or restricted-
information access, a reproducible test case, and typically a sec-high or
sec-critical rating. None of that was established here, and the underlying
code no longer carries the rule in any case.

## What this run is actually good for

It is a validation result, and a strong one, on live vendor code rather than
on fixtures:

- **True positive on real pre-fix code.** The analyser flagged the exact rule
  that the vendor's own engineers later rewrote, at the exact line.
- **True negative on real post-fix code.** The analyser clears the corrected
  form rather than continuing to flag the method — the failure mode a
  shape-matching detector would have.
- **Independent agreement on the governing rule.** The property derived the
  pairing requirement from the WHATWG text; the vendor's fix comment cites
  the same clause.
- **A clean 1→0 differential** across two commits of the same tree with an
  unchanged analyser and full parse coverage on both sides.

This is the same before/after structure as the historical plugin
differential, but on a live browser codebase and with the fix authored by the
vendor rather than reconstructed by us.

## Limits of this run, stated plainly

- **The chain layer still says `NOT_ESTABLISHED`** even on the pre-fix
  snapshot: `NO_DELAYED_SOURCE_REACHES_PARSER`,
  `NO_STRUCTURED_TEXT_CONSUMER_REACHED`. The reachability model looks for
  stored-text sources feeding a transform; an HTTP response header reaching a
  MIME parser is not a shape it models. This gap was recorded earlier and is
  unchanged.
- **The JavaScript surface is thin.** Only 33 executable JS files fall inside
  the frozen sparse paths, which were chosen around C/C++ parser directories.
  Firefox's substantial JS lives in `toolkit/`, `browser/` and `devtools/`,
  none of which is in this surface. The JS result says nothing about them.
- **The frozen surface is a slice**, not the tree: MIME, HTTP, cookies, DNS,
  websocket, data URLs, HTML parsing, certificate handling and string
  handling. Vendored and test trees are excluded, on the program's own terms.
- **Nothing was executed.** No Firefox build was run; every statement above
  is about source text, CPG structure, and published vendor artifacts.

## Pipeline defect found and fixed during this run

`run_target.py` originally passed relative paths to Joern. Joern resolves a
relative path against **its own install directory**, so producer facts were
being written into the Joern tree while the reducer read an empty directory
here. The first JavaScript run reported `ANALYZED` with 9 records only because
a manual run had happened to leave facts at the path the reducer read — a
result that looked clean and was not honestly produced. All paths handed to
Joern are now absolute, the stray directory under the Joern install was
removed, and every run in this document was produced after that fix.

Separately, a Joern script invocation can exit 0 without running the script
body when its workspace project is being re-materialised. The runner now
decides success on the **existence of the output artifact**, not the exit
status, retries up to three times, and records the attempt count in the run
record. Both fixes exist so an infrastructure condition can never be
presented as a clean negative — which is the same reason parse coverage is
measured at all.
