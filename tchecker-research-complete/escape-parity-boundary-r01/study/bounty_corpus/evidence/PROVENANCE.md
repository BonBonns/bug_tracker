# Primary-source evidence for the Mozilla scan

Everything here was fetched from a published vendor source. No system was
tested, no payload was constructed, and no security assessment is made.

## `bug2063814_changeset_8e738b55.diff`

The raw Mercurial changeset that corrected `TMimeType::SplitMimetype`.

- source: `https://hg-edge.mozilla.org/mozilla-central/raw-rev/8e738b555997f8685d6b9fbbe3eba1570edfe868`
  (`hg.mozilla.org` 302-redirects to `hg-edge.mozilla.org`)
- fetched: 2026-09-02 UTC, HTTP 200, 1,457 bytes
- sha256: `7204caba570e96f9dc188caaf381719c142f8d39b2e65aa2fa617297b58690bc`
- author: Valentin Gosu, dated 2026-08-19 13:21 UTC
- commit message: `Bug 2063814 - Handle \ correctly in SplitMimetype r=necko-reviewers,kershaw`
- Differential Revision: D319097

## File log

`https://hg-edge.mozilla.org/mozilla-central/log/tip/dom/base/MimeType.cpp`
(HTTP 200) lists, most recent first:

| changeset | created | summary |
|---|---|---|
| `3f1e8298` | 2026-08-19 13:51 | Bug 2064026 — Check if iterator has reached the end of the string |
| `8e738b55` | 2026-08-19 13:21 | Bug 2063814 — Handle \ correctly in SplitMimetype |
| `0967d9f1` | 2026-03-16 | Bug 2023419 — Remove Emacs/Vim modelines from dom/ |
| `a4893687` | 2026-02-13 | Bug 2003766 — header array holds last contentType value |
| `5119c175` | 2025-08-05 | Bug 1976665 — Sort headers in dom/ |

The 2025-07-08 snapshot analysed here predates every entry above `5119c175`,
which is consistent with the pre-fix source it contains.

## Bugzilla

`https://bugzilla.mozilla.org/rest/bug/2063814` and `.../2064026` both return:

```
{"code": 102, "error": true,
 "message": "You are not authorized to access bug ... To see this bug, you
             must first log in to an account with the appropriate permissions."}
```

Recorded as observed. No inference is drawn from it here.

## Specification

`https://fetch.spec.whatwg.org/#collect-an-http-quoted-string` — the clause
the vendor's fix comment cites, and the clause this property's analysis
identified independently as governing the boundary rule.
