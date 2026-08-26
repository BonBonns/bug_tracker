# JS-SOURCE-R03 — use-scoped WebExtension tab URL inputs

## Outcome

TChecker now preserves URL metadata read from direct WebExtension tab event
callbacks as the distinct MAY origin `WEBEXT_TAB_URL_INPUT`. The source is
attached to one concrete keyed-state read, never to the whole callback object.
That is the class-separation boundary: URL reads may carry browser/navigation
input, while IDs, status, cookie-store metadata and sibling properties do not.

This matches Mozilla's API contract. `tabs.onCreated` supplies one `tabs.Tab`
argument, though its URL may still be the initial value when the event fires.
`tabs.onUpdated` supplies `(tabId, changeInfo, tab)`; `changeInfo.url` is optional
and denotes a changed URL, while `tab` is the tab's new state:

- https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/tabs/onCreated
- https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/tabs/onUpdated

## Promoted recognition

Only these direct registration shapes are eligible:

- `browser|chrome.tabs.onCreated.addListener(callback)`:
  parameter 0, direct literal field read `url`;
- `browser|chrome.tabs.onUpdated.addListener(callback)`:
  parameter 1 direct literal field read `url` (`changeInfo.url`), and parameter 2
  direct literal field read `url` (`tab.url`).

The callback must be an inline function or a local with exactly one
function-valued definition. Each emitted `SourceOriginFact` has:

```text
target_kind=STATE_READ
target_local_id=<the actual StateReadFact id>
origin_kind=WEBEXT_TAB_URL_INPUT
derivation.rule=JS_WEBEXT_TAB_URL_SOURCE
```

The `target_local_id` name is retained for source-schema 0.1 compatibility; for
`STATE_READ`, its documented meaning is the target fact ID.

## Portable-core semantics

The core has no browser API names. It consumes the frontend's origin kind and
targets the specified read. A registered callback can also be called normally,
so the result is `AMBIGUOUS`: the ordinary formal-parameter position and the tab
URL origin are both MAY alternatives. It is never upgraded to EXACT.

A definite write to the same state slot is evaluated by the existing keyed-state
rules and kills the event origin. Parent replacement and dynamic-path cases keep
their existing abstention ceilings.

## Contamination ceilings

The recognizer does not label:

- `tab.id`, `tab.cookieStoreId`, `changeInfo.status`, or any sibling field;
- nested `tab.profile.url`-shaped reads;
- `runtime.onMessage`, `runtime.onMessageExternal`, or other event families;
- `browser.test`, prefix collisions, or aliased API namespaces;
- callback properties such as `this.handler`, multiply-defined locals, or
  otherwise unresolved callback identities;
- URLs returned later by `tabs.get()` or any async continuation.

Those are separate source contracts, not spelling variants of this one.

## Scanner, vulnerability classes, hints and LLM handoff

This milestone changes only source provenance. It does not add a sink, redefine
SSRF or another vulnerability class, change property effects, reinterpret a
sanitizer, or modify semantic hints. The portable scanner receives the new origin
at an existing sink observation point.

The source sidecar is **not yet an automatic input** to the separate
`tchecker-property-adjudicator` producer/LLM-packet pipeline. Therefore this
milestone must not be described as producing an SSRF candidate or LLM packet.
A future bridge must be gated as a separate, class-specific expansion: it may
admit this origin to the existing SSRF source-to-sink path, but it must reuse the
current SSRF property obligations and hint contract unchanged.

On the controlled real-Joern corpus, the portable scanner's `fetch(tab.url)`
observation under `tabs.onUpdated` produces:

```text
resolution=AMBIGUOUS may=[2]
mayOrigins=[WEBEXT_TAB_URL_INPUT@tabs.onUpdated.tab.url]
```

Existing external-message fetches remain `WEBEXT_EXTERNAL_MESSAGE_INPUT`; the
extension-local fetch remains origin-free. This is provenance evidence, not a
vulnerability verdict.

## Real Mozilla add-on holdout

On Mozilla's Multi-Account Containers `messageHandler.js`, the unchanged Joern
facts yield exactly one R03 source: the real `tabs.onCreated` callback's
`tab.url` read. The nearby `tab.cookieStoreId` reads and the separately registered
`tabs.onUpdated` callback's `changeInfo.status` read remain outside this origin
class. That file contains no security sink consuming this URL, and the adjudicator
does not yet consume the portable source sidecar, so the correct result is
provenance evidence without a vulnerability/LLM packet.

## Gates

- `CORE-S06=6/6`: MAY semantics, ordinary-call alternative, origin-kind purity,
  sibling separation, same-slot overwrite killing, strict loader support.
- `JS_SOURCE_R03_CONTROLS=11/11`: positive, negative, named-handler,
  ambiguous-handler, nested-path and namespace contamination controls.
- Existing JS-SOURCE-R02, origin-purity, scanner and vulnerability gates replay
  unchanged.
