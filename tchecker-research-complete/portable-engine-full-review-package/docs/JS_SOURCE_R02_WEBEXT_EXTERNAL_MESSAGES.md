# JS-SOURCE-R02 — WebExtension external-message payloads

This milestone adds one browser-specific source class without changing any
vulnerability-class sink rule, property rule, or LLM hint contract.

## Promoted invariant

For a direct registration of either form:

```js
browser.runtime.onMessageExternal.addListener(callback)
chrome.runtime.onMessageExternal.addListener(callback)
```

when `callback` resolves to exactly one inline function or to one function-valued
local definition, callback parameter 0 is a
`WEBEXT_EXTERNAL_MESSAGE_INPUT` source. The core reports it as **MAY**, never
EXACT, because the same function may also be called normally.

The source fact is parameter-targeted and records the registration call, callback
argument and callback parameter node IDs. The core consumes `origin_kind`
explicitly; it no longer collapses every source fact into `FILE_INPUT`.

## Class-separation ceiling

The following are deliberately not part of this class:

- `runtime.onMessage` (same-extension messaging has a different trust model);
- `tabs.onUpdated` and other browser event metadata;
- `browser.test.onMessage` test-harness traffic;
- `port.onMessage`, including native messaging;
- sender metadata and `tabs.*` URL fields;
- aliased runtime objects or multiply-defined callback locals.

Those shapes abstain until each has its own positive, negative and contamination
controls. A broad bare-name rule for `addListener` is forbidden.

## Scanner and hint boundary

`scan_repo.py` and `scanner/provenance_scan.py` now both pass the generated
`.source.json` sidecar. The scanner preserves `origins` and `mayOrigins` in text
and JSON output. This affects neutral source provenance only. Class-specific sink
profiles still decide whether a source reaches an SSRF, DOM-XSS, command-injection
or other candidate, and the LLM packet remains a request for a semantic hint—not
an established fact.

## Controls

- `CORE_S05=7/7`: parameter target loading, MAY semantics, origin-kind purity,
  unregistered-parameter negative, missing-target rejection and unknown-kind
  fail-closed behavior.
- `JS_SOURCE_R02_CONTROLS=10/10`: browser/chrome positives; internal-message,
  tabs, test-harness, prefix-collision and ambiguous-handler negatives.
- `PROVENANCE_SCAN_CONTROLS=4/4`: sidecar routing and origin preservation.
- Real cached-CPG A/B: both inline and named external-message `fetch(message.url)`
  carry `mayOrigins=[WEBEXT_EXTERNAL_MESSAGE_INPUT@runtime.onMessageExternal]`;
  local-resource fetch and `tabs.onUpdated` carry no such origin.

## Real add-on holdout

Mozilla Multi-Account Containers' real `messageHandler.js` was scanned as a
one-file bounded holdout. Selection was 1 discovered / 1 eligible / 1 parsed.
The direct external-message callback produced exactly one parameter-targeted
WebExtension source. Its `message.url` reaches
`assignManager.storageArea.get(message.url)` as:

```text
resolution=AMBIGUOUS may=[0]
mayOrigins=[WEBEXT_EXTERNAL_MESSAGE_INPUT@runtime.onMessageExternal]
```

The separate `browser.management.get(sender.id)` call reports `may=[1]` and no
WebExtension payload origin. The permission guard on `sender.id` is retained as
code context; it is not mislabelled as sanitizing `message.url`. No security sink
profile classifies storage `get`, so no vulnerability verdict or LLM packet is
created from this neutral provenance observation.
