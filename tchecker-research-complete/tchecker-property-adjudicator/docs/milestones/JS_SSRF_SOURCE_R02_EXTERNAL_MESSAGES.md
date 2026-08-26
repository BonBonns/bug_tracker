# JS-SSRF-SOURCE-R02 — external WebExtension messages

This milestone bridges only the existing `WEBEXT_EXTERNAL_MESSAGE_INPUT` class into SSRF. The
adapter requires `PARAMETER`, `runtime.onMessageExternal`, the frozen derivation, and distinct
registration/parameter identities. The producer resolves exactly one payload parameter, follows
only exact `REF` edges, and adds a one-hop field read only when its base is that exact reference.
It never expands same-name identifiers, internal messages, siblings, or arbitrary descendants.

Live controlled replay emits two external `message.url -> fetch()` paths (inline and named) plus
the unchanged R01 tab-URL path. All are `ESTABLISHED`, contain no transforms, and require no LLM
hint. Navigation-only and internal-message controls do not emit. The real Mozilla add-on has one
source of each class but zero modeled network sinks and remains a no-finding holdout.

`gate_webext_external_ssrf_bridge.py` must report `WEBEXT_EXTERNAL_SSRF_BRIDGE=10/10`.
