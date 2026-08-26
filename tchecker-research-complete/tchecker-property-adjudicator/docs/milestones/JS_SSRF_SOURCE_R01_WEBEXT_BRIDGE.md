# JS-SSRF-SOURCE-R01 — bounded WebExtension URL bridge

## Scope

This milestone connects one already-established portable provenance class to one
TChecker property pipeline.  It does not add a sink, property rule, semantic hint,
or new source recognizer.

The accepted source class is `WEBEXT_TAB_URL_INPUT`, produced by JS-SOURCE-R03 for
the individual `url` state read at exactly one of these locations:

- `tabs.onCreated.tab.url`
- `tabs.onUpdated.changeInfo.url`
- `tabs.onUpdated.tab.url`

The adapter consumes `portable-source-facts/0.1`, checks that the fact ID is the
target local ID, requires `STATE_READ` and `JS_WEBEXT_TAB_URL_SOURCE`, rejects
duplicates, and writes a four-column bridge TSV. Other origin families are ignored
so vulnerability classes remain separate.

`export_ssrf_integ.sc` accepts that TSV through the optional `browserSourceTsv`
parameter. It revalidates the class and location, resolves the ID to exactly one CPG
expression, requires the concrete expression to be a `.url` field access, and adds
only that expression to the existing SSRF source pool. Existing Express/Rocket.Chat
sources and all sink/property/hint logic remain unchanged.

## Measured behavior

A live Joern run over the controlled WebExtension corpus emitted exactly one
candidate: `tabs.onUpdated`'s `tab.url` reaching `fetch(tab.url)`. The property was
`ESTABLISHED`, with no transform chain and no invented edge. The adjudicator therefore
closed deterministically in zero hint rounds and emitted no LLM packet.

A live run over the real Mozilla MAC add-on recognized one bridged source but found
zero SSRF sinks, so it emitted no candidate and no LLM packet. This negative result is
preserved alongside the controlled result in `fixtures/webext_ssrf_bridge/`.

## Gates

Run:

    python3 adjudicator/test_portable_ssrf_source_bridge.py
    python3 adjudicator/gate_webext_ssrf_bridge.py

Expected results are `PORTABLE_SSRF_BRIDGE_CONTROLS=9/9` and
`WEBEXT_SSRF_BRIDGE=9/9`.
