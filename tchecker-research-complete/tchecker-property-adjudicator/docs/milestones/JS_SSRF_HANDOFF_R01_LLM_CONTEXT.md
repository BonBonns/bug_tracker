# JS-SSRF-HANDOFF-R01 — browser source-to-LLM context

This milestone freezes the first WebExtension SSRF path that genuinely requires semantic
adjudication rather than closing deterministically. The controlled path is:

`runtime.onMessageExternal` payload → `message.url` → `rewriteTarget` →
`normalizeDestination` → `fetch`.

The unchanged SSRF property producer preserves the source as
`WEBEXT_EXTERNAL_MESSAGE_INPUT`, records both calls in path order, and returns `OPEN` because
neither call has established request-host semantics. This is intentional abstention: function
names are not treated as proof of restriction or safety.

During the live replay, `export_path_code_context.sc` exposed an integration defect. It read the
historical `path_transform_identity.tsv` filename, while the production producer and adjudicator
use `transform_identity.tsv`. The resulting LLM packet had the right identities but null source,
step, and sink code. The exporter now consumes the canonical table first and retains the
historical filename only as a compatibility fallback.

The frozen `llm_input_1.json` therefore includes the actual source expression and statement,
both ordered transform callsites and statements, the sink expression and statement, and a
host-only question that explicitly permits `UNKNOWN`. Any LLM response remains an advisory
semantic hint and never becomes an established static fact.

Run the self-contained regression gate:

```sh
python3 adjudicator/gate_webext_ssrf_llm_handoff.py
# WEBEXT_SSRF_LLM_HANDOFF=10/10
```

