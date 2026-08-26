# JS-PROP-R03 — canonical nested state location

## Scope

This milestone extends the existing keyed-state provenance ceiling to a narrowly
defined nested-property class. It does not add sources, sinks, vulnerability
classes, framework profiles, or LLM hints.

State facts 0.4 retain the frontend receiver reference and add a canonical
receiver location:

```text
root binding + ordered selector path
```

For `input.profile.url`, the `url` access has root `input` and receiver path
`[profile]`. This fixes a measured identity gap: Joern emits different accessor
CALL IDs for a read and write of the same source-level path.

## Propagation ceiling

Nested propagation is permitted only when:

- the final key and every receiver-path component are literal;
- the canonical root is a `PARAMETER` or `LOCAL`;
- no write may replace a parent path; and
- normal keyed-state processing finds no write to the receiver.

The result is always `MAY` / `AMBIGUOUS`. `SELF`, `CALL`, unknown roots, dynamic
paths, parent writes, dynamic parent writes, and written receivers without a
matching slot continue to abstain. Same-path writes use their written value
instead of inherited root provenance.

## Controls

- `CORE-S04=13/13`: language-neutral positive, negative, contamination, schema-strictness, and legacy-compatibility cases.
- `JS_PROP_R03=16/16`: live jssrc2cpg/export/normalizer/loader/engine gate.
- The live gate confirms that raw read/write receiver IDs differ while canonical
  receiver locations match.
- State-facts 0.3 replay remains loadable with direct-receiver semantics.

## Mozilla measurement

On the bounded all-eligible extension slice, the rule changes exactly six
functions from `STATE_READ` abstention to `MAY` parameter provenance. They are
parameter-rooted browser/extension property reads; no `SELF`, dynamic-path, or
same-path-write case is promoted. The source/sink and hint layers are unchanged,
so this measurement is not a vulnerability finding and does not create an LLM
handoff packet by itself.
