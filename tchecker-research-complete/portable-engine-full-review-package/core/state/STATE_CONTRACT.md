# Portable State / Persistence Contract — Gate 28

The portable core models durable or out-of-band state as an explicit semantic channel, not as a language/framework API name.

## Location identity

`PersistenceLocation(domain, objectKey, slotKey)` identifies one logical state cell.

Examples a frontend/profile may eventually map into this shape:

- WordPress post meta: `(post_meta, post_id, meta_key)`
- browser local storage: `(local_storage, origin, key)`
- database field: `(db_table_row, row_identity, column)`
- session state: `(session, session_identity, field)`

The core does not know those APIs. It only consumes facts.

## Write/read facts

A `PersistenceWriteFact` records `location <- semantic ValueRef`.
A `PersistenceReadFact` records the candidate writes demonstrated to reach a read plus a resolution class.

The state/front-end layer, not the provenance engine, is responsible for establishing write/read correspondence. The core never matches writes by substring or slot name alone.

Resolution rules:

- EXACT: exactly one demonstrated reaching write
- HEURISTIC: one or more possible writes, never hardened
- AMBIGUOUS: at least two demonstrated alternatives
- UNRESOLVED: no demonstrated write relation; remains UNKNOWN

A candidate write whose `PersistenceLocation` differs from the read is rejected as unresolved.

## Out-of-band origins

A persisted value may originate in a different function/request and therefore cannot be represented as a parameter position of the reader. `OriginRef.PERSISTED_PARAMETER` preserves:

- write event id
- writer function id
- writer parameter index
- stable channel location

These origins survive ordinary return/call wrappers without being rewritten into the caller's parameters.

## Safety invariants

1. Constant writes carry no source provenance.
2. Ambiguous/heuristic persistence reads never become hard/proven origins.
3. Unresolved state reads are UNKNOWN, not no-flow.
4. Location identity includes channel + object identity + slot identity.
5. Write values are evaluated semantically through the same ValueRef/call-summary machinery as ordinary provenance.

## Gate 34: non-persistence state channels

Durable persistence and runtime/request state are intentionally separate abstractions.
`REQUEST`, `SESSION`, `ENVIRONMENT`, and `PROCESS` state are represented by `StateChannelLocation` and must declare whether provenance is an external channel origin, is linked to demonstrated writes, or is currently unmodeled.

A recognized-but-unmodeled channel must produce UNKNOWN/abstention. It must never trigger deeper generic traversal or source guessing.
