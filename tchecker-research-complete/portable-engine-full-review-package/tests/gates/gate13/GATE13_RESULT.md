# Gate 13 — may-alias joins across control flow

## Goal
Extend the receiver-sensitive state model from must-alias chains to conditional aliases without flattening a may-alias join into either an exact flow or no flow.

No security source/sink semantics are involved.

## Model change
At a control-flow join, object identities are unioned. A write through a receiver with multiple possible identities is a **weak update**: each possible receiver keeps its prior state and gains the new possible value. An exact single-receiver write remains a strong update.

This distinction is required for code such as:

```ts
if (cond) x = a; else x = b;
x.setValue(source);
return a.readValue();
```

The write may hit `a`, but is not guaranteed to. The result is therefore represented as an ambiguous union rather than as exact provenance.

## Frontend results

- `mayAliasWrite(cond, source)` -> `AMBIGUOUS { source, STATE_UNKNOWN(a.value) }`.
- `sameAliasBothBranches(cond, source)` -> `EXACT { source }`; both branches select the same receiver, so the join collapses to a must-alias.
- `mayAliasDifferentField(cond, source)` -> `UNKNOWN` for `a.value`, with **no source cross-flow** from a write to `other`.
- `mayAliasOverwrite(cond, source)` -> `AMBIGUOUS { source, CONST }`; the conditional overwrite may kill the source, but may also target the other object.
- `mayAliasRead(cond, source)` -> `AMBIGUOUS { source, CONST }` when the read receiver itself is the join of two differently-valued objects.

## Bridge discipline
Only an `EXACT` state result is eligible for the existing `COMPLETE` return-summary bridge. The four `AMBIGUOUS`/`UNKNOWN` results are deliberately not promoted to hard engine summaries.

The generated bridge therefore contains exactly one row: `sameAliasBothBranches -> parameter 1`.

## Real-engine check
Using the existing Gate-11 bridge:

- bridge OFF: all five Gate-13 functions have `positions=[]` in the legacy engine on this fixture;
- bridge ON: only `sameAliasBothBranches` changes to `positions=[1]`;
- `mayAliasWrite`, `mayAliasDifferentField`, `mayAliasOverwrite`, and `mayAliasRead` remain unchanged.

Runtime instrumentation reports:

`FRONTEND_STATE_RETURN loaded=1 rejected=0 complete=1`

`gate13_test.py`: **9/9 PASS**.

## What this establishes
The portable state layer now distinguishes **must-alias** from **may-alias** at branch joins. It performs strong updates only for exact receiver identity and weak updates for a receiver set. This prevents conditional aliases from being silently converted into hard provenance while still preserving possible flows for downstream analysis.

Call-target resolution and receiver-object identity remain separate concepts: two possible receiver objects may still share one exact method implementation. The ambiguity here is heap identity/provenance ambiguity, not necessarily method-target ambiguity.

## Boundary
The legacy return-summary interface is still binary: a parameter position is either present or absent. It has no place to carry `AMBIGUOUS` state provenance. Gate 13 therefore refuses to inject may-alias results rather than laundering them into exact facts.

The next portability step should add a resolution/confidence field to state-derived provenance (or a parallel uncertain-summary channel), so `AMBIGUOUS {source, const/unknown}` can travel through the core without becoming a hard return-taint position.
