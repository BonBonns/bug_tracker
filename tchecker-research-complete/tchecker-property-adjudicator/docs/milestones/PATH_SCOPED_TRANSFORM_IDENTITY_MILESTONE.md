# Path-scoped transform identity (separately gated milestone)

## Requirement
Transform membership for a source->sink alternative must be derived from the ESTABLISHED
propagation path itself (stable CPG call-node identity on that flow), not from "what is
data-dependent on the source". Identity of path-member calls is resolved via existing
R-series import facts; UNKNOWN when not an import binding.

## Approach (frozen propagation + adjudicator untouched)
`path_transform_identity.py` works OUTWARD from `propagation_relations.tsv`: the frozen
propagation producer already lists the ordered path call-nodes per alternative
(transform_chain). The new producer takes exactly those call-nodes, in path order, and
resolves each via `import_bindings.tsv`. Output is drop-in compatible with
transform_identity.tsv (8 cols), so the adjudicator consumes it unchanged.

Invariant preserved per emitted row:
   path_membership = ESTABLISHED (on the established flow)
   semantic_identity = module#member when resolved, else UNKNOWN
A call can be a known path member whose semantic family is UNKNOWN.

## Controls (all pass)
  ctrl1 side call off the sink path        -> EXCLUDED by NEW, was INCLUDED by OLD
  ctrl2 two transforms on the flow          -> both preserved in path order
  ctrl3 same source, two sink paths         -> each alternative only its own transform
  ctrl4 local call on path, no import        -> membership ESTABLISHED, identity UNKNOWN
  ctrl5 imported transform on path           -> identity resolved via import facts
  ctrl6 identical call text, distinct nodes  -> no collision (per-node identity)
  ctrl7 FxA rerun (old vs new membership)    -> see table below

## FxA old-vs-new (mozilla/fxa @ e1a8c43)
  customs.js L75        OLD=26 attributed  NEW=4 on-path (0 identity-established; sanitizePayload UNKNOWN)
  (18 off-path callees removed: makeRequest, emitMetricsEvent, normalizeEmail, error, ... )
  The actual on-path transform is sanitizePayload; its identity stays UNKNOWN (local/method
  call), not repaired downstream.

## Promotion checklist
  off-path transforms attributed : 0
  fabricated identities          : 0
  frozen source/propagation gates: unchanged (SERIALIZE_DOS 9/9; R38/R39/R40 PASS)
  controlled adjudicator proof   : unchanged (clip/wrap identical old==new)
  corpus retains UNKNOWN          : yes (sanitizePayload UNKNOWN, not repaired)

## Result
The payload for a real FxA candidate now contains only path-member transforms, each with
explicit path_membership vs semantic_identity. This is the clean boundary for the next
experiment: can a live LLM supply useful semantic hints about statically
identified-but-semantically-unknown on-path operations (e.g. sanitizePayload)?
