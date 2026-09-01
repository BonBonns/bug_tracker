# VIRTUAL-DISPATCH-REACHABILITY-R01

Shared reachability revision that resolves C++ virtual callbacks through
concrete-allocation-type object flow, so a native method reached only through the
"worker object → registered async callback → cast-back → virtual dispatch" idiom can be
proven reachable from a registered entry when — and only when — exactly one concrete
override is provable. Name-agnostic (no package/class/method special cases); reads the
raw cpp facts directly; **does not modify `reachability_tier.py`, the normalizer, or any
frozen behavior** (a new revision, per the brief).

Files: `virtual_dispatch_reachability.py` (analysis), `check_virtual_dispatch_
reachability.py` (16/16 gate), `study/napi_status/fixture_vd_controls.cpp` +
`raw_vd_controls/` (frozen control facts), `study/napi_status/
VIRTUAL_DISPATCH_LEVELDB_RESULT.json` (the real-package outcome).

## What it proves (abstain-first at every hop)

1. A function contains `p = new T` — a single concrete allocation type T (a factory
   call or non-`new` source is UNRESOLVED → abstain).
2. p is not reassigned between allocation and use → else abstain.
3. T's construction (T's ctor, transitively through base-ctor init) contains a
   registration-API call (reused `CALLBACK_OR_WORKER_REGISTRATION_APIS`) whose **data
   argument is `this`** — so the callback's data pointer has concrete type T. Data that
   is some other object → abstain.
4. p reaches a queue-API call (the async work is actually enqueued).
5. Inside each registered callback, the data parameter is cast to a base pointer
   (`self = (Base*)data`), Base a supertype of T; an unrelated cast, or data that is not
   the callback's own parameter → abstain.
6. From the callback with receiver `self` of concrete type T, an interprocedural
   typestate walk follows member calls on that receiver, resolving each callee by **MRO
   from T** (nearest class in T's linearization defining the exact (name, signature)).
   This resolves non-virtual base methods to the base and virtual overrides to T's own
   override, uniformly and signature-exactly.
7. A function is PROMOTED only when a **single** concrete type reaches it (unique
   override). Two concrete types resolving the same site to different overrides → both
   abstained.

## Callback-cast ancestry rule (explicit)

A `(cast_target)data` recovery of an object whose real concrete type is `concrete_type`
is valid **iff `cast_target == concrete_type` OR `cast_target` is an ANCESTOR of
`concrete_type`** (an upcast). It never requires the concrete type to be an ancestor of
the cast target. `cast_ancestry_check` returns `(ALLOW|ABSTAIN, reason)`:
same-type/upcast → ALLOW; downcast / sibling / missing-or-ambiguous edge → ABSTAIN.
Type names are normalized first — pointers, references, `const`/`volatile`, and leading
`class`/`struct`/`enum`/`union` are stripped, while **namespaces and template arguments
are preserved** (`a::B` never collapses to `B`); a pointer-type `TypeDecl` (`Foo*`)
never overwrites the real class's inheritance. On the real leveldb facts the cast
`self = (BaseWorker*)data` of a concrete `NextWorker` resolves to
`(ALLOW, UPCAST_TO_ANCESTOR)`.

## Controls (compiled + frozen facts + explicit ancestry unit tests, gate 22/22)

| # | shape | outcome |
|---|---|---|
| 1 | one concrete derived worker | derived override **promoted** |
| 2 | two possible derived workers (ambiguous receiver) | abstain, derived not promoted |
| 3 | base-class allocation | **base** override promoted, derived not |
| 4 | callback registered with a different data pointer | `REGISTRATION_DATA_NOT_THIS`, not promoted |
| 5 | receiver reassigned before callback | `RECEIVER_REASSIGNED`, not promoted |
| 6 | factory return, unresolved concrete type | `UNRESOLVED_FACTORY_CONSTRUCTION`, not promoted |
| 7 | virtual signature mismatch | mismatched override not promoted (resolves to base) |
| 8 | callback not registered | no promotion |
| 9 | leveldb pattern (distilled) | worker override **promoted** for the unique concrete type |
| + | root-gate | promoted to the reportable tier **only when the root entry is externally reachable** |
| A1 | same concrete/cast type | cast ALLOWED |
| A2 | concrete derived, cast to base | cast ALLOWED (upcast, incl. multi-level) |
| A3 | concrete base, cast to derived | cast ABSTAIN (downcast) |
| A4 | concrete sibling, cast to sibling | cast ABSTAIN |
| A5 | missing hierarchy edge | cast ABSTAIN |
| A6 | pointer/qualified spelling differences | resolve identically (namespaces preserved) |

Frozen implementation: `virtual_dispatch_reachability.py` sha256
`b375e291583d32b00a08b7759ae3418261f59756db64736c26077ce4e3fba606`.

## Real leveldb-zlib result — virtual-dispatch hop SOLVED; findings still non-reportable

On the real `@8crafter/leveldb-zlib@1.6.0` cpp facts
(`VIRTUAL_DISPATCH_LEVELDB_RESULT.json`): **`NextWorker::HandleOKCallback` (the two
`STATUS_GUARD_MISSING` sites) is proven virtual-dispatch-reachable from `iterator_next`**
via the complete chain — `new NextWorker` → `napi_create_async_work(data=this)` →
`Complete` trampoline → `(BaseWorker*)data` cast → `DoComplete` → virtual
`HandleOKCallback` resolved by MRO to NextWorker's unique override. The other workers'
overrides (Get/End/ApproximateSize/…) resolve the same way, each from its own export.

**But the two findings do NOT yet become reportable.** A SEPARATE gap now dominates: the
JS-export **root** `iterator_next` is `TIER_INTERNAL_UNREGISTERED` and 0 exports are
recognized on these facts — because the facts were built by a standalone c2cpg **without
node/napi headers staged**, so `NAPI_EXPORT_FUNCTION(iterator_next)` in `NAPI_INIT()`
(bindings.cpp:1761) never expanded. `iterator_next` is genuinely exported in source; the
export is simply invisible in header-less facts. The sound root-gate therefore withholds
promotion: virtual dispatch resolves the object-flow hop, but it never invents a JS entry
point.

**Failure injection: NOT performed.** The full JS-to-native chain is not established end
to end (the export root is unproven on these facts), so per the review's gate no bounded
failure-injection test is run. These remain two confirmed API return-code handling
discrepancies, **not** confirmed vulnerabilities; no runtime behavior or security impact
is established or claimed.

## Shared infrastructure

`virtual_dispatch_reachability` returns reachable native function ids and is
property-agnostic — Lock Balance, Protected Field, and the OOB classes benefit
identically from resolving worker/callback virtual dispatch. It is a new revision layered
on top of the frozen `reachability_tier.py`, promoting through the sound root-gate only.

## The clearly-named next gap

Recognize the export idiom (`NAPI_EXPORT_FUNCTION` / `napi_create_function` +
`napi_set_named_property(exports, name, fn)`), or rebuild the leveldb facts **with**
node + napi-macros headers staged so the export macro expands and `iterator_next` becomes
a recognized export. If `iterator_next` is then externally reachable,
`promote_gated_by_root` elevates `NextWorker::HandleOKCallback` to
`TIER_CALLBACK_OR_WORKER_VIRTUAL_PROVEN` and the findings' reportability re-evaluates —
at which point (and only then) the bounded failure-injection test becomes appropriate.
