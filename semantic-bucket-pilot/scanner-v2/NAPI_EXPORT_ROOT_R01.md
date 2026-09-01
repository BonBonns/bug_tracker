# NAPI-EXPORT-ROOT-R01 + the three-proof combined promotion

Closes the last reachability gap for the raw-N-API findings: native **export-root
recognition**. Separate revision — it does not modify the frozen
`virtual_dispatch_reachability.py` and does not weaken `promote_gated_by_root`; it
produces the `root_is_reachable` predicate those consume.

## Recognized chain (structural, by N-API call + argument IDENTITIES only)

```
napi_create_function(env, name, len, CALLBACK_METHOD_REF, data, &FUNCTION_VALUE)
        |  same FUNCTION_VALUE identity (identifier referent)
        v
napi_set_named_property(env, EXPORTS, export_name, FUNCTION_VALUE)
        |  same EXPORTS identity (identifier referent)
        v
a proven MODULE INITIALIZER returns EXPORTS
   (a function with the N-API init shape (napi_env, napi_value P) that RETURNS its own
    parameter P, to whose P the property was attached — directly, or one hop away
    through an init(env, P) call it makes)
```

Only `CALLBACK_METHOD_REF`'s resolved native function id is marked an externally
reachable root. **Never keyed on macro spelling (`NAPI_EXPORT_FUNCTION`), source text, or
any function name** (`iterator_next`, `NextWorker`, …). Abstain-first at every link.

`napi_export_root.py` — `established_roots(raw)` and `root_reachable_predicate(raw)`.

## Controls (`check_napi_export_root.py`, 18/18)

| # | shape | outcome |
|---|---|---|
| 1 | exact create→same-value set→returned exports | root **established** |
| 2 | created function never attached | not established |
| 3 | a different `napi_value` attached | `ATTACHED_VALUE_NOT_FROM_CREATE_FUNCTION` |
| 4 | property attached to a different object | `EXPORTS_NOT_RETURNED_BY_MODULE_INIT` |
| 5 | ambiguous callback identity | `AMBIGUOUS_CALLBACK_IDENTITY` |
| 6 | callback argument is not a method reference | `CALLBACK_NOT_A_METHOD_REF` |
| 7 | registration outside a proven module initializer | not established |
| 8 | initializer returns a different exports object | not established |
| 9 | multiple created-function defs reach the property | `MULTIPLE_CREATE_FUNCTION_DEFS_REACH_PROPERTY` |
| 10 | unresolved `napi_define_properties` | explicit `UNRESOLVED_DEFINE_PROPERTIES_IDIOM` |
| 11 | **real header-expanded leveldb** | `iterator_next` **established** (one-hop wrapper init) |
| 12 | real never-exported function (`CreateError`, the init itself, a worker override) | not established |

Header staging: the leveldb facts for controls 11/12 (`raw_leveldb_export_hdr/`) were
produced by compiling `bindings.cpp` with node headers staged (`--include
/opt/node22/include/node`), so `NAPI_EXPORT_FUNCTION` expands to the real
`create_function`/`set_named_property` chain. The recognizer establishes 21 real exports
(all the addon's exports) with zero abstentions.

## The three-proof final promotion (`napi_reachability_combined.py`)

A worker-override native function is elevated to the reportable virtual tier
(`TIER_CALLBACK_OR_WORKER_VIRTUAL_PROVEN`) only when **all three** hold:

```
export root established            (napi_export_root)
AND async registration / object identity established   (frozen virtual_dispatch)
AND unique virtual override established                (frozen virtual_dispatch)
```

Composed by feeding `napi_export_root.root_reachable_predicate` into the frozen
`promote_gated_by_root` (whose result already carries the async-registration/object-
identity + unique-override proofs). A **new** revision with its own EXTENDED reachable-tier
set (the frozen staged set plus the virtual tier); `staged_enablement.py` and
`napi_status_integration.py` are untouched.

## Complete pipeline re-run on real leveldb-zlib (`COMBINED_LEVELDB_RESULT.json`)

On `raw_leveldb_export_hdr` (both chains present), the two `napi_create_buffer_copy`
`STATUS_GUARD_MISSING` findings in `NextWorker::HandleOKCallback` now clear **every** gate:

| finding | provenance | reachability | applicability | adjudication | reportable |
|---|---|---|---|---|---|
| returnKey @1440→1453 | RESOLVED (bindings.cpp) | `TIER_CALLBACK_OR_WORKER_VIRTUAL_PROVEN` | APPLICABLE | NOT_ADJUDICATED | **True** |
| returnValue @1447→1454 | RESOLVED | `TIER_CALLBACK_OR_WORKER_VIRTUAL_PROVEN` | APPLICABLE | NOT_ADJUDICATED | **True** |

Both findings clear provenance + reachability + applicability + adjudication — the
precondition set for bounded failure injection. `reportable=True` means *eligible gated
scanner candidate*, never a confirmed vulnerability: reachability establishes a JS-to-
native path exists; it does not establish runtime harm.
