#!/usr/bin/env python3
"""JS-PROV-R12-1 — ReturnedFunctionIdentityFact.

A general higher-order-function identity primitive:

    wrapper CALL -> callee METHOD -> RETURN -> METHOD_REF -> returned METHOD

Promoted as its own fact rather than embedded in the state-flow join. It was
found while characterizing Koa's `validate(schema)` (JS-PROV-R11), but nothing
about it is framework-specific: any function that returns a function literal
resolves here. Reusable by callback registration, event handlers, decorators,
and middleware in other frameworks.

Known boundary (JS-PROV-R12 Corpus-B replay): this resolves the wrapper METHOD
to its returned METHOD. It does NOT resolve a *module* to the function it
exports -- a call reaching the wrapper via `require(m)` + `module.exports = fn`
resolves to the module object, which has no RETURN to follow. That is the
separate cross-module export-identity problem (JS-PROV-R13).
"""
import json, sys
from pathlib import Path


def derive(raw):
    p = Path(raw) / "returned_function_identity.tsv"
    facts = []
    if p.exists():
        for ln in p.read_text().splitlines():
            if not ln.strip():
                continue
            xs = ln.split("\t")
            if len(xs) != 3:
                continue
            wrapper, returned, ret_type = xs
            facts.append({
                "wrapper_method": wrapper,
                "returned_method": returned,
                "declared_return_type": ret_type,
                "identity_mechanism": "RETURN_METHOD_REF",
                "resolution": "ESTABLISHED",
            })
    return {"schema": "portable-returned-function-identity/0.1",
            "note": ("General higher-order function identity. Resolves a wrapper METHOD to "
                     "the METHOD it returns. Does NOT cross a module-export boundary."),
            "facts": facts}


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1]), indent=2))
