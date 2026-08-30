#!/usr/bin/env python3
"""NPM-CORPUS pipeline glue: a minimal, disclosed compatibility adapter between
`normalize_joern_facts.py` (JS/TS, `portable-program-facts/0.2`) and `link_napi_facts.py`
(the cross-language resolver, `frontends/polyglot/`).

REAL BUG FOUND during pilot validation (not assumed, not guessed): `link_napi_facts.py`
merges `js.get('metadata', []) + cpp.get('metadata', [])` via list concatenation, but
`normalize_joern_facts.py`'s real output emits `metadata` as a single DICT
(`{"language": ..., "cpg_version": ..., "root": ...}`), while `normalize_c_cpp_facts_v03.py`
emits a LIST of one dict. Running the real pipeline on real output crashes
(`TypeError: unsupported operand type(s) for +: 'dict' and 'list'`) even though
`link_napi_facts.py`'s own isolated gate (`tests/gates/core-crosslang/`, 5/5) passes -- that
gate evidently exercises the resolver's linking logic against hand-built fixture JSON, never
against the real output of these two specific normalizer scripts run together. This is a real
integration gap between two independently-tested components, discovered here for the first
time by actually running the full pipeline end-to-end on a real package (per this project's
own "verify against real facts, don't assume components compose" discipline).

Fix scope, deliberately narrow: this adapter ONLY reshapes the JS facts document's own
`metadata` field (dict -> single-element list) before `link_napi_facts.py` reads it. It does
NOT modify `link_napi_facts.py`, `normalize_joern_facts.py`, or `normalize_c_cpp_facts_v03.py`
-- none of those files are touched, and none of R01-R04's frozen scanning logic is anywhere
near this. This is corpus-pipeline glue, applied to the INPUT DATA shape, not a change to any
frozen analyzer component.
"""
import json
import sys


def adapt_js_facts(js_facts_path, out_path):
    with open(js_facts_path) as f:
        doc = json.load(f)
    md = doc.get("metadata")
    if isinstance(md, dict):
        doc["metadata"] = [md]
    with open(out_path, "w") as f:
        json.dump(doc, f)


if __name__ == "__main__":
    adapt_js_facts(sys.argv[1], sys.argv[2])
