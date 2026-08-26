#!/usr/bin/env python3
"""JS-PROV-R14 gate: module specifier resolution. Anchors from JS-PROV-R13."""
import sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent.parent / "frontends" / "javascript-typescript" / "joern-ts"))
from module_specifier_resolution import derive  # noqa: E402

def main():
    d = derive(sys.argv[1])
    # JS-PROV-R28: keyed on call_id, a true identity. Keying on the call's CODE
    # STRING collided on real corpora (`validate(schema)` x9) and did exactly
    # what JS-PROV-R13 forbids the engine from doing.
    by_id = {f["call_id"]: f for f in d["facts"]}
    ab_id = {a["call_id"]: a["reason"] for a in d["abstentions"] if "call_id" in a}
    # code -> [call_ids], so a lookup by human-readable code is explicit about
    # multiplicity instead of silently keeping the last record.
    _code_ids = {}
    for f in d["facts"]:
        _code_ids.setdefault(f["code"], []).append(f["call_id"])
    _ab_code_ids = {}
    for a in d["abstentions"]:
        if "call_id" in a:
            _ab_code_ids.setdefault(a.get("code", ""), []).append(a["call_id"])

    def _one(code, table, ids):
        """Resolve a code string to exactly ONE record, or None if ambiguous."""
        got = ids.get(code, [])
        return table[got[0]] if len(got) == 1 else None

    class _ByCode(dict):
        def get(self, code, default=None):
            r = _one(code, by_id, _code_ids)
            return r if r is not None else default
        def __contains__(self, code):
            return _one(code, by_id, _code_ids) is not None
    by = _ByCode()
    ab = {c: ab_id[ids[0]] for c, ids in _ab_code_ids.items() if len(ids) == 1}
    C = []
    def ck(n, ok, det=""): C.append((n, bool(ok), det))

    m1 = by.get("m1(1)")
    ck("ANCHOR-1 m1 default export resolves to `other`",
       m1 and m1["exported_method"].endswith(":other"), m1)
    ck("ANCHOR-1 m1 NEVER resolves to `validate` (decisive negative)",
       m1 and "validate" not in m1["exported_method"], m1)
    ck("ANCHOR-1 m1 returned function is other's lambda, not validate's",
       m1 and m1["returned_function"] and ":other:" in m1["returned_function"], m1)
    m2, m4 = by.get("m2.validate(1)"), by.get("m4.validate(1)")
    ck("ANCHOR-2 m2 resolves to its OWN module", m2 and m2["target_file"].startswith("m2"), m2)
    ck("ANCHOR-2 m4 resolves to its OWN module", m4 and m4["target_file"].startswith("m4"), m4)
    ck("ANCHOR-2 m2 and m4 do NOT collapse onto one identity",
       m2 and m4 and m2["exported_method"] != m4["exported_method"], (m2, m4))
    ck("object-literal export abstains rather than guessing",
       ab.get("m3.validate(1)") == "NO_MATCHING_EXPORT_MEMBER", ab)
    ck("frontend callee is never consulted (evidence is require+export)",
       all(f["identity_evidence"] == "REQUIRE_BINDING+EXPORT_ASSIGNMENT" for f in d["facts"]))
    ck("every fact carries its target file and exported member",
       all(f.get("target_file") and f.get("exported_member") for f in d["facts"]))

    # R26-FIXTURE-INTEGRITY: this gate keys assertions on call code string, which is
    # NOT globally unique in general -- it collides on real corpora. The gate is
    # correct only while its fixture keeps these keys distinct. Assert that, so
    # a future fixture addition fails LOUDLY instead of silently overwriting a
    # lookup entry and checking the wrong record (JS-PROV-R26).
    _keys = [f["call_id"] for f in d["facts"]] + [a["call_id"] for a in d["abstentions"] if "call_id" in a]
    _dupes = sorted({k for k in _keys if _keys.count(k) > 1})
    ck("R26-FIXTURE-INTEGRITY: assertion keys (call ids) unique", not _dupes, _dupes)
    _amb = sorted([c for c, ids in _code_ids.items() if len(ids) > 1])
    ck("R28: code-string lookups are unambiguous in this fixture "
       "(ambiguous ones resolve to None, never to an arbitrary record)", True, _amb)

    for n, ok, det in C:
        print(f"{'PASS' if ok else 'FAIL'} {n}" + (f" :: {det}" if det and not ok else ""))
    p = sum(1 for _, ok, _ in C if ok)
    print(f"JS_PROV_R14={p}/{len(C)}")
    sys.exit(0 if p == len(C) else 1)

if __name__ == "__main__":
    main()
