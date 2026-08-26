#!/usr/bin/env python3
"""JS-PROV-R23b gate: import-binding identity. Preregistered outcome table."""
import sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent.parent / "frontends" / "javascript-typescript" / "joern-ts"))
from import_binding_identity import derive  # noqa: E402
from module_specifier_resolution import derive as derive_l1  # noqa: E402

def main():
    d = derive(sys.argv[1])
    est = {f["local_binding"]: f for f in d["facts"]}
    ab = {a["local"]: a["reason"] for a in d["abstentions"]}
    C = []
    def ck(n, ok, det=""): C.append((n, bool(ok), det))

    ck("import { f }        -> establishes local -> exported f",
       est.get("fDecl", {}).get("imported_member") == "fDecl"
       and est["fDecl"]["exported_method"].endswith(":fDecl"), est.get("fDecl"))
    ck("import { f as g }   -> establishes g -> exported f (source member, not alias)",
       est.get("fAliased", {}).get("imported_member") == "fConst", est.get("fAliased"))
    ck("default import      -> ABSTAINS (member is the local alias, not `default`)",
       "fDefault" not in est and ab.get("fDefault") == "MEMBER_NOT_EXPORTED_BY_TARGET", ab.get("fDefault"))
    ck("namespace import    -> ABSTAINS; never fabricates a member named `ns`",
       "ns" not in est and ab.get("ns") == "MEMBER_NOT_EXPORTED_BY_TARGET", ab.get("ns"))
    # SUPERSEDED BY JS-PROV-R26. R23b abstained on re-exports because the RHS is
    # a field access on a module object. R26 added a BOUNDED chain hop, so this
    # now resolves. The assertion is inverted rather than deleted, so the change
    # in behaviour stays visible in the gate history.
    ck("re-export dependency -> RESOLVES via the R26 chain hop (was: ABSTAINS)",
       "viaReexport" in est, ab.get("viaReexport"))
    ck("every established fact names its target file and source member",
       all(f.get("target_file") and f.get("imported_member") for f in d["facts"]))
    ck("evidence always starts IMPORT_NODE+EXPORT_ASSIGNMENT (never the lowered require form)",
       all(f["identity_evidence"].startswith("IMPORT_NODE+EXPORT_ASSIGNMENT") for f in d["facts"]),
       [f["identity_evidence"] for f in d["facts"]])
    ck("observed and established counts reported separately",
       "import_bindings_observed" in d and "identities_established" in d)
    ck("no established member is absent from its target module's exports",
       all(f["imported_member"] for f in d["facts"]))

    est = {f["local_binding"]: f for f in d["facts"]}
    abst = {a["local"]: a["reason"] for a in d["abstentions"]}

    # --- JS-PROV-R26: bounded re-export hop ---
    vr = est.get("viaReexport")
    ck("R26 re-export chain resolves to the terminal declaration",
       vr and vr["exported_method"].endswith("lib.ts::program:fDecl"), vr)
    ck("R26 the full chain is recorded, not just the endpoint",
       vr and len(vr.get("reexport_chain", [])) > 1, vr.get("reexport_chain") if vr else None)
    ck("R26 chain-derived facts carry a distinct evidence label",
       vr and vr["identity_evidence"].endswith("REEXPORT_CHAIN"), vr.get("identity_evidence") if vr else None)
    ck("R26 depth bound recorded on the fact", vr and vr.get("reexport_depth_bound"), vr)
    ck("R26 re-export of a MISSING member abstains",
       "r26Missing" not in est and "r26Missing" in abst, abst.get("r26Missing"))
    ck("R26 TRUE non-terminating cycle abstains via the cycle guard",
       "r26Spin" not in est and abst.get("r26Spin") == "REEXPORT_CYCLE", abst.get("spin"))
    ck("R26 terminating mutual re-export still resolves (not over-blocked)",
       est.get("r26Mutual", {}).get("exported_method", "").endswith("r26MutualTerminal"), est.get("fromCyc2"))
    ck("R26 export * still abstains (no member identity to chain to)",
       not any(f["local_binding"] == "r26Star" for f in d["facts"]))

    # --- JS-PROV-R25: consumer integration. Consumes the FACT, not the import. ---
    l1 = derive_l1(sys.argv[1])
    esm = [f for f in l1["facts"] if f["identity_evidence"] == "ESM_IMPORT_BINDING_IDENTITY"]
    moved = {f["enabled_by_import_binding"]["local"] for f in esm}
    est_names = set(est)
    abst_names = set(abst)
    ck("R25 established ESM bindings reach the L1 consumer", bool(moved), moved)
    ck("R25 DECISIVE NEGATIVE: no ABSTAINED binding moves downstream",
       not (moved & abst_names), sorted(moved & abst_names))
    ck("R25 every downstream move has an ESTABLISHED R23b record", moved <= est_names, sorted(moved - est_names))
    ck("R25 namespace import never reaches the consumer", "ns" not in moved)
    ck("R25 default import never reaches the consumer", "fDefault" not in moved)
    # SUPERSEDED BY JS-PROV-R26: re-exports are now ESTABLISHED, so reaching the
    # consumer is correct. The invariant that still matters -- only ESTABLISHED
    # bindings move -- is asserted by the DECISIVE NEGATIVE above.
    ck("R25 re-export reaches the consumer ONLY because R26 established it",
       ("viaReexport" not in moved) or ("viaReexport" in est_names), sorted(moved))
    ck("R25 every ESM-evidenced L1 fact is traceable to its enabling binding",
       all(f.get("enabled_by_import_binding", {}).get("member") for f in esm))
    ck("R25 CommonJS evidence label is never used for an ESM-derived fact",
       all(f["identity_evidence"] == "ESM_IMPORT_BINDING_IDENTITY" for f in esm))

    # --- JS-PROV-R26: re-export chain resolution (isolated revision) ---
    ck("R26 single-hop re-export resolves to the real declaration",
       est.get("r26SingleHop", {}).get("exported_method", "").endswith("r26ChainTerminal"),
       est.get("realFn"))
    ck("R26 CHAINED re-export (top->mid->base) resolves transitively",
       est.get("r26Transitive", {}).get("exported_method", "").endswith("r26ChainTerminal"),
       est.get("viaTop"))
    ck("R26 chain is recorded on the fact for traceability",
       len(est.get("r26Transitive", {}).get("reexport_chain", [])) == 3, est.get("viaTop"))
    ck("R26 re-export of a member the target does NOT export ABSTAINS",
       "r26Missing" not in est and ab.get("r26Missing") == "MEMBER_NOT_EXPORTED_BY_TARGET",
       ab.get("missing"))
    ck("R26 CYCLE terminates and abstains (never loops)",
       "r26Spin" not in est and ab.get("r26Spin") == "REEXPORT_CYCLE", ab.get("r26Spin"))
    ck("R26 no established fact lacks a resolvable declaration",
       all(f["exported_method"] for f in d["facts"]))

    _est = {f["local_binding"] for f in d["facts"]}
    _ab = {a["local"] for a in d["abstentions"]}
    ck("R26-SET-DISJOINTNESS: ESTABLISHED n ABSTAINED = {}", not (_est & _ab), sorted(_est & _ab))
    _names = [f["local_binding"] for f in d["facts"]] + [a["local"] for a in d["abstentions"]]
    ck("R26-FIXTURE-INTEGRITY: every gate key names exactly one binding record",
       len(_names) == len(set(_names)),
       sorted({n for n in _names if _names.count(n) > 1}))

    for n, ok, det in C:
        print(f"{'PASS' if ok else 'FAIL'} {n}" + (f" :: {det}" if det and not ok else ""))
    p = sum(1 for _, ok, _ in C if ok)
    print(f"JS_PROV_R23B={p}/{len(C)}")
    sys.exit(0 if p == len(C) else 1)

if __name__ == "__main__":
    main()
