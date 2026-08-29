#!/usr/bin/env python3
"""Control/regression harness for capability 4 (external decoder contracts). Synthetic
positive + adversarial controls only; NO model calls; the frozen held-out corpus is NOT
referenced. Verifies: authoritative-provenance hash binding (and per-contract fail-closed on a
tampered excerpt); role mapping by position + declaration identity; pre/post avail_out
semantics; bounded vs oversized vs unresolved routing; contract tied to signature+library not
name (arity mismatch and local shadow); additive-ness / separation from earlier capabilities.

Usage: cap_decoder_contract_test.py   (REPO env + scan_c_frozen.sh + joern 4.0.608)
"""
import os, shutil, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "tchecker-research-complete",
                                "portable-engine-full-review-package", "tools"))
import cap_decoder_contract as C
import cap_write_site_dedup as WSD
import cap3_domain_audit as AUD
import cap_member_pointer_walk as M


def scan(srcdir):
    out = tempfile.mkdtemp()
    os.environ.setdefault("REPO", os.path.abspath(os.path.join(HERE, "..", "..")))
    subprocess.run(["bash", os.path.join(HERE, "scan_c_frozen.sh"), srcdir, out],
                   capture_output=True, text=True)
    return os.path.join(out, "cpp.json")


def main():
    cpp = scan(os.path.join(HERE, "cap_controls", "cap4_decoder"))
    ops = C.analyze_decoder_calls(cpp)
    by = {o["function"]: o for o in ops}

    def route(fn): return by.get(fn, {}).get("route")
    def disp(fn): return by.get(fn, {}).get("disposition")
    def reason(fn): return by.get(fn, {}).get("reason")

    # provenance: all four archived authority excerpts verify by sha256
    _bn, prov = C.load_contracts()
    checks = [
        ("PROVENANCE: all archived authority excerpts hash-verify (ok)",
         len(prov) == 4 and all(p["provenance"] == "ok" for p in prov)),

        # BOUNDED (explicit capacity arg <= established dest capacity)
        ("BOUNDED dstCapacity==bufsize -> deterministic_complete",
         route("dc_fits") == "deterministic_complete"
         and by["dc_fits"]["max_write_extent"] == 100 and by["dc_fits"]["dest_capacity"] == 100),
        ("BOUNDED via sizeof(dst) -> deterministic_complete (extent bound to exact capacity)",
         disp("dc_sizeof") == "deterministic_complete"),
        ("BOUNDED via heap literal allocation -> deterministic_complete",
         disp("dc_heap") == "deterministic_complete"
         and by["dc_heap"]["dest_capacity_prov"] == "heap_literal_allocation"),
        ("PARTIAL-write contract (safe_partial arg4 cap) -> deterministic_complete",
         disp("dc_partial") == "deterministic_complete"
         and by["dc_partial"]["contract_id"].startswith("lz4.LZ4_decompress_safe_partial")),

        # OVERSIZED (capacity arg > established dest capacity)
        ("OVERSIZED dstCapacity 200 > 64-byte dst -> proven_oversized",
         disp("dc_over") == "proven_oversized"
         and by["dc_over"]["max_write_extent"] == 200 and by["dc_over"]["dest_capacity"] == 64),

        # UNRESOLVED (recognized, relationship left open -- never a false safe)
        ("UNRESOLVED symbolic capacity -> recognize + relationship_unresolved",
         disp("dc_symbolic") == "relationship_unresolved"
         and reason("dc_symbolic") == "write_extent_unresolved"),
        ("UNRESOLVED dest capacity (param dst) -> recognize + relationship_unresolved",
         disp("dc_param_dst") == "relationship_unresolved"
         and reason("dc_param_dst") == "capacity_of_dest_unresolved"),

        # PRE/POST avail_out semantics: recognized, extent is pre-call remaining capacity,
        # explicitly NOT treated as bytes written.
        ("STATEFUL inflate -> recognized; extent=PRE-call avail_out (not bytes written)",
         reason("dc_inflate") == "decoder_capacity_in_state_object"
         and by["dc_inflate"]["extent_field"] == "avail_out"
         and by["dc_inflate"]["extent_field_meaning"] == "pre_call_remaining_capacity"
         and by["dc_inflate"]["stateful"] is True),

        # ROLE MAPPING by position + declaration identity
        ("ROLES mapped by position: dst=arg1, input=arg0, len=arg2, capacity=arg3",
         by["dc_fits"]["roles"]["destination"]["arg_index"] == 1
         and by["dc_fits"]["roles"]["input"]["arg_index"] == 0
         and by["dc_fits"]["roles"]["input_length"]["arg_index"] == 2
         and by["dc_fits"]["roles"]["available_capacity"]["arg_index"] == 3),
        ("ROLE decl identity: dst resolves to its local declaration (ref-target, verifiable)",
         by["dc_fits"]["roles"]["destination"]["decl_verifiable"] is True
         and by["dc_fits"]["roles"]["destination"]["decl_identity"][0] == "local"),
        ("ROLE decl identity: inflate state_object resolves to the z_streamp param",
         by["dc_inflate"]["roles"]["state_object"]["arg_index"] == 0
         and by["dc_inflate"]["roles"]["state_object"]["decl_identity"][0] == "param"),

        # SIGNATURE, not NAME
        ("SIGNATURE not name: arity mismatch (3 args vs 4) -> NOT bound (no op)",
         "dc_arity" not in by),
        ("SIGNATURE not name: local shadow (same name+sig, has body) -> NOT bound (no op)",
         "dc_local_deflate" not in by),

        # NEGATIVE: a plain copy loop is not a decoder contract
        ("NEG plain memcpy-style loop -> no cap4 op", "dc_notdecoder" not in by),

        # exactly the 8 recognized decoder calls, nothing else
        ("EXACTLY 8 decoder ops recognized (3 no-ops correctly excluded)", len(ops) == 8),
    ]

    # FAIL CLOSED on provenance: a tampered authority excerpt drops ONLY that contract; the
    # others still operate. Corrupt the LZ4_decompress_safe excerpt in a temp authority dir.
    tmp_auth = tempfile.mkdtemp()
    shutil.copytree(C.AUTH_DIR, os.path.join(tmp_auth, "authorities"))
    bad = os.path.join(tmp_auth, "authorities", "lz4-1.9.4-LZ4_decompress_safe.txt")
    open(bad, "a").write("\n/* tampered */\n")
    _bn2, prov2 = C.load_contracts(os.path.join(tmp_auth, "authorities"))
    fc = {o["function"]: o for o in
          C.analyze_decoder_calls(cpp, auth_dir=os.path.join(tmp_auth, "authorities"))}
    checks += [
        ("FAIL CLOSED: tampered excerpt -> that contract's provenance is hash_mismatch",
         any(p["id"].startswith("lz4.LZ4_decompress_safe@") and p["provenance"] == "hash_mismatch"
             for p in prov2)),
        ("FAIL CLOSED: dropped contract's calls are NOT routed (dc_fits/dc_over gone)",
         "dc_fits" not in fc and "dc_over" not in fc),
        ("FAIL CLOSED: intact contracts still operate (safe_partial + inflate remain)",
         "dc_partial" in fc and "dc_inflate" in fc),
    ]

    # ADDITIVE / SEPARATION: cap4 sites are disjoint from the frozen cursor producer, and cap4
    # emits nothing on a bare copy file; cap3 emits nothing on the decoder controls.
    cur_keys = {WSD.identity_key(o) for o in AUD.cursor_sites(cpp)}
    cap4_keys = {WSD.identity_key({"identity": o["identity"]}) for o in ops}
    cap3_on_decoders = M.analyze_member_walks(cpp)
    bare = tempfile.mkdtemp()
    open(os.path.join(bare, "b.c"), "w").write(
        "#include <string.h>\nvoid f(char*s,int n){char d[50];memcpy(d,s,n);}\n")
    n_bare = len(C.analyze_decoder_calls(scan(bare)))
    checks += [
        ("SEPARATION: cap4 decoder-call sites are disjoint from cursor-recognized sites",
         cap4_keys.isdisjoint(cur_keys)),
        ("ADDITIVE: cap3 (member walks) emits nothing on the decoder controls",
         len(cap3_on_decoders) == 0),
        ("ADDITIVE: cap4 emits 0 ops on a bare-memcpy file", n_bare == 0),
    ]

    ok = True
    for name, c in checks:
        print(("PASS" if c else "FAIL"), name); ok = ok and c
    print("\nALL PASS" if ok else "\nFAILURES PRESENT")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
