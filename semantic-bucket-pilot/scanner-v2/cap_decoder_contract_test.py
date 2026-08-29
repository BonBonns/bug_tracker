#!/usr/bin/env python3
"""Control/regression harness for capability 4 (external decoder contracts). Synthetic
positive + adversarial controls only; NO model calls; the frozen held-out corpus is NOT
referenced. Verifies: authoritative-provenance hash binding (+ per-contract fail-closed on a
tampered excerpt); LIBRARY-IDENTITY provenance gate (call shape recognized, contract applied
only with an attested+validated library/version); role mapping by position + declaration
identity; pre/post avail_out semantics; the EXTENT-DIRECTION rule (a max upper bound above
capacity is NOT a proven overflow; only a lower/exact bound above capacity is); additive-ness
/ separation from earlier capabilities.

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

# operator BUILD ATTESTATION: the linked libraries + validated versions (pinned build).
BUILD = {"lz4": {"version": "1.9.4", "established_by": "pinned_build"},
         "zlib": {"version": "1.3.1", "established_by": "pinned_build"}}


def scan(srcdir):
    out = tempfile.mkdtemp()
    os.environ.setdefault("REPO", os.path.abspath(os.path.join(HERE, "..", "..")))
    subprocess.run(["bash", os.path.join(HERE, "scan_c_frozen.sh"), srcdir, out],
                   capture_output=True, text=True)
    return os.path.join(out, "cpp.json")


def main():
    cpp = scan(os.path.join(HERE, "cap_controls", "cap4_decoder"))
    ops = C.analyze_decoder_calls(cpp, build_identity=BUILD)   # verified library+version
    by = {o["function"]: o for o in ops}

    def route(fn): return by.get(fn, {}).get("route")
    def disp(fn): return by.get(fn, {}).get("disposition")
    def reason(fn): return by.get(fn, {}).get("reason")

    _bn, prov = C.load_contracts()
    checks = [
        ("PROVENANCE: all 5 archived authority excerpts hash-verify (ok)",
         len(prov) == 5 and all(p["provenance"] == "ok" for p in prov)),

        # BOUNDED (extent <= established capacity) -> deterministic, for max and exact bounds
        ("BOUNDED max dstCapacity==bufsize -> deterministic_complete",
         disp("dc_fits") == "deterministic_complete" and by["dc_fits"]["extent_bound"] == "max"),
        ("BOUNDED via sizeof(dst) -> deterministic_complete",
         disp("dc_sizeof") == "deterministic_complete"),
        ("BOUNDED via heap literal allocation -> deterministic_complete",
         disp("dc_heap") == "deterministic_complete"
         and by["dc_heap"]["dest_capacity_prov"] == "heap_literal_allocation"),
        ("BOUNDED partial-write contract (safe_partial arg4) -> deterministic_complete",
         disp("dc_partial") == "deterministic_complete"),
        ("BOUNDED exact-bound within capacity (fast originalSize 50 <= 64) -> deterministic",
         disp("dc_fast_fits") == "deterministic_complete"
         and by["dc_fast_fits"]["extent_bound"] == "exact"),

        # FIX 1: an excessive MAX is NOT a proven overflow
        ("MAX-bound > capacity -> open_candidate (decoder_extent_exceeds_known_capacity), "
         "NOT proven_oversized",
         route("dc_over") == "open_candidate"
         and reason("dc_over") == "decoder_extent_exceeds_known_capacity"
         and disp("dc_over") == "relationship_unresolved"),
        # only an EXACT / lower bound > capacity is a proven overflow
        ("EXACT-bound > capacity (fast originalSize 200 > 64) -> proven_oversized",
         disp("dc_fast_over") == "proven_oversized"
         and by["dc_fast_over"]["extent_bound"] == "exact"
         and reason("dc_fast_over") == "write_extent_exceeds_destination_capacity"),

        # UNRESOLVED (recognized, relationship open)
        ("UNRESOLVED symbolic extent -> relationship_unresolved (write_extent_unresolved)",
         disp("dc_symbolic") == "relationship_unresolved"
         and reason("dc_symbolic") == "write_extent_unresolved"),
        ("UNRESOLVED dest capacity (param dst) -> relationship_unresolved",
         reason("dc_param_dst") == "capacity_of_dest_unresolved"),
        ("STATEFUL inflate -> recognized; extent=PRE-call avail_out (not bytes written)",
         reason("dc_inflate") == "decoder_capacity_in_state_object"
         and by["dc_inflate"]["extent_field"] == "avail_out"
         and by["dc_inflate"]["extent_field_meaning"] == "pre_call_remaining_capacity"),

        # ROLE MAPPING by position + declaration identity
        ("ROLES by position: dst=arg1, input=arg0, len=arg2, capacity=arg3",
         by["dc_fits"]["roles"]["destination"]["arg_index"] == 1
         and by["dc_fits"]["roles"]["input"]["arg_index"] == 0
         and by["dc_fits"]["roles"]["input_length"]["arg_index"] == 2
         and by["dc_fits"]["roles"]["available_capacity"]["arg_index"] == 3),
        ("ROLE decl identity: dst resolves to its local declaration (ref-target)",
         by["dc_fits"]["roles"]["destination"]["decl_identity"][0] == "local"),
        ("ROLE decl identity: inflate state_object resolves to the z_streamp param",
         by["dc_inflate"]["roles"]["state_object"]["decl_identity"][0] == "param"),

        # SIGNATURE, not NAME (call-shape gate)
        ("SIGNATURE not name: arity mismatch (3 vs 4) -> not bound (no op)", "dc_arity" not in by),
        ("SIGNATURE not name: local shadow (same sig, has body) -> not bound (no op)",
         "dc_local_deflate" not in by),
        ("NEG plain copy loop -> no cap4 op", "dc_notdecoder" not in by),
        ("EXACTLY 10 decoder ops recognized (3 no-ops correctly excluded)", len(ops) == 10),
    ]

    # FIX 2: LIBRARY IDENTITY provenance gate ------------------------------------------------
    # (3) same signature from an unresolved external declaration -> contract identity unresolved
    unattested = {o["function"]: o for o in C.analyze_decoder_calls(cpp)}  # no build_identity
    # (4) correct library but unknown/unvalidated version -> version unresolved
    badver = C.analyze_decoder_calls(cpp, build_identity={
        "lz4": {"version": None, "established_by": "verified_header"},
        "zlib": {"version": "1.2.11", "established_by": "verified_header"}})
    badver = {o["function"]: o for o in badver}
    checks += [
        ("IDENTITY unresolved: no attestation -> call shape recognized, contract identity "
         "unresolved (dc_fits/dc_inflate)",
         unattested["dc_fits"]["reason"] == "contract_identity_unresolved"
         and unattested["dc_fits"]["route"] == "additional_evidence_required"
         and unattested["dc_inflate"]["reason"] == "contract_identity_unresolved"
         and len(unattested) == 10),   # still RECOGNIZED (call shape), just not applied
        ("IDENTITY unresolved: roles still mapped (recognition survives no-provenance)",
         unattested["dc_fits"]["roles"]["destination"]["arg_index"] == 1),
        ("VERSION unresolved: attested but version not in validated family -> version unresolved",
         badver["dc_fits"]["reason"] == "contract_version_unresolved"
         and badver["dc_inflate"]["reason"] == "contract_version_unresolved"),
        ("VERSION unresolved: no bounded/oversized verdict issued on an unvalidated version",
         all(o["disposition"] == "relationship_unresolved" for o in badver.values())),
        # (5) verified library/header/version -> contract applied (the main run above already
        # produced deterministic/open/oversized verdicts under BUILD).
        ("VERIFIED library+version -> contract applied (deterministic/oversized verdicts exist)",
         disp("dc_fits") == "deterministic_complete"
         and disp("dc_fast_over") == "proven_oversized"),
    ]

    # provenance hash FAIL CLOSED: a tampered excerpt drops ONLY that contract.
    tmp_auth = tempfile.mkdtemp()
    shutil.copytree(C.AUTH_DIR, os.path.join(tmp_auth, "authorities"))
    open(os.path.join(tmp_auth, "authorities",
                      "lz4-1.9.4-LZ4_decompress_safe.txt"), "a").write("\n/* tampered */\n")
    adir2 = os.path.join(tmp_auth, "authorities")
    _bn2, prov2 = C.load_contracts(adir2)
    fc = {o["function"]: o for o in C.analyze_decoder_calls(cpp, auth_dir=adir2, build_identity=BUILD)}
    checks += [
        ("FAIL CLOSED: tampered excerpt -> that contract's provenance is hash_mismatch",
         any(p["id"] == "lz4.LZ4_decompress_safe" and p["provenance"] == "hash_mismatch"
             for p in prov2)),
        ("FAIL CLOSED: dropped contract's calls are NOT recognized (dc_fits/dc_over gone)",
         "dc_fits" not in fc and "dc_over" not in fc),
        ("FAIL CLOSED: intact contracts still operate (fast + partial + inflate remain)",
         "dc_fast_over" in fc and "dc_partial" in fc and "dc_inflate" in fc),
    ]

    # ADDITIVE / SEPARATION
    cur_keys = {WSD.identity_key(o) for o in AUD.cursor_sites(cpp)}
    cap4_keys = {WSD.identity_key({"identity": o["identity"]}) for o in ops}
    cap3_on_decoders = M.analyze_member_walks(cpp)
    bare = tempfile.mkdtemp()
    open(os.path.join(bare, "b.c"), "w").write(
        "#include <string.h>\nvoid f(char*s,int n){char d[50];memcpy(d,s,n);}\n")
    n_bare = len(C.analyze_decoder_calls(scan(bare), build_identity=BUILD))
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
