#!/usr/bin/env python3
"""Control/regression harness for capability 4 (external decoder contracts). Synthetic
positive + adversarial controls only; NO model calls; the frozen held-out corpus is NOT
referenced. Verifies: authoritative-provenance hash binding (+ per-contract fail-closed on a
tampered excerpt); the TRUSTED SCAN-BOUND build-attestation channel (fingerprinted to the
analyzed artifacts, not caller-supplied JSON); role mapping by position + declaration identity;
pre/post avail_out semantics; the CORRECT bound-direction matrix (upper/lower/exact x
below/above capacity); additive-ness / separation from earlier capabilities.

Usage: cap_decoder_contract_test.py   (REPO env + scan_c_frozen.sh + joern 4.0.608)
"""
import hashlib, json, os, shutil, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "tchecker-research-complete",
                                "portable-engine-full-review-package", "tools"))
import cap_decoder_contract as C
import cap_write_site_dedup as WSD
import cap3_domain_audit as AUD
import cap_member_pointer_walk as M

# full-file fingerprints of the authoritative headers (== PROVENANCE.json full_file_sha256);
# the attested build's header_sha256 must match these for a contract to be applied.
HDR = {"lz4": "c1614ecf7ada7b0be1acb560d4239595f96fbb7aa6a79a7c40cb358753830be6",
       "zlib": "8a5579af72ea4f427ff00a4150f0ccb3fc5c1e4379f726e101133b1ab9fc600c",
       "synthetic_testonly": "4a874ca39e12a2d8e7af8202051fa334de593d5eb9a89e8925ca6742ac80d82a"}
VERIFIED = {
    "lz4": {"version": "1.9.4", "established_by": "pinned_build", "header_sha256": HDR["lz4"]},
    "zlib": {"version": "1.3.1", "established_by": "pinned_build", "header_sha256": HDR["zlib"]},
    "synthetic_testonly": {"version": "1.0.0", "established_by": "pinned_build",
                           "header_sha256": HDR["synthetic_testonly"]}}


def _sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def scan(srcdir):
    out = tempfile.mkdtemp()
    os.environ.setdefault("REPO", os.path.abspath(os.path.join(HERE, "..", "..")))
    subprocess.run(["bash", os.path.join(HERE, "scan_c_frozen.sh"), srcdir, out],
                   capture_output=True, text=True)
    return os.path.join(out, "cpp.json")


def write_attestation(cpp, libraries, scan_bound=True):
    """Emit a build_attestation.json into the scan dir (simulating the trusted scan pipeline),
    fingerprinted to THIS scan's cpp.json (and cpg.bin). scan_bound=False writes a wrong scan
    fingerprint so the analyzer must REJECT it (not scan-bound)."""
    sdir = os.path.dirname(os.path.abspath(cpp))
    scan_fp = {"cpp_sha256": _sha(cpp) if scan_bound else "0" * 64}
    cpg = os.path.join(sdir, "cpg.bin")
    if os.path.exists(cpg) and scan_bound:
        scan_fp["cpg_sha256"] = _sha(cpg)
    json.dump({"channel": "scan_pipeline", "scan": scan_fp, "libraries": libraries},
              open(os.path.join(sdir, "build_attestation.json"), "w"))


def clear_attestation(cpp):
    p = os.path.join(os.path.dirname(os.path.abspath(cpp)), "build_attestation.json")
    if os.path.exists(p):
        os.remove(p)


def main():
    cpp = scan(os.path.join(HERE, "cap_controls", "cap4_decoder"))
    write_attestation(cpp, VERIFIED)                     # trusted, scan-bound, verified
    ops = C.analyze_decoder_calls(cpp)
    by = {o["function"]: o for o in ops}

    def route(fn): return by.get(fn, {}).get("route")
    def disp(fn): return by.get(fn, {}).get("disposition")
    def reason(fn): return by.get(fn, {}).get("reason")

    _bn, prov = C.load_contracts()
    checks = [
        ("PROVENANCE: all 7 contract authority excerpts hash-verify (ok)",
         len(prov) == 7 and all(p["provenance"] == "ok" for p in prov)),

        # ---- CORRECT BOUND-DIRECTION MATRIX --------------------------------------------------
        # UPPER (max) bound
        ("MATRIX max, extent<=cap -> deterministic_complete (dc_fits)",
         disp("dc_fits") == "deterministic_complete" and by["dc_fits"]["extent_bound"] == "max"),
        ("MATRIX max, extent>cap -> open (decoder_extent_exceeds_known_capacity), NOT oversized",
         route("dc_over") == "open_candidate"
         and reason("dc_over") == "decoder_extent_exceeds_known_capacity"
         and disp("dc_over") == "relationship_unresolved"),
        # EXACT bound
        ("MATRIX exact, extent<=cap -> deterministic_complete (synth 50<=64)",
         disp("dc_synth_exact_fits") == "deterministic_complete"
         and by["dc_synth_exact_fits"]["extent_bound"] == "exact"),
        ("MATRIX exact, extent>cap -> proven_oversized (synth 200>64)",
         disp("dc_synth_exact_over") == "proven_oversized"
         and by["dc_synth_exact_over"]["extent_bound"] == "exact"),
        # LOWER (min) bound -- the corrected rows
        ("MATRIX min, extent<=cap -> open (lower_bound_below_capacity_inconclusive), NOT "
         "deterministic (a lower bound below capacity cannot establish safety)",
         route("dc_synth_atleast_below") == "open_candidate"
         and reason("dc_synth_atleast_below") == "lower_bound_below_capacity_inconclusive"
         and disp("dc_synth_atleast_below") == "relationship_unresolved"),
        ("MATRIX min, extent>cap -> proven_oversized (synth >=200 > 64)",
         disp("dc_synth_atleast_over") == "proven_oversized"),

        # LZ4_decompress_fast: max upper bound + DESTINATION PRECONDITION (not exact write)
        ("FAST originalSize<=cap -> deterministic_complete (upper bound within dst)",
         disp("dc_fast_fits") == "deterministic_complete"),
        ("FAST originalSize>cap -> open (decoder_destination_precondition_violated), NOT "
         "proven_oversized (may stop early on malformed input)",
         route("dc_fast_over") == "open_candidate"
         and reason("dc_fast_over") == "decoder_destination_precondition_violated"
         and disp("dc_fast_over") == "relationship_unresolved"),

        # bounded via sizeof / heap / partial (all max bounds)
        ("BOUNDED via sizeof(dst) -> deterministic_complete", disp("dc_sizeof") == "deterministic_complete"),
        ("BOUNDED via heap literal allocation -> deterministic_complete",
         disp("dc_heap") == "deterministic_complete"
         and by["dc_heap"]["dest_capacity_prov"] == "heap_literal_allocation"),
        ("BOUNDED partial-write contract -> deterministic_complete", disp("dc_partial") == "deterministic_complete"),

        # UNRESOLVED (recognized, relationship open)
        ("UNRESOLVED symbolic extent -> write_extent_unresolved", reason("dc_symbolic") == "write_extent_unresolved"),
        ("UNRESOLVED dest capacity (param dst) -> capacity_of_dest_unresolved",
         reason("dc_param_dst") == "capacity_of_dest_unresolved"),
        ("STATEFUL inflate -> recognized; extent=PRE-call avail_out (not bytes written)",
         reason("dc_inflate") == "decoder_capacity_in_state_object"
         and by["dc_inflate"]["extent_field"] == "avail_out"
         and by["dc_inflate"]["extent_field_meaning"] == "pre_call_remaining_capacity"),

        # NO manufactured proven_oversized on a real decoder (only the synthetic unconditional
        # contract yields proven_oversized).
        ("NO real-decoder proven_oversized: proven_oversized only from synthetic unconditional",
         all(o["function"].startswith("dc_synth_")
             for o in ops if o.get("disposition") == "proven_oversized")),

        # ROLE MAPPING by position + declaration identity
        ("ROLES by position: dst=arg1, input=arg0, len=arg2, capacity=arg3 (safe)",
         by["dc_fits"]["roles"]["destination"]["arg_index"] == 1
         and by["dc_fits"]["roles"]["available_capacity"]["arg_index"] == 3),
        ("ROLE decl identity: inflate state_object resolves to the z_streamp param",
         by["dc_inflate"]["roles"]["state_object"]["decl_identity"][0] == "param"),

        # SIGNATURE, not NAME (call-shape gate)
        ("SIGNATURE not name: arity mismatch -> not bound", "dc_arity" not in by),
        ("SIGNATURE not name: local shadow (has body) -> not bound", "dc_local_deflate" not in by),
        ("NEG plain copy loop -> no cap4 op", "dc_notdecoder" not in by),
        ("EXACTLY 14 decoder ops recognized (3 no-ops excluded)", len(ops) == 14),
    ]

    # ---- TRUSTED SCAN-BOUND ATTESTATION CHANNEL --------------------------------------------
    # (identity) no attestation -> call shape recognized, contract identity unresolved
    clear_attestation(cpp)
    unatt = {o["function"]: o for o in C.analyze_decoder_calls(cpp)}
    # (not scan-bound) attestation with a WRONG scan fingerprint -> rejected -> identity unresolved
    write_attestation(cpp, VERIFIED, scan_bound=False)
    notbound = {o["function"]: o for o in C.analyze_decoder_calls(cpp)}
    # (version) attested but version not in any contract's validated family (all libraries)
    badver_libs = {"lz4": {"version": "1.8.0", "established_by": "pinned_build",
                           "header_sha256": HDR["lz4"]},
                   "zlib": {"version": "1.2.0", "established_by": "pinned_build",
                            "header_sha256": HDR["zlib"]},
                   "synthetic_testonly": {"version": "0.9.0", "established_by": "pinned_build",
                                          "header_sha256": HDR["synthetic_testonly"]}}
    write_attestation(cpp, badver_libs)
    badver = {o["function"]: o for o in C.analyze_decoder_calls(cpp)}
    # (fingerprint) validated version but the build header hash does not match the authority
    badfp_libs = dict(VERIFIED)
    badfp_libs["lz4"] = {"version": "1.9.4", "established_by": "pinned_build",
                         "header_sha256": "dead" * 16}
    write_attestation(cpp, badfp_libs)
    badfp = {o["function"]: o for o in C.analyze_decoder_calls(cpp)}
    write_attestation(cpp, VERIFIED)   # restore verified state
    checks += [
        ("CHANNEL identity: no attestation -> contract_identity_unresolved (shape recognized)",
         unatt["dc_fits"]["reason"] == "contract_identity_unresolved" and len(unatt) == 14
         and unatt["dc_fits"]["roles"]["destination"]["arg_index"] == 1),
        ("CHANNEL not-scan-bound: wrong scan fingerprint -> attestation REJECTED (identity "
         "unresolved), i.e. not caller-replayable",
         notbound["dc_fits"]["reason"] == "contract_identity_unresolved"),
        ("CHANNEL version: attested version not in validated family -> contract_version_unresolved",
         badver["dc_fits"]["reason"] == "contract_version_unresolved"
         and all(o["disposition"] == "relationship_unresolved" for o in badver.values())),
        ("CHANNEL fingerprint: build header hash != authority -> contract_build_fingerprint_mismatch",
         badfp["dc_fits"]["reason"] == "contract_build_fingerprint_mismatch"
         and badfp["dc_inflate"]["reason"] == "decoder_capacity_in_state_object"),  # zlib still ok
        ("CHANNEL verified -> contracts applied (deterministic + synthetic proven_oversized exist)",
         disp("dc_fits") == "deterministic_complete"
         and disp("dc_synth_exact_over") == "proven_oversized"),
    ]

    # provenance hash FAIL CLOSED: a tampered excerpt drops ONLY that contract.
    tmp_auth = tempfile.mkdtemp()
    shutil.copytree(C.AUTH_DIR, os.path.join(tmp_auth, "authorities"))
    open(os.path.join(tmp_auth, "authorities",
                      "lz4-1.9.4-LZ4_decompress_safe.txt"), "a").write("\n/* tampered */\n")
    adir2 = os.path.join(tmp_auth, "authorities")
    _bn2, prov2 = C.load_contracts(adir2)
    fc = {o["function"]: o for o in C.analyze_decoder_calls(cpp, auth_dir=adir2)}
    checks += [
        ("FAIL CLOSED: tampered excerpt -> that contract hash_mismatch",
         any(p["id"] == "lz4.LZ4_decompress_safe" and p["provenance"] == "hash_mismatch"
             for p in prov2)),
        ("FAIL CLOSED: dropped contract's calls unrecognized (dc_fits/dc_over gone)",
         "dc_fits" not in fc and "dc_over" not in fc),
        ("FAIL CLOSED: intact contracts still operate (synth + partial + inflate remain)",
         "dc_synth_exact_over" in fc and "dc_partial" in fc and "dc_inflate" in fc),
    ]

    # ADDITIVE / SEPARATION
    cur_keys = {WSD.identity_key(o) for o in AUD.cursor_sites(cpp)}
    cap4_keys = {WSD.identity_key({"identity": o["identity"]}) for o in ops}
    cap3_on_decoders = M.analyze_member_walks(cpp)
    bare = tempfile.mkdtemp()
    open(os.path.join(bare, "b.c"), "w").write(
        "#include <string.h>\nvoid f(char*s,int n){char d[50];memcpy(d,s,n);}\n")
    bare_cpp = scan(bare)
    write_attestation(bare_cpp, VERIFIED)
    n_bare = len(C.analyze_decoder_calls(bare_cpp))
    checks += [
        ("SEPARATION: cap4 decoder-call sites disjoint from cursor-recognized sites",
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
