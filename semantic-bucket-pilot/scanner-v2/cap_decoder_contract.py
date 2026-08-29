#!/usr/bin/env python3
"""Capability 4 -- EXTERNAL DECODER CONTRACTS  (NO model calls).

A library decoder/decompressor call writes into a caller-provided destination buffer, but
the number of bytes written is governed by the API's DOCUMENTED CONTRACT, not by a plain
memcpy-style length argument. This capability recognizes such calls and -- only when the
contract lets us bound the maximum write extent against an independently-established
destination capacity -- routes them; otherwise it recognizes the operation and leaves the
relationship UNRESOLVED. It never claims VULNERABLE and never claims safe without a proof.

DELIBERATELY NARROW boundary (soundness over coverage):
  * A contract is tied to a specific LIBRARY + EXACT VALIDATED VERSION + EXACT SIGNATURE. Name
    + arity + "no local definition" is only a CALL-SHAPE match; it does NOT establish library
    identity (a same-named external symbol could be another library, an interposed symbol, a
    project function in another translation unit, or a same-signature look-alike). Applying a
    contract additionally requires ESTABLISHED PROVENANCE of the linked library and version --
    supplied as an operator BUILD ATTESTATION (pinned build / linked package / verified
    header). Without it, the call SHAPE is recognized but the contract identity is left
    unresolved (`contract_identity_unresolved`); with library identity but no validated
    version, `contract_version_unresolved`.
  * Version is NOT extrapolated. One archived header validates only its OWN version family
    (e.g. lz4 1.9.4, zlib 1.3.1); a broader range would require archiving+validating the
    boundary versions. The attested version must be in the contract's `validated_versions`.
  * Each contract's authoritative provenance is an ARCHIVED header/doc excerpt, sliced verbatim
    from the pinned upstream tag, hashed; the registry VERIFIES those hashes at load and drops
    a contract (fail closed) if its excerpt has changed. See
    cap_controls/cap4_contracts/authorities/PROVENANCE.json.
  * Every argument is mapped by POSITION and by DECLARATION IDENTITY (ref-target), into the
    roles: destination, available_capacity / exact_output_size, input, input_length,
    state_object.
  * PRE-call vs POST-call meanings are modeled explicitly. zlib's `avail_out` is REMAINING
    free capacity BEFORE the call and is DECREMENTED by the bytes written AFTER the call --
    it is NOT "bytes written". Because that pre-state field is not tracked here, an inflate/
    deflate call is RECOGNIZED but its write extent is left unresolved (never mis-read).
  * AN EXCESSIVE MAXIMUM IS NOT A PROVEN OVERFLOW. A decoder's documented write extent is a
    per-call bound with a DIRECTION: `max` (upper bound: actual_writes <= extent) or
    `exact`/`min` (lower bound: actual_writes >= extent). `extent <= capacity` is always a
    deterministic in-capacity proof. `extent > capacity` is proven_oversized ONLY for a
    lower/exact bound (the API will write >= extent > capacity); for a MAX bound it is merely
    an unsafe configuration -- the input might decode to far less -- so it is
    `decoder_extent_exceeds_known_capacity` / relationship_unresolved, NEVER proven_oversized.
  * Return codes, partial writes, repeated/stateful calls, callbacks, and error exits are
    recorded on each contract and respected.

Additive: emits attribution="call_site_summary", capability="decoder_contract" records with a
robust write-site identity (the decoder CALL site). Its sites are library-decoder calls that
Capabilities 1-3 and the frozen producers never route, so it moves no existing verdict.
"""
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import oob_runtime_capacity_v2 as v2
import allocation_extent as AE
import cap_write_site_dedup as WSD

AUTH_DIR = os.path.join(HERE, "cap_controls", "cap4_contracts", "authorities")
_SIZEOF = re.compile(r"^\s*sizeof\s*\(\s*([A-Za-z_]\w*)\s*\)\s*$")
INT_RE = re.compile(r"^\s*[+-]?\d+\s*$")
BYTE_TYPES = ("char", "unsigned char", "signed char", "int8_t", "uint8_t", "byte")


# -- CONTRACT REGISTRY --------------------------------------------------------------------
# Each contract is tied to (library, validated_versions, exact signature). `validated_versions`
# is the version family the ARCHIVED header actually validates -- NOT extrapolated to a broader
# range. `roles` maps an argument INDEX to a role. `write_extent` says how the per-call write
# count is bounded AND in which DIRECTION:
#   {"kind":"arg_bytes","bound":"max","arg":i}   -> actual_writes <= value of arg i (upper).
#   {"kind":"arg_bytes","bound":"exact","arg":i} -> actual_writes == value of arg i (exact;
#                                                    a lower bound for overflow purposes).
#   {"kind":"state_field_prestate",...}          -> bounded by a struct field's PRE-call value
#                                                    not tracked here -> unresolved.
# Only a lower/exact bound > capacity is a PROVEN overflow; a max bound > capacity is an unsafe
# configuration (relationship_unresolved), never proven_oversized.
# `authority` names the archived excerpt + its sha256 (verified at load).
CONTRACTS = [
    {"id": "lz4.LZ4_decompress_safe", "library": "lz4", "validated_versions": ["1.9.4"],
     "signature": {"name": "LZ4_decompress_safe", "return_type": "int",
                   "params": ["const char *", "char *", "int", "int"]},
     "roles": {0: "input", 1: "destination", 2: "input_length", 3: "available_capacity"},
     "capacity_semantics": "arg3 dstCapacity = size of dst BEFORE the call (explicit arg); the "
                           "API is contractually guaranteed never to write outside dst, i.e. "
                           "AT MOST dstCapacity bytes (an UPPER bound; it may write far less).",
     "write_extent": {"kind": "arg_bytes", "bound": "max", "arg": 3},
     "return_codes": ">0 = bytes decompressed (== bytes written, <= dstCapacity); "
                     "<0 = error (malformed input or dst too small); decoding stops.",
     "partial_writes": "on the <0 error path decoding stops early; bytes already written are "
                       "still <= dstCapacity (the upper bound holds on every path).",
     "stateful": False, "callbacks": False,
     "authority": {"excerpt_file": "lz4-1.9.4-LZ4_decompress_safe.txt",
                   "sha256": "71a1710d7b659a00a7c8201f829ed4ddfada184c11873fba6da08ccec7dddf65"}},

    {"id": "lz4.LZ4_decompress_safe_partial", "library": "lz4", "validated_versions": ["1.9.4"],
     "signature": {"name": "LZ4_decompress_safe_partial", "return_type": "int",
                   "params": ["const char *", "char *", "int", "int", "int"]},
     "roles": {0: "input", 1: "destination", 2: "input_length",
               3: "target_output_size", 4: "available_capacity"},
     "capacity_semantics": "arg4 dstCapacity = size of dst BEFORE the call; the API writes AT "
                           "MOST dstCapacity bytes (upper bound).",
     "write_extent": {"kind": "arg_bytes", "bound": "max", "arg": 4},
     "return_codes": ">=0 = bytes written into dst (<= dstCapacity); <0 = error.",
     "partial_writes": "writes up to dstCapacity even when it stops at targetOutputSize; the "
                       "dstCapacity upper bound holds on every path.",
     "stateful": False, "callbacks": False,
     "authority": {"excerpt_file": "lz4-1.9.4-LZ4_decompress_safe_partial.txt",
                   "sha256": "c84b9e21aec98f5bf891af8d28c31ed0b5072e0ae4f5816c9cffb6b280d4ac65"}},

    {"id": "lz4.LZ4_decompress_fast", "library": "lz4", "validated_versions": ["1.9.4"],
     "signature": {"name": "LZ4_decompress_fast", "return_type": "int",
                   "params": ["const char *", "char *", "int"]},
     "roles": {0: "input", 1: "destination", 2: "required_output_size"},
     "capacity_semantics": "arg2 originalSize = the intended decompressed size; the API REQUIRES "
                           "dst to be >= originalSize (a DESTINATION PRECONDITION) and, given "
                           "that, never writes past dst. It is NOT an unconditional exact write: "
                           "malformed input makes it stop early and return <0, so actual writes "
                           "are <= originalSize (an UPPER bound). originalSize > dst capacity is "
                           "a precondition VIOLATION (unsafe/contract-invalid), not a proven "
                           "overflow -- malformed input might stop before exceeding the buffer. "
                           "(Deprecated + unsafe upstream.)",
     "write_extent": {"kind": "arg_bytes", "bound": "max", "arg": 2},
     "destination_precondition": {"min_capacity_arg": 2},
     "return_codes": "return = bytes read from src (== compressed size); <0 = error (malformed "
                     "input stops decoding early). dst receives at most originalSize bytes.",
     "partial_writes": "on the <0 malformed path it stops early, writing fewer than "
                       "originalSize bytes; the originalSize UPPER bound holds on every path.",
     "stateful": False, "callbacks": False,
     "authority": {"excerpt_file": "lz4-1.9.4-LZ4_decompress_fast.txt",
                   "sha256": "a6ad113aff7df32c626268b42daa1a1c47852a7e92e31fe66cf52acd6c0e3060"}},

    # SYNTHETIC test-only contracts (library synthetic_testonly, never linked in a real build):
    # the ONLY way to exercise genuinely-unconditional exact / lower-bound routing, since real
    # decoders can stop early on malformed input. Authority is the archived synthetic spec.
    {"id": "synthetic_testonly.synth_fill_exact", "library": "synthetic_testonly",
     "validated_versions": ["1.0.0"],
     "signature": {"name": "synth_fill_exact", "return_type": "void",
                   "params": ["char *", "int"]},
     "roles": {0: "destination", 1: "exact_output_size"},
     "capacity_semantics": "arg1 = the number of bytes written; the API UNCONDITIONALLY writes "
                           "EXACTLY arg1 bytes on every execution (no error/early-stop path).",
     "write_extent": {"kind": "arg_bytes", "bound": "exact", "arg": 1},
     "return_codes": "void; no error path.", "partial_writes": "none (unconditional).",
     "stateful": False, "callbacks": False,
     "authority": {"excerpt_file": "synthetic-testonly-1.0.0-spec.txt",
                   "sha256": "4a874ca39e12a2d8e7af8202051fa334de593d5eb9a89e8925ca6742ac80d82a"}},

    {"id": "synthetic_testonly.synth_fill_atleast", "library": "synthetic_testonly",
     "validated_versions": ["1.0.0"],
     "signature": {"name": "synth_fill_atleast", "return_type": "void",
                   "params": ["char *", "int"]},
     "roles": {0: "destination", 1: "min_output_size"},
     "capacity_semantics": "arg1 = a LOWER bound; the API UNCONDITIONALLY writes AT LEAST arg1 "
                           "bytes on every execution (possibly more).",
     "write_extent": {"kind": "arg_bytes", "bound": "min", "arg": 1},
     "return_codes": "void; no error path.", "partial_writes": "none (unconditional).",
     "stateful": False, "callbacks": False,
     "authority": {"excerpt_file": "synthetic-testonly-1.0.0-spec.txt",
                   "sha256": "4a874ca39e12a2d8e7af8202051fa334de593d5eb9a89e8925ca6742ac80d82a"}},

    {"id": "zlib.inflate", "library": "zlib", "validated_versions": ["1.3.1"],
     "signature": {"name": "inflate", "return_type": "int",
                   "params": ["z_streamp", "int"]},
     "roles": {0: "state_object", 1: "flush_mode"},
     "capacity_semantics": "destination + capacity live in the z_stream: next_out (dst) and "
                           "avail_out (REMAINING free space BEFORE the call). POST-call, "
                           "avail_out is DECREMENTED by the bytes written and total_out is "
                           "incremented -- avail_out is NOT bytes-written. The per-call max "
                           "write extent is the PRE-call avail_out.",
     "write_extent": {"kind": "state_field_prestate", "field": "avail_out",
                      "meaning": "pre_call_remaining_capacity"},
     "return_codes": "Z_OK / Z_STREAM_END / Z_NEED_DICT progress; Z_BUF_ERROR (no progress, "
                     "not fatal); Z_DATA_ERROR / Z_MEM_ERROR / Z_STREAM_ERROR errors.",
     "partial_writes": "STATEFUL + REPEATED: called in a loop, each call consumes avail_in / "
                       "produces up to avail_out and updates next_out/avail_out; the caller "
                       "refills the output buffer between calls.",
     "stateful": True, "callbacks": False,
     "authority": {"excerpt_file": "zlib-1.3.1-inflate.txt",
                   "sha256": "cb7e42a8ef44bc9f231acda8d6483ba849b0559b98d80f8628d2a2f11bc017b9"}},

    {"id": "zlib.deflate", "library": "zlib", "validated_versions": ["1.3.1"],
     "signature": {"name": "deflate", "return_type": "int",
                   "params": ["z_streamp", "int"]},
     "roles": {0: "state_object", 1: "flush_mode"},
     "capacity_semantics": "same z_stream next_out/avail_out pre/post semantics as inflate; "
                           "avail_out is pre-call remaining capacity, decremented after.",
     "write_extent": {"kind": "state_field_prestate", "field": "avail_out",
                      "meaning": "pre_call_remaining_capacity"},
     "return_codes": "Z_OK / Z_STREAM_END progress; Z_BUF_ERROR (no progress, not fatal); "
                     "Z_STREAM_ERROR error.",
     "partial_writes": "STATEFUL + REPEATED, as inflate.",
     "stateful": True, "callbacks": False,
     "authority": {"excerpt_file": "zlib-1.3.1-deflate.txt",
                   "sha256": "f3060f732c4af15558e51c32db715ca298a8600af250436419747b7dac859f1f"}},
]


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for ch in iter(lambda: f.read(1 << 20), b""):
            h.update(ch)
    return h.hexdigest()


def load_contracts(auth_dir=AUTH_DIR):
    """Return the contracts whose ARCHIVED authority excerpt is present AND whose sha256
    matches the registry (a contract is only trusted while it is bound to the exact
    authoritative text it was derived from). A contract with a missing/altered excerpt is
    DROPPED (fail closed) -- it is never applied on unverified provenance. Returns
    (contracts_by_name, provenance_report)."""
    by_name, report = {}, []
    for ct in CONTRACTS:
        af = os.path.join(auth_dir, ct["authority"]["excerpt_file"])
        status = "missing"
        if os.path.exists(af):
            actual = _sha256_file(af)
            status = "ok" if actual == ct["authority"]["sha256"] else "hash_mismatch"
        report.append({"id": ct["id"], "authority": ct["authority"]["excerpt_file"],
                       "provenance": status})
        if status == "ok":
            by_name.setdefault(ct["signature"]["name"], []).append(ct)
    return by_name, report


def _lit_bytes(code):
    return int(code) if INT_RE.match(code or "") else None


def _resolve_decl(arg, index):
    """Declaration node of an argument's pointer base, via Joern ref-target (never by name)."""
    idid = WSD._descend_to_identifier(arg, index["call_by_id"])
    ident = index["ident_by_id"].get(idid) if idid else None
    refs = (ident.get("ref_target_ids") if ident else None) or []
    return refs[0] if len(refs) == 1 else None


def _dest_capacity(dest_arg, dest_code, fid, index, stack_ext, heap_ext):
    """Independently-established BYTE capacity of the destination, or (None, reason). Only a
    fixed byte-array local or a literal-count byte allocation qualifies; a param / struct
    field / alias / symbolic allocation stays UNRESOLVED (never assumed)."""
    base = WSD._root_ident(dest_code)
    if dest_code.strip() != base:      # dst is an expression (dst+off, &a[i], ...) -> not bound
        return None, "destination_not_bare_base"
    decl = _resolve_decl(dest_arg, index)
    if decl is not None and (fid, decl) in stack_ext:
        e = stack_ext[(fid, decl)]
        if e["element_type"] in BYTE_TYPES:
            return {"bytes": e["element_count"], "prov": "stack_fixed_array"}, "ok"
        return None, "destination_not_byte_array"
    he = heap_ext.get((fid, base))
    if (he and he.get("establishment_status") == "ESTABLISHED"
            and isinstance(he.get("extent_in_bytes"), int)):
        # extent_in_bytes is the total BYTE capacity of the allocation (byte-element buffer);
        # the decoder writes bytes, so this is the right capacity to compare against.
        if he.get("element_width") == 1:
            return {"bytes": he["extent_in_bytes"], "prov": "heap_literal_allocation"}, "ok"
        return None, "destination_not_byte_array"
    return None, "capacity_of_dest_unresolved"


def _decoder_site_identity(c, index):
    """Robust cross-run identity of a decoder CALL site (the physical write is inside the
    library, so the call is the site). site column via occurrence pairing on the source line;
    destination declaration via ref-target. Fail closed to verifiable=False when unresolved."""
    fid = c.get("enclosing_function_id")
    f = index["funcs"].get(fid, {})
    txt = WSD._line_text(index["root"], WSD._norm_path(f.get("file")), c.get("line"))
    cols = WSD._occurrence_columns(txt, c.get("name")) if txt is not None else []
    # pair by call ordinal among same-callee calls on this line
    same_line = sorted([x for x in index["call_by_id"].values()
                        if x.get("enclosing_function_id") == fid
                        and x.get("line") == c.get("line") and x.get("name") == c.get("name")],
                       key=lambda x: x.get("id"))
    site = ("unverifiable",)
    if txt is not None and len(cols) == len(same_line):
        pos = {x.get("id"): col for x, col in zip(same_line, cols)}
        if c.get("id") in pos:
            site = ("call_col", pos[c.get("id")])
    return {"file": WSD._norm_path(f.get("file")),
            "function": [f.get("name"), f.get("line"), f.get("line_end")],
            "line": c.get("line"), "site": list(site),
            "write": ["decoder_call", c.get("name")],
            "verifiable": site[0] != "unverifiable"}


def _role_map(c, ct, index):
    """Map every contract role to {arg_index, code, decl_identity} by POSITION + ref-target."""
    args = sorted(c.get("arguments", []), key=lambda a: a.get("index", 0))
    roles = {}
    for i, role in ct["roles"].items():
        if i >= len(args):
            continue
        a = args[i]
        decl = _resolve_decl(a, index)
        ser, ok = WSD.serialize_declaration(decl, index)
        roles[role] = {"arg_index": i, "code": WSD._norm_code(a.get("code") or ""),
                       "decl_identity": list(ser), "decl_verifiable": ok}
    return roles


def _prov_fingerprints(auth_dir):
    """(library, version) -> full-file SHA-256 of the authoritative header/spec, from the
    archived PROVENANCE.json. This is the fingerprint the linked-build's header must match."""
    fp = {}
    pj = os.path.join(auth_dir, "PROVENANCE.json")
    if not os.path.exists(pj):
        return fp
    for a in json.load(open(pj)).get("authorities", []):
        tag = (a.get("upstream_tag") or "").lstrip("v")   # "v1.9.4" -> "1.9.4"
        fp[(a.get("library"), tag)] = a.get("full_file_sha256")
    return fp


def load_build_attestation(cpp):
    """Load the build attestation from the TRUSTED, SCAN-BOUND channel: a `build_attestation.json`
    emitted into the scan output directory (a sibling of cpp.json / cpg.bin) by the scan
    pipeline -- NOT passed in as caller-controlled contract JSON. It is rejected (treated as
    absent) unless it is FINGERPRINTED to THIS scan: its recorded cpp.json (and cpg.bin) SHA-256
    must match the artifacts actually analyzed, so an attestation cannot be replayed against a
    different scan. Returns (attestation_dict, status)."""
    if not isinstance(cpp, str):
        return None, "no_scan_dir"
    sdir = os.path.dirname(os.path.abspath(cpp))
    ap = os.path.join(sdir, "build_attestation.json")
    if not os.path.exists(ap):
        return None, "no_attestation"
    try:
        a = json.load(open(ap))
    except Exception:
        return None, "attestation_unreadable"
    scan = a.get("scan", {})
    if scan.get("cpp_sha256") != _sha256_file(cpp):
        return None, "attestation_not_scan_bound"      # replayed / wrong scan -> reject
    cpg = os.path.join(sdir, "cpg.bin")
    if os.path.exists(cpg) and scan.get("cpg_sha256") not in (None, _sha256_file(cpg)):
        return None, "attestation_not_scan_bound"
    return a, "ok"


def _library_identity(library, validated_versions, attestation, prov_fp):
    """Establish the linked library IDENTITY + VERSION for a contract from the SCAN-BOUND build
    attestation (already verified as bound to this scan). A same-named external symbol is not
    proof of provenance. Establishment additionally requires the attested build's header
    FINGERPRINT to match the archived authority's full-file hash for that validated version --
    i.e. the scan's build actually used the header the contract was validated against. Returns
    (state, detail)."""
    libs = (attestation or {}).get("libraries", {})
    bi = libs.get(library)
    if not bi:
        return "identity_unresolved", {"library": library, "attested": False}
    ver = bi.get("version")
    if ver is None or ver not in validated_versions:
        return "version_unresolved", {"library": library, "attested_version": ver,
                                      "validated_versions": validated_versions,
                                      "established_by": bi.get("established_by")}
    expected = prov_fp.get((library, ver))
    if expected is None or bi.get("header_sha256") != expected:
        return "fingerprint_mismatch", {"library": library, "attested_version": ver,
                                        "attested_header_sha256": bi.get("header_sha256"),
                                        "expected_header_sha256": expected,
                                        "established_by": bi.get("established_by")}
    return "established", {"library": library, "version": ver,
                           "established_by": bi.get("established_by"),
                           "header_sha256": bi.get("header_sha256")}


def analyze_decoder_calls(cpp, auth_dir=AUTH_DIR):
    """Library identity comes ONLY through the trusted scan-bound build attestation
    (load_build_attestation), never a caller-supplied dict. A contract's write-extent routing is
    applied only when the library identity + version + build-header fingerprint are established;
    otherwise the call shape is recognized and the contract identity/version is left unresolved."""
    d = json.load(open(cpp)) if isinstance(cpp, str) else cpp
    by_name, _prov = load_contracts(auth_dir)
    attestation, _att_status = load_build_attestation(cpp)
    prov_fp = _prov_fingerprints(auth_dir)
    index = WSD.build_index(d)
    stack_ext = v2.compute_stack_fixed_array_extents(d)
    heap_ext = AE.compute_allocation_extents(d)
    # user-defined (non-external, with body) function names shadow any library contract:
    # the contract is tied to the LIBRARY, not the name.
    local_defs = {f.get("name") for f in d.get("functions", [])
                  if not f.get("is_external") and f.get("line_end")}

    ops = []
    for c in d.get("calls", []):
        name = c.get("name")
        cands = by_name.get(name)
        if not cands:
            continue
        args = sorted(c.get("arguments", []), key=lambda a: a.get("index", 0))
        # CALL-SHAPE match: the callee must NOT be a user-defined same-named function, and the
        # call arity must equal the contract's parameter count. (This is shape only, NOT proof
        # of library identity -- that is checked next.)
        if name in local_defs:
            continue
        ct = next((x for x in cands if len(x["signature"]["params"]) == len(args)), None)
        if ct is None:
            continue

        fid = c.get("enclosing_function_id")
        roles = _role_map(c, ct, index)
        ident = _decoder_site_identity(c, index)
        rec = {"capability": "decoder_contract", "attribution": "call_site_summary",
               "function": index["funcs"].get(fid, {}).get("name"), "line": c.get("line"),
               "callee": name, "contract_id": ct["id"], "library": ct["library"],
               "validated_versions": ct["validated_versions"], "roles": roles,
               "stateful": ct["stateful"], "callbacks": ct["callbacks"],
               "identity": ident, "node_id": c.get("id")}

        # ---- LIBRARY IDENTITY provenance gate (name+arity is only a call shape) -------------
        idstate, idinfo = _library_identity(ct["library"], ct["validated_versions"],
                                            attestation, prov_fp)
        rec["library_identity"] = idinfo
        if idstate == "identity_unresolved":
            rec.update(route="additional_evidence_required",
                       reason="contract_identity_unresolved",
                       disposition="relationship_unresolved",
                       note="external callee matches the contract call shape, but the linked "
                            "library identity is not established by the scan-bound build "
                            "attestation; a same-named symbol is not proof of provenance")
            ops.append(rec); continue
        if idstate == "version_unresolved":
            rec.update(route="additional_evidence_required",
                       reason="contract_version_unresolved",
                       disposition="relationship_unresolved",
                       note="library identity established but the version is not in the "
                            "archived contract's validated family %s (attested %r); one header "
                            "validates only its own version"
                            % (ct["validated_versions"], idinfo.get("attested_version")))
            ops.append(rec); continue
        if idstate == "fingerprint_mismatch":
            rec.update(route="additional_evidence_required",
                       reason="contract_build_fingerprint_mismatch",
                       disposition="relationship_unresolved",
                       note="attested version is in the validated family, but the build's header "
                            "fingerprint does not match the archived authority hash for it -- the "
                            "scan's build did not use the validated header")
            ops.append(rec); continue

        we = ct["write_extent"]
        # ---- zlib avail_out: pre-call remaining capacity, NOT tracked -> recognize, unresolved
        if we["kind"] == "state_field_prestate":
            state = roles.get("state_object", {})
            rec.update(route="additional_evidence_required",
                       reason="decoder_capacity_in_state_object",
                       disposition="relationship_unresolved",
                       write_extent="unresolved_prestate_field", extent_bound=None,
                       extent_field=we["field"], extent_field_meaning=we["meaning"],
                       state_object=state.get("code"),
                       note="write extent is the PRE-call %s (remaining capacity) of the "
                            "z_stream, which is not tracked; not treated as bytes written"
                            % we["field"])
            ops.append(rec); continue

        # ---- arg_bytes: the extent argument, with a DIRECTION (max upper / exact lower) ------
        bound = we.get("bound", "max")   # "max" -> upper bound; "exact"/"min" -> lower bound
        ext_i = we["arg"]
        cap_code = WSD._norm_code(args[ext_i].get("code") or "") if ext_i < len(args) else ""
        dest_role = roles.get("destination", {})
        dest_arg = args[dest_role["arg_index"]] if "destination" in roles else None
        dest_code = dest_role.get("code", "")
        dcap, why = (_dest_capacity(dest_arg, dest_code, fid, index, stack_ext, heap_ext)
                     if dest_arg is not None else (None, "no_destination_arg"))

        # extent value: literal bytes, or sizeof(dest) which binds to the exact capacity.
        extent = _lit_bytes(cap_code)
        m = _SIZEOF.match(cap_code)
        extent_is_sizeof_dest = bool(m and dcap is not None
                                     and m.group(1) == WSD._root_ident(dest_code))

        common = dict(extent_bound=bound, extent_arg=cap_code, dest=dest_code)
        if extent is None and not extent_is_sizeof_dest:
            rec.update(route="additional_evidence_required", reason="write_extent_unresolved",
                       disposition="relationship_unresolved", write_extent="symbolic",
                       dest_capacity=(dcap["bytes"] if dcap else None), **common,
                       note="decoder extent argument is symbolic; write extent not bounded")
            ops.append(rec); continue
        if dcap is None:
            rec.update(route="additional_evidence_required", reason=why,
                       disposition="relationship_unresolved",
                       write_extent=(extent if not extent_is_sizeof_dest else "sizeof_dest"),
                       dest_capacity=None, **common,
                       note="write extent bounded by contract, but destination capacity is not "
                            "independently established")
            ops.append(rec); continue

        ext_bytes = dcap["bytes"] if extent_is_sizeof_dest else extent
        capN = dcap["bytes"]
        below = ext_bytes <= capN
        # CORRECT bound-direction matrix:
        #                      extent <= capacity        extent > capacity
        #   max  (actual<=U):  deterministic within      unresolved (config/precondition)
        #   exact(actual==E):  deterministic within      proven_oversized
        #   min  (actual>=L):  UNRESOLVED (L below cap    proven_oversized
        #                      says nothing about a max)
        # A lower bound BELOW capacity cannot establish safety -- actual writes may be far larger.
        has_precond = "destination_precondition" in ct
        if bound == "max":
            if below:
                rec.update(route="deterministic_complete",
                           reason="write_extent_within_destination_capacity",
                           disposition="deterministic_complete", write_extent=ext_bytes,
                           dest_capacity=capN, dest_capacity_prov=dcap["prov"], **common,
                           note=("sizeof(dst) as capacity -> API cannot write past dst"
                                 if extent_is_sizeof_dest else
                                 "upper-bound write extent %d <= %d-byte dst -> within capacity"
                                 % (ext_bytes, capN)))
            elif has_precond:
                # e.g. LZ4_decompress_fast: originalSize > dst is a destination PRECONDITION
                # violation (unsafe / contract-invalid), but malformed input might stop early
                # before exceeding the buffer -> NOT a proven overflow.
                rec.update(route="open_candidate",
                           reason="decoder_destination_precondition_violated",
                           disposition="relationship_unresolved", write_extent=ext_bytes,
                           dest_capacity=capN, dest_capacity_prov=dcap["prov"], **common,
                           note="required output size %d > %d-byte dst -> destination "
                                "precondition violated (unsafe/contract-invalid), but not a "
                                "proven overflow (may stop early on malformed input)"
                                % (ext_bytes, capN))
            else:
                rec.update(route="open_candidate",
                           reason="decoder_extent_exceeds_known_capacity",
                           disposition="relationship_unresolved", write_extent=ext_bytes,
                           dest_capacity=capN, dest_capacity_prov=dcap["prov"], **common,
                           note="upper-bound write extent %d > %d-byte dst -> unsafe "
                                "configuration, but actual writes may be far less -> not proven "
                                "oversized" % (ext_bytes, capN))
        elif bound == "exact":
            if below:
                rec.update(route="deterministic_complete",
                           reason="write_extent_within_destination_capacity",
                           disposition="deterministic_complete", write_extent=ext_bytes,
                           dest_capacity=capN, dest_capacity_prov=dcap["prov"], **common,
                           note="exact write extent %d <= %d-byte dst -> within capacity"
                                % (ext_bytes, capN))
            else:
                rec.update(route="range_arithmetic_review",
                           reason="write_extent_exceeds_destination_capacity",
                           disposition="proven_oversized", write_extent=ext_bytes,
                           dest_capacity=capN, dest_capacity_prov=dcap["prov"], **common,
                           note="exact write extent %d > %d-byte dst -> the API writes past dst"
                                % (ext_bytes, capN))
        else:  # bound == "min" (lower bound)
            if below:
                # LOWER bound below capacity establishes NOTHING about safety (actual >= L, but
                # the true maximum is unknown and may exceed capacity) -> unresolved.
                rec.update(route="open_candidate",
                           reason="lower_bound_below_capacity_inconclusive",
                           disposition="relationship_unresolved", write_extent=ext_bytes,
                           dest_capacity=capN, dest_capacity_prov=dcap["prov"], **common,
                           note="lower-bound write extent %d <= %d-byte dst -> actual writes are "
                                ">= %d with no known maximum -> safety NOT established"
                                % (ext_bytes, capN, ext_bytes))
            else:
                rec.update(route="range_arithmetic_review",
                           reason="write_extent_exceeds_destination_capacity",
                           disposition="proven_oversized", write_extent=ext_bytes,
                           dest_capacity=capN, dest_capacity_prov=dcap["prov"], **common,
                           note="lower-bound write extent %d > %d-byte dst -> the API writes "
                                ">= %d > capacity -> past dst" % (ext_bytes, capN, ext_bytes))
        ops.append(rec)
    return ops


if __name__ == "__main__":
    by_name, prov = load_contracts()
    for p in prov:
        print("PROVENANCE", json.dumps(p, sort_keys=True))
    if len(sys.argv) > 1:
        # library identity comes ONLY from a scan-bound build_attestation.json in the scan dir;
        # without one every decoder call -> contract_identity_unresolved (conservative default).
        for o in analyze_decoder_calls(sys.argv[1]):
            print(json.dumps({k: o[k] for k in o if k not in ("roles", "identity")},
                             sort_keys=True))
