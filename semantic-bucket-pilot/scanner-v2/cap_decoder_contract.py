#!/usr/bin/env python3
"""Capability 4 -- EXTERNAL DECODER CONTRACTS  (NO model calls).

A library decoder/decompressor call writes into a caller-provided destination buffer, but
the number of bytes written is governed by the API's DOCUMENTED CONTRACT, not by a plain
memcpy-style length argument. This capability recognizes such calls and -- only when the
contract lets us bound the maximum write extent against an independently-established
destination capacity -- routes them; otherwise it recognizes the operation and leaves the
relationship UNRESOLVED. It never claims VULNERABLE and never claims safe without a proof.

DELIBERATELY NARROW boundary (soundness over coverage):
  * A contract is tied to a specific LIBRARY + VERSION-RANGE + EXACT SIGNATURE -- NOT to a
    bare function name. A same-named user-defined function, or a call whose arity does not
    match the signature, is NOT bound (it is out of this capability's domain).
  * Each contract's provenance is an ARCHIVED authoritative header/doc excerpt, sliced
    verbatim from the pinned upstream tag, hashed; the registry VERIFIES those hashes at load
    and refuses to operate (fail closed) if any archived excerpt has changed. See
    cap_controls/cap4_contracts/authorities/PROVENANCE.json.
  * Every argument is mapped by POSITION and by DECLARATION IDENTITY (ref-target), into the
    roles: destination, available_capacity, input, input_length, state_object.
  * PRE-call vs POST-call meanings are modeled explicitly. zlib's `avail_out` is REMAINING
    free capacity BEFORE the call and is DECREMENTED by the bytes written AFTER the call --
    it is NOT "bytes written". Because that pre-state field is not tracked here, an inflate/
    deflate call is RECOGNIZED but its write extent is left unresolved (never mis-read).
  * Return codes, partial writes, repeated/stateful calls, callbacks, and error exits are
    recorded on each contract and respected: a bound is the per-call MAXIMUM write extent
    (an upper bound that holds across partial/repeated/error-exit paths), never an exact
    count, so it can only DISPROVE safety (oversized) or establish an in-capacity upper
    bound, never assert a precise write.

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
# Each contract is tied to (library, version_range, signature). `roles` maps an argument
# INDEX to a role. `max_write_extent` says how the per-call maximum number of bytes written
# is bounded:
#   {"kind": "arg_bytes", "arg": i}      -> at most the byte value of argument i (a capacity
#                                           the caller passes; the API never writes past it).
#   {"kind": "state_field_prestate", ...}-> bounded by a struct field's PRE-call value that
#                                           this capability does not track -> unresolved.
# `authority` names the archived excerpt + its sha256 (verified at load).
CONTRACTS = [
    {"id": "lz4.LZ4_decompress_safe@v1.7.0+", "library": "lz4",
     "version_range": ">=1.7.0 (signature stable since r129; verified against v1.9.4)",
     "signature": {"name": "LZ4_decompress_safe", "return_type": "int",
                   "params": ["const char *", "char *", "int", "int"]},
     "roles": {0: "input", 1: "destination", 2: "input_length", 3: "available_capacity"},
     "capacity_semantics": "arg3 dstCapacity = size of dst BEFORE the call (explicit arg); "
                           "the API is contractually guaranteed never to write outside dst, "
                           "i.e. at most dstCapacity bytes.",
     "max_write_extent": {"kind": "arg_bytes", "arg": 3},
     "return_codes": ">0 = bytes decompressed (== bytes written, <= dstCapacity); "
                     "<0 = error (malformed input or dst too small); decoding stops.",
     "partial_writes": "on the <0 error path decoding stops early; bytes already written are "
                       "still <= dstCapacity (the bound holds on every path).",
     "stateful": False, "callbacks": False,
     "authority": {"excerpt_file": "lz4-1.9.4-LZ4_decompress_safe.txt",
                   "sha256": "71a1710d7b659a00a7c8201f829ed4ddfada184c11873fba6da08ccec7dddf65"}},

    {"id": "lz4.LZ4_decompress_safe_partial@v1.8.3+", "library": "lz4",
     "version_range": ">=1.8.3 (verified against v1.9.4)",
     "signature": {"name": "LZ4_decompress_safe_partial", "return_type": "int",
                   "params": ["const char *", "char *", "int", "int", "int"]},
     "roles": {0: "input", 1: "destination", 2: "input_length",
               3: "target_output_size", 4: "available_capacity"},
     "capacity_semantics": "arg4 dstCapacity = size of dst BEFORE the call; the API writes at "
                           "most dstCapacity bytes (targetOutputSize <= dstCapacity, and the "
                           "decoder may write up to dstCapacity).",
     "max_write_extent": {"kind": "arg_bytes", "arg": 4},
     "return_codes": ">=0 = bytes written into dst (<= dstCapacity); <0 = error.",
     "partial_writes": "writes up to dstCapacity even when it stops at targetOutputSize; the "
                       "dstCapacity bound holds on every path.",
     "stateful": False, "callbacks": False,
     "authority": {"excerpt_file": "lz4-1.9.4-LZ4_decompress_safe_partial.txt",
                   "sha256": "c84b9e21aec98f5bf891af8d28c31ed0b5072e0ae4f5816c9cffb6b280d4ac65"}},

    {"id": "zlib.inflate@v1.2.0+", "library": "zlib",
     "version_range": ">=1.2.0 (verified against v1.3.1)",
     "signature": {"name": "inflate", "return_type": "int",
                   "params": ["z_streamp", "int"]},
     "roles": {0: "state_object", 1: "flush_mode"},
     "capacity_semantics": "destination + capacity live in the z_stream: next_out (dst) and "
                           "avail_out (REMAINING free space BEFORE the call). POST-call, "
                           "avail_out is DECREMENTED by the bytes written and total_out is "
                           "incremented -- avail_out is NOT bytes-written. The per-call max "
                           "write extent is the PRE-call avail_out.",
     "max_write_extent": {"kind": "state_field_prestate", "field": "avail_out",
                          "meaning": "pre_call_remaining_capacity"},
     "return_codes": "Z_OK / Z_STREAM_END / Z_NEED_DICT progress; Z_BUF_ERROR (no progress, "
                     "not fatal); Z_DATA_ERROR / Z_MEM_ERROR / Z_STREAM_ERROR errors.",
     "partial_writes": "STATEFUL + REPEATED: called in a loop, each call consumes avail_in / "
                       "produces up to avail_out and updates next_out/avail_out; the caller "
                       "refills the output buffer between calls.",
     "stateful": True, "callbacks": False,
     "authority": {"excerpt_file": "zlib-1.3.1-inflate.txt",
                   "sha256": "cb7e42a8ef44bc9f231acda8d6483ba849b0559b98d80f8628d2a2f11bc017b9"}},

    {"id": "zlib.deflate@v1.2.0+", "library": "zlib",
     "version_range": ">=1.2.0 (verified against v1.3.1)",
     "signature": {"name": "deflate", "return_type": "int",
                   "params": ["z_streamp", "int"]},
     "roles": {0: "state_object", 1: "flush_mode"},
     "capacity_semantics": "same z_stream next_out/avail_out pre/post semantics as inflate; "
                           "avail_out is pre-call remaining capacity, decremented after.",
     "max_write_extent": {"kind": "state_field_prestate", "field": "avail_out",
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


def analyze_decoder_calls(cpp, auth_dir=AUTH_DIR):
    d = json.load(open(cpp)) if isinstance(cpp, str) else cpp
    by_name, _prov = load_contracts(auth_dir)
    index = WSD.build_index(d)
    stack_ext = v2.compute_stack_fixed_array_extents(d)
    heap_ext = AE.compute_allocation_extents(d)
    # user-defined (non-external, with body) function names shadow any library contract:
    # the contract is tied to the LIBRARY signature, not the name.
    local_defs = {f.get("name") for f in d.get("functions", [])
                  if not f.get("is_external") and f.get("line_end")}
    call_by_id = index["call_by_id"]

    ops = []
    for c in d.get("calls", []):
        name = c.get("name")
        cands = by_name.get(name)
        if not cands:
            continue
        args = sorted(c.get("arguments", []), key=lambda a: a.get("index", 0))
        # SIGNATURE match (not name): the callee must NOT be a user-defined same-named
        # function, and the call arity must equal the contract's parameter count.
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
               "version_range": ct["version_range"], "roles": roles,
               "stateful": ct["stateful"], "callbacks": ct["callbacks"],
               "identity": ident, "node_id": c.get("id")}

        mwe = ct["max_write_extent"]
        # ---- max write extent per contract -------------------------------------------------
        if mwe["kind"] == "state_field_prestate":
            # e.g. zlib avail_out: pre-call remaining capacity, NOT tracked here. RECOGNIZE
            # the operation, leave the relationship unresolved (never mis-read as bytes-written).
            state = roles.get("state_object", {})
            rec.update(route="additional_evidence_required",
                       reason="decoder_capacity_in_state_object",
                       disposition="relationship_unresolved",
                       max_write_extent="unresolved_prestate_field",
                       extent_field=mwe["field"], extent_field_meaning=mwe["meaning"],
                       state_object=state.get("code"),
                       note="write extent is the PRE-call %s (remaining capacity) of the "
                            "z_stream, which is not tracked; not treated as bytes written"
                            % mwe["field"])
            ops.append(rec); continue

        # arg_bytes: the caller passes the capacity/extent bound explicitly.
        cap_role = roles.get("available_capacity", {})
        cap_code = cap_role.get("code", "")
        dest_role = roles.get("destination", {})
        dest_arg = args[dest_role["arg_index"]] if "destination" in roles else None
        dest_code = dest_role.get("code", "")

        # destination byte capacity (established fixed array / literal allocation only)
        dcap, why = (_dest_capacity(dest_arg, dest_code, fid, index, stack_ext, heap_ext)
                     if dest_arg is not None else (None, "no_destination_arg"))

        # value of the max write extent: literal bytes, or sizeof(dest) == capacity exactly
        extent = _lit_bytes(cap_code)
        m = _SIZEOF.match(cap_code)
        extent_is_sizeof_dest = bool(m and dcap is not None
                                     and m.group(1) == WSD._root_ident(dest_code))

        if extent is None and not extent_is_sizeof_dest:
            # symbolic capacity argument -> cannot bound the extent -> recognize, unresolved.
            rec.update(route="additional_evidence_required",
                       reason="write_extent_unresolved",
                       disposition="relationship_unresolved",
                       max_write_extent="symbolic",
                       capacity_arg=cap_code, dest=dest_code,
                       dest_capacity=(dcap["bytes"] if dcap else None),
                       note="decoder capacity argument is symbolic; max write extent not bounded")
            ops.append(rec); continue

        if dcap is None:
            # extent known but destination buffer capacity not established -> unresolved.
            rec.update(route="additional_evidence_required", reason=why,
                       disposition="relationship_unresolved",
                       max_write_extent=(dcap and "sizeof_dest") or extent,
                       capacity_arg=cap_code, dest=dest_code, dest_capacity=None,
                       note="max write extent bounded by contract, but destination capacity "
                            "is not independently established")
            ops.append(rec); continue

        # both established: compare the per-call MAXIMUM write extent to the dest capacity.
        ext_bytes = dcap["bytes"] if extent_is_sizeof_dest else extent
        if extent_is_sizeof_dest or ext_bytes <= dcap["bytes"]:
            rec.update(route="deterministic_complete",
                       reason="write_extent_within_destination_capacity",
                       disposition="deterministic_complete",
                       max_write_extent=ext_bytes, dest=dest_code,
                       dest_capacity=dcap["bytes"], dest_capacity_prov=dcap["prov"],
                       note=("sizeof(dst) passed as capacity -> API cannot write past dst"
                             if extent_is_sizeof_dest else
                             "%d-byte cap arg <= %d-byte dst -> API bounded within dst"
                             % (ext_bytes, dcap["bytes"])))
        else:
            rec.update(route="range_arithmetic_review",
                       reason="write_extent_within_destination_capacity",
                       disposition="proven_oversized",
                       max_write_extent=ext_bytes, dest=dest_code,
                       dest_capacity=dcap["bytes"], dest_capacity_prov=dcap["prov"],
                       note="%d-byte capacity passed to decoder for a %d-byte dst -> the API "
                            "is told it may write past the buffer" % (ext_bytes, dcap["bytes"]))
        ops.append(rec)
    return ops


if __name__ == "__main__":
    by_name, prov = load_contracts()
    for p in prov:
        print("PROVENANCE", json.dumps(p, sort_keys=True))
    if len(sys.argv) > 1:
        for o in analyze_decoder_calls(sys.argv[1]):
            print(json.dumps({k: o[k] for k in o if k not in ("roles", "identity")},
                             sort_keys=True))
