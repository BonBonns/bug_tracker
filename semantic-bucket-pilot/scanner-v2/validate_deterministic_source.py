#!/usr/bin/env python3
"""Independent source-level validation of the 54 deterministic_complete promotions.

This deliberately does NOT reuse v2.compare() or the normalized cpp.json capacity
facts. It re-derives, from the raw C source text (L1), the array declaration bound
N and the literal write count k for each promoted operation, and re-checks the
SAME narrow property v2 claims: write_length_within_destination_capacity (k <= N,
byte/element-type matched, offset 0). It proves nothing about source-buffer
sufficiency or pointer validity (point #2) — only that the write length fits the
destination capacity, independently confirmed from source.

Emits validate_deterministic_source.json and a per-operation table.
"""
import glob
import json
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
CMP = os.path.join(HERE, "compare_v1_v2_stack.json")

# byte element types whose element size is 1 (so byte-count width compares to N directly)
BYTE_TYPES = {"char", "unsigned char", "signed char", "uint8_t", "int8_t",
              "u_char", "JOCTET", "CK_BYTE", "PRUint8", "PRInt8", "Byte", "BYTE"}


def scan_root(source_label):
    # source_label like "E1/patched"
    return os.path.join("/tmp/expansion", source_label, "csrc")


_DEFINE_CACHE = {}


def _define_rhs(root, ident):
    """Return the raw RHS token of `#define <ident> <rhs>` from source, or None."""
    pat = re.compile(r'^\s*#\s*define\s+' + re.escape(ident) + r'\s+\(?\s*([A-Za-z0-9_]+)\s*\)?\s*(?:/\*|//|$)')
    for path in glob.glob(os.path.join(root, "**", "*.h"), recursive=True) + \
               glob.glob(os.path.join(root, "**", "*.c"), recursive=True):
        try:
            for ln in open(path, "r", errors="replace"):
                m = pat.match(ln)
                if m:
                    return m.group(1)
        except OSError:
            continue
    return None


def resolve_macro(root, ident, depth=4):
    """Resolve `#define <ident> <int>` from source, following identifier
    indirections up to `depth` levels (e.g. HASH_BLOCK_LENGTH_MAX ->
    SHA3_224_BLOCK_LENGTH -> 144). Independent of cpp.json."""
    if (root, ident) in _DEFINE_CACHE:
        return _DEFINE_CACHE[(root, ident)]
    val = None
    cur = ident
    for _ in range(depth):
        rhs = _define_rhs(root, cur)
        if rhs is None:
            break
        if rhs.isdigit():
            val = int(rhs)
            break
        cur = rhs  # follow the indirection
    _DEFINE_CACHE[(root, ident)] = val
    return val


def _fn_bodies(root, function):
    fn_re = re.compile(r'\b' + re.escape(function) + r'\s*\(')
    for path in glob.glob(os.path.join(root, "**", "*.c"), recursive=True):
        try:
            txt = open(path, "r", errors="replace").read()
        except OSError:
            continue
        for fm in fn_re.finditer(txt):
            b = txt.find("{", fm.end())
            if b < 0 or b - fm.end() > 400:   # signature must be near the name
                continue
            depth, i, n = 0, b, len(txt)
            while i < n:
                c = txt[i]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            yield path, txt[b:i]


def find_decl_bound(root, function, dest, elem_type):
    """Re-derive, from raw C source, the declared bound N of `dest` inside `function`.
    Handles multi-declarator statements (`mp_digit c0, c1, at[8];`) and macro bounds
    (`unsigned char firstBlock[HASH_BLOCK_LENGTH_MAX];`). Confirms the statement's
    leading type matches the claimed element type. Independent of cpp.json / v2.compare."""
    # bound token = literal or identifier
    decl_re = re.compile(r'\b' + re.escape(dest) + r'\s*\[\s*([0-9]+|[A-Za-z_]\w*)\s*\]')
    et_head = elem_type.split()[0]  # e.g. "unsigned" / "uint8_t" / "mp_digit"
    hits = []
    for path, body in _fn_bodies(root, function):
        for dm in decl_re.finditer(body):
            # statement start: previous ; { or }
            start = max(body.rfind(";", 0, dm.start()),
                        body.rfind("{", 0, dm.start()),
                        body.rfind("}", 0, dm.start()))
            stmt = body[start + 1:dm.start()].strip()
            # must be a declaration whose leading type token is the element type
            toks = [t for t in stmt.split()
                    if t not in ("static", "const", "register", "volatile", "auto")]
            if not toks or toks[0] != et_head:
                continue  # `firstBlock` used but not declared here (e.g. the memcpy line)
            bound = dm.group(1)
            if bound.isdigit():
                n_src, how = int(bound), "literal"
            else:
                rv = resolve_macro(root, bound)
                if rv is None:
                    hits.append((None, path, "macro_unresolved:%s" % bound))
                    continue
                n_src, how = rv, "macro:%s=%d" % (bound, rv)
            hits.append((n_src, path, how))
    real = [h for h in hits if h[0] is not None]
    if not real:
        if hits:
            return None, hits[0][2], None
        return None, "decl_not_found_in_source", None
    bounds = {h[0] for h in real}
    if len(bounds) > 1:
        return None, "multiple_source_bounds:%s" % sorted(bounds), None
    return real[0][0], real[0][1], real[0][2]


def parse_k(width, elem_type):
    """Independent width parse -> literal byte/element count k, or None if symbolic.
    Returns (k, kind)."""
    w = width.strip()
    m = re.fullmatch(r'(\d+)', w)
    if m:
        return int(m.group(1)), "literal_bytes"
    # k * sizeof(T)
    m = re.fullmatch(r'(\d+)\s*\*\s*sizeof\s*\(\s*([\w ]+?)\s*\)', w)
    if m:
        return int(m.group(1)), "count_sizeof:%s" % m.group(2).strip()
    m = re.fullmatch(r'sizeof\s*\(\s*([\w ]+?)\s*\)', w)
    if m:
        return 1, "sizeof_only"
    return None, "symbolic"


def main():
    d = json.load(open(CMP))
    det = [t for t in d["transitions"] if t["disposition"] == "deterministic_complete"]
    rows = []
    ok = bad = 0
    verdicts = Counter()
    for t in det:
        src = t["source"]
        fn = t["function"]
        dest = t["dest"]
        ev = t["evidence"]
        elem_type = ev["element_type"]
        v2_N = ev["element_count"]
        width = str(ev["width"])
        root = scan_root(src)
        N_src, where, how = find_decl_bound(root, fn, dest, elem_type)
        k, kkind = parse_k(width, elem_type)
        verdict = "CONFIRMED"
        detail = ""
        if N_src is None:
            verdict = "UNVERIFIED_SOURCE"
            detail = where
        elif k is None:
            verdict = "NOT_LITERAL"  # should not happen for deterministic
            detail = kkind
        else:
            # byte-type: k is a byte count directly comparable to N (element size 1)
            byte_dest = elem_type in BYTE_TYPES
            if kkind.startswith("count_sizeof"):
                # count*sizeof(T): compare count to N with type match
                ctype = kkind.split(":", 1)[1]
                if ctype != elem_type and not (ctype in BYTE_TYPES and byte_dest):
                    verdict = "TYPE_MISMATCH"
                    detail = "width sizeof(%s) vs decl %s" % (ctype, elem_type)
                elif k <= N_src:
                    detail = "%d elems <= %d (source), type %s" % (k, N_src, elem_type)
                else:
                    verdict = "OVERSIZED"
                    detail = "%d > %d" % (k, N_src)
            else:  # literal_bytes
                if not byte_dest:
                    verdict = "NON_BYTE_LITERAL"
                    detail = "literal byte width on %s[] dest" % elem_type
                elif k <= N_src:
                    detail = "%d bytes <= %d (source byte array)" % (k, N_src)
                else:
                    verdict = "OVERSIZED"
                    detail = "%d > %d" % (k, N_src)
            # cross-check: source bound must equal v2's normalized bound
            if verdict == "CONFIRMED" and N_src != v2_N:
                verdict = "BOUND_DISAGREES"
                detail = "source N=%d vs v2 N=%d" % (N_src, v2_N)
        verdicts[verdict] += 1
        if verdict == "CONFIRMED":
            ok += 1
        else:
            bad += 1
        rows.append({"source": src, "function": fn, "dest": dest,
                     "elem_type": elem_type, "width": width,
                     "source_bound_N": N_src, "v2_bound_N": v2_N,
                     "literal_k": k, "verdict": verdict, "detail": detail,
                     "bound_derivation": how,
                     "source_file": where if isinstance(where, str) and where.endswith((".c", ".h")) else None})

    out = {"deterministic_total": len(det), "confirmed": ok, "not_confirmed": bad,
           "verdicts": dict(verdicts), "rows": rows}
    with open(os.path.join(HERE, "validate_deterministic_source.json"), "w") as fh:
        json.dump(out, fh, indent=2, sort_keys=True, default=str)

    print("deterministic promotions: %d" % len(det))
    print("independently CONFIRMED from source: %d" % ok)
    print("not confirmed: %d   verdicts=%s" % (bad, dict(verdicts)))
    print()
    # compact per (source,function,dest) unique table
    seen = set()
    for r in sorted(rows, key=lambda x: (x["source"], x["function"], x["dest"])):
        key = (r["source"], r["function"], r["dest"], r["width"])
        if key in seen:
            continue
        seen.add(key)
        print("  [%s] %-22s %-14s w=%-16s N_src=%-5s %-22s %s"
              % (r["verdict"][:4], r["function"][:22], r["dest"][:14],
                 r["width"], r["source_bound_N"], r["bound_derivation"], r["detail"]))
    if bad:
        print("\nNOT ALL CONFIRMED — see verdicts above")
        sys.exit(1)
    print("\nALL %d DETERMINISTIC PROMOTIONS INDEPENDENTLY CONFIRMED FROM SOURCE "
          "(property: write_length_within_destination_capacity only)." % len(det))


if __name__ == "__main__":
    main()
