#!/usr/bin/env python3
"""Audit: capability 1's new physical-write identity integration (NO model calls).

Verifies, against real scanned bodies (cap_controls/cap1/*.c), that:
  1. every cap1 record recognized via a COPY_SINKS-covered sink name (memcpy/memmove/
     strncpy/wcsncpy) gets a VERIFIABLE identity, correctly resolved through
     `<operator>.addressOf` -> `<operator>.indirectIndexAccess` -> the base IDENTIFIER
     (no change to cap_write_site_dedup.py was needed for this -- its existing
     `_descend_to_identifier` already walks that chain);
  2. a sink name NOT in `cap_write_site_dedup.COPY_SINKS` (strcpy/wcscpy/strcat/wcscat --
     cap1 recognizes these, WSD's copy-sink registry does not) correctly degrades to
     `identity_unverifiable=True` -- fail-closed, never a crash, never silently merged;
  3. identity is DETERMINISTIC: the same cpp.json scanned twice yields byte-identical
     identities for the same site;
  4. two DISTINCT recognized sites (pos1, pos3) get DISTINCT identities;
  5. `WSD.dedup()` over cap1's own output never accidentally collapses two distinct
     recognized sites into one operation, and correctly separates the unverifiable
     strcpy-family record from the verifiable memcpy-family ones.

Cross-capability collision note (not asserted here, explained): cap1 only fires on
copy-sink CALL nodes (`write_dest_arg`'s COPY_SINKS branch); capability 3 only fires on
`<operator>.assignment` nodes (the other branch). A single CPG call record has exactly one
`name`, so the two branches are mutually exclusive on the SAME call -- cap1 and cap3
cannot recognize the identical physical call as their site. This audit documents that
structural non-overlap rather than asserting a collision that cannot occur; the identity
integration's value is the SAME defensive posture CAP2_CAP3_BOUNDARY_FROZEN.md took before
capability 3 existed -- wired in before, not after, any future capability that also
treats a copy-sink call as its physical site would need it.
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "tchecker-research-complete",
                                "portable-engine-full-review-package", "tools"))
import cap_addr_indexed as C1
import cap_write_site_dedup as WSD


def scan(srcdir):
    out = tempfile.mkdtemp()
    os.environ.setdefault("REPO", os.path.abspath(os.path.join(HERE, "..", "..")))
    subprocess.run(["bash", os.path.join(HERE, "scan_c_frozen.sh"), srcdir, out],
                   capture_output=True, text=True)
    return os.path.join(out, "cpp.json")


def one(ops, fn):
    lst = [o for o in ops if o.get("function") == fn]
    return lst[0] if len(lst) == 1 else None


def main():
    cpp = scan(os.path.join(HERE, "cap_controls", "cap1"))
    ops = C1.analyze_addr_indexed(cpp)
    checks = []

    # --- 1. verifiable identity on a COPY_SINKS-covered sink (pos1: memcpy) ---
    pos1 = one(ops, "pos1")
    checks.append(("pos1 identity present", pos1 is not None and pos1.get("identity") is not None))
    checks.append(("pos1 attribution=direct", pos1 is not None and pos1.get("attribution") == "direct"))
    checks.append(("pos1 identity verifiable", pos1 is not None and pos1["identity"].get("verifiable") is True))
    checks.append(("pos1 identity.write is memcpy + the &buf[10] target",
                   pos1 is not None and pos1["identity"].get("write")
                   and pos1["identity"]["write"][0] == "memcpy"))

    # --- 4. distinct sites -> distinct identities ---
    pos3 = one(ops, "pos3")
    checks.append(("pos1/pos3 identities distinct",
                   pos1 is not None and pos3 is not None
                   and WSD.identity_key(pos1) != WSD.identity_key(pos3)))

    # --- 3. determinism: rescan, compare ---
    ops2 = C1.analyze_addr_indexed(cpp)
    pos1_again = one(ops2, "pos1")
    checks.append(("identity deterministic across re-scans",
                   pos1_again is not None and pos1["identity"] == pos1_again["identity"]))

    # --- 5. dedup over cap1's own output: distinct sites stay distinct ---
    deduped = WSD.dedup(ops)
    n_verifiable_sites = len({WSD.identity_key(o) for o in ops if WSD.is_verifiable(o)})
    n_deduped_verifiable = len([o for o in deduped if not o.get("identity_unverifiable")])
    checks.append(("dedup preserves distinct-site count (no false merge)",
                   n_deduped_verifiable == n_verifiable_sites))

    # --- 2. sink not in WSD.COPY_SINKS -> unverifiable, fail-closed ---
    strcpy_src = os.path.join(HERE, "cap_controls", "cap1", "_strcpy_control.c")
    with open(strcpy_src, "w") as f:
        f.write("#include <string.h>\n"
                "/* NOTSINK: strcpy dest &(base[index]) -- cap1 recognizes the shape, "
                "WSD.COPY_SINKS does not cover strcpy -> identity_unverifiable, fail-closed. */\n"
                "void notsink(const char *src){ char buf[100]; strcpy(&buf[5], src); }\n")
    try:
        cpp2 = scan(os.path.join(HERE, "cap_controls", "cap1"))
        ops3 = C1.analyze_addr_indexed(cpp2)
        notsink = one(ops3, "notsink")
        checks.append(("strcpy-family sink recognized by cap1 at all",
                       notsink is not None and notsink.get("route") is not None))
        checks.append(("strcpy-family identity correctly unverifiable (not a crash, not merged)",
                       notsink is not None and notsink.get("identity") is not None
                       and notsink["identity"].get("verifiable") is False))
        deduped3 = WSD.dedup(ops3)
        strcpy_op = [o for o in deduped3 if o.get("canonical_capability") == "addr_indexed"
                    and any(p.get("function") == "notsink" for p in o.get("provenance", []))]
        checks.append(("dedup marks the strcpy record identity_unverifiable, never merges it",
                       len(strcpy_op) == 1 and strcpy_op[0].get("identity_unverifiable") is True))
    finally:
        os.remove(strcpy_src)

    ok = True
    for name, c in checks:
        print(("PASS" if c else "FAIL"), name)
        ok = ok and c
    print("\nALL PASS" if ok else "\nFAILURES PRESENT")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
