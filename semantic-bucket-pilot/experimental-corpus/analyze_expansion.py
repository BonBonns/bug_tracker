#!/usr/bin/env python3
"""Run the frozen producers over the pre-registered expansion scans and report
what the scanner emits per family (routable or not), with vuln/patched
comparison. Reads scanned facts under /tmp/expansion/<id>/<side>/cpp.json.

No back-selection: this reports whatever the frozen scanner produces for the
pre-registered set. Families that yield 0 routable candidates are reported as
such (an informative scarcity result), not dropped.
"""
import importlib.util
import json
import os
import sys
from collections import Counter

TOOLS = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "tchecker-research-complete",
    "portable-engine-full-review-package", "tools"))
sys.path.insert(0, TOOLS)
REASON = ("oob_runtime_capacity_verdict", "oob_cursor_write_verdict",
          "oob_interprocedural_verdict")

FAMILIES = {
    "E1": ("Bug 1869493 AES Keywrap", "pkcs11c.c"),
    "E2": ("Bug 1835425 RSA input heap overflow", "rsapkcs.c"),
    "E3": ("Bug 1396616 nssUTF8_Length overrun", "utf8.c"),
    "E4": ("Bug 2026311 RSA_EMSAEncodePSS", "rsapkcs.c"),
    "E5": ("Bug 2028954 CERT_DecodeAVAValue", "secname.c"),
}


def _load(m):
    s = importlib.util.spec_from_file_location(m, os.path.join(TOOLS, m + ".py"))
    mod = importlib.util.module_from_spec(s)
    s.loader.exec_module(mod)
    return mod


def analyze(path, mods):
    tot = Counter()
    le = []
    for name, mod in mods.items():
        try:
            recs = mod.analyze_operations(path)
        except Exception as e:
            return None, f"producer {name} error: {e}"
        for r in recs:
            tot[r["analysis_status"]] += 1
            if r.get("llm_eligible"):
                le.append({"producer": name.split("_")[1], "function": r.get("function"),
                           "line": r.get("line"), "dest": r.get("dest"),
                           "reason": r.get("primary_reason_code"),
                           "bucket": r.get("uncertainty_bucket")})
    return {"status": dict(tot), "llm_eligible": le}, None


def main():
    mods = {n: _load(n) for n in REASON}
    out = {}
    base = "/tmp/expansion"
    for fid, (title, srcfile) in FAMILIES.items():
        out[fid] = {"title": title, "src": srcfile, "sides": {}}
        for side in ("vuln", "patched"):
            p = os.path.join(base, fid, side, "cpp.json")
            if not os.path.exists(p):
                out[fid]["sides"][side] = {"missing": True}
                continue
            res, err = analyze(p, mods)
            out[fid]["sides"][side] = {"error": err} if err else res
    with open(os.path.join(os.path.dirname(__file__), "expansion_scan_results.json"), "w") as fh:
        json.dump(out, fh, indent=2, sort_keys=True)

    for fid, d in out.items():
        print(f"\n== {fid}: {d['title']} ({d['src']}) ==")
        for side in ("vuln", "patched"):
            s = d["sides"].get(side, {})
            if s.get("missing"):
                print(f"  {side}: MISSING (not scanned)")
                continue
            if s.get("error"):
                print(f"  {side}: ERROR {s['error']}")
                continue
            print(f"  {side}: status={s['status']} llm_eligible={len(s['llm_eligible'])}")
            for c in s["llm_eligible"]:
                print(f"       {c['function']}:{c['line']} dest={c['dest']} "
                      f"{c['reason']} [{c['producer']}]")


if __name__ == "__main__":
    main()
