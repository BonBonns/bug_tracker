#!/usr/bin/env python3
"""Freeze test for prompt_generator_v2: proves the v2 invariants on the dev cases
BEFORE any confirmatory model call. Run this whenever the generator changes; a
change that breaks an invariant means a NEW version, not an in-place edit.

Checks:
  1. version pinned to "2".
  2. macro closure resolves the mozjpeg capacity macros (BUFSIZE, DCTSIZE2) and
     the write macros -- the exact gap the dry run found.
  3. code block byte-identical across A/B/C for every dev case.
  4. B/C differ ONLY by the category/question block.
  5. deterministic: two builds give byte-identical prompts.
"""
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(
    HERE, "..", "..", "tchecker-research-complete",
    "portable-engine-full-review-package", "tools")))
import bucket_router as br
import prompt_generator_v2 as g

SRC = {"cve-2019-17006": "rsapkcs.c", "cve-2019-11745": "pkcs11c.c",
       "mjpg-cve-huff": "jchuff.c"}
DEV = [
    ("cve-2019-17006", "vuln", "rsa_FormatOneBlock", "bp"),
    ("mjpg-cve-huff", "vuln", "encode_one_block", "buffer"),
    ("cve-2019-11745", "patched", "sftk_compute_ANSI_X9_63_kdf", "buffer"),
    ("cve-2019-11745", "patched", "nsc_pbe_key_gen", "buf"),
]


def build(cve, side, fn, dest):
    checkout = f"/tmp/{cve}/{side}/scan/work/csrc"
    recs = br.route_factfile(f"/tmp/{cve}/{side}/scan/work/cpp.json")
    rec = next((r for r in recs if r["function"] == fn and r.get("dest") == dest),
               next((r for r in recs if r["function"] == fn), None))
    cq = br.render_for_condition_c(rec)
    return g.build_abc(checkout, SRC[cve], fn, dest, rec, cq)


def main():
    n = 0
    def ck(desc, cond):
        nonlocal n
        print(("PASS" if cond else "FAIL"), desc)
        assert cond, desc
        n += 1

    ck('version pinned to "2"', g.PROMPT_GENERATOR_VERSION == "2")

    for cve, side, fn, dest in DEV:
        prompts, meta = build(cve, side, fn, dest)
        tag = f"{fn}"
        ck(f"{tag}: code block identical in A/B/C",
           _code(prompts["A"]) == _code(prompts["B"]) == _code(prompts["C"]))
        cqline = [l for l in prompts["C"].split("\n") if l.startswith("Uncertainty category:")]
        ck(f"{tag}: B/C differ only by category/question",
           prompts["B"] == prompts["C"].replace(
               _cqblock(prompts["C"]) + "\n\n", "", 1))
        if fn == "encode_one_block":
            ck("mozjpeg: BUFSIZE resolved", "BUFSIZE" in prompts["A"])
            ck("mozjpeg: DCTSIZE2 resolved (capacity computable)", "DCTSIZE2" in prompts["A"])
            ck("mozjpeg: PUT_BITS resolved", "PUT_BITS" in prompts["A"])
        # determinism
        p2, _ = build(cve, side, fn, dest)
        ck(f"{tag}: deterministic across builds",
           _sha(prompts) == _sha(p2))

    print(f"\nPROMPT_GENERATOR_V2_FREEZE={n}/{n}")


def _code(prompt):
    return prompt.split("```c\n", 1)[1].split("\n```", 1)[0]


def _cqblock(promptc):
    lines = promptc.split("\n")
    cat = next(l for l in lines if l.startswith("Uncertainty category:"))
    q = next(l for l in lines if l.startswith("Focused question:"))
    return f"{cat}\n{q}"


def _sha(prompts):
    return hashlib.sha256(
        (prompts["A"] + prompts["B"] + prompts["C"]).encode()).hexdigest()


if __name__ == "__main__":
    main()
