#!/usr/bin/env python3
"""Mechanics dry run -- Step 1 of the corpus plan (DEVELOPMENT-ONLY).

Generate the A/B/C prompts for the 5 independent development cases and PROVE the
prompt machinery is sound. These cases are development-only: they validate the
pipeline (generation, byte-identical B/C evidence, archival) and MUST NEVER
appear in the confirmatory accuracy statistics.

Conditions (frozen design):
  A = code + highlighted operation.
  B = A + established facts (auto-derived by the frozen bucket_router) + the
      fixed generic-unresolved instruction.
  C = B + the typed uncertainty category + focused question (auto-rendered by
      the frozen bucket_router from the operation's unresolved_property).

B and C share a byte-for-byte identical prefix (code + highlighted op +
evidence + instruction); C differs ONLY by inserting the two-line
category/question block. This is asserted here, not assumed: a failure aborts
generation. The category/question are produced BY the scanner's router, not
hand-written, so Condition C tests the bucket method, not a human hint.
"""
import hashlib
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
TOOLS = os.path.join(REPO, "tchecker-research-complete",
                     "portable-engine-full-review-package", "tools")
sys.path.insert(0, TOOLS)
import bucket_router as br  # frozen router

SRC = {"cve-2016-1950": "secasn1d.c", "cve-2019-17006": "rsapkcs.c",
       "cve-2019-11745": "pkcs11c.c", "cve-2019-11759": "pkcs11c.c",
       "mjpg-cve-huff": "jchuff.c"}

# The 5 independent development cases (from ground_truth.json), with a chosen
# representative (side) per case so the dry run exercises every ground-truth
# label. GT is recorded ONLY for later scoring; it is NOT shown to the reviewer.
DEV_CASES = [
    dict(id="rsa_vuln", cve="cve-2019-17006", side="vuln",
         function="rsa_FormatOneBlock", dest="bp", gt="vulnerable"),
    dict(id="rsa_patched", cve="cve-2019-17006", side="patched",
         function="rsa_FormatOneBlock", dest="bp", gt="safe"),
    dict(id="mjpg_encode_vuln", cve="mjpg-cve-huff", side="vuln",
         function="encode_one_block", dest="buffer", gt="vulnerable"),
    dict(id="sftk_kdf_safe", cve="cve-2019-11745", side="patched",
         function="sftk_compute_ANSI_X9_63_kdf", dest="buffer", gt="safe"),
    dict(id="nsc_pbe_unresolved", cve="cve-2019-11745", side="patched",
         function="nsc_pbe_key_gen", dest="buf", gt="unresolved"),
    # NOTE: sec_asn1d_add_to_subitems/copy (external_contract_unknown) is
    # intentionally EXCLUDED from the mechanics dry run. It is an abstained
    # (not open-candidate) llm-eligible record, so the frozen bucket_router --
    # which routes only emit_candidates output and whose PROPERTY_RENDER has no
    # Condition-C question template for external_contract_unknown -- cannot
    # render Condition C for it without a router change (a new experimental
    # version). Recorded as a limitation, not worked around.
]

JSON_INSTR = ('Respond ONLY with a JSON object of the form '
              '{"classification": "safe|vulnerable|unknown", "reasoning": "..."}.')
B_INSTR = ("TChecker identified the highlighted operation and established the "
           "facts listed above, but the result remains unresolved. Based on the "
           "code and these facts, classify the operation as safe, vulnerable, or "
           "unknown, and explain your reasoning.")


def function_body(src_file, fname):
    lines = open(src_file, errors="replace").read().split("\n")
    start = None
    for i, L in enumerate(lines):
        s = L.lstrip()
        if (s.startswith(fname + "(") or s.startswith(fname + " (")) and not s.startswith("*"):
            start = i
            break
    if start is None:
        return None, None
    body, depth, opened = [], 0, False
    for k in range(start, len(lines)):
        L = lines[k]
        body.append(L)
        depth += L.count("{") - L.count("}")
        if "{" in L:
            opened = True
        if opened and depth <= 0:
            break
    return "\n".join(body), start + 1  # 1-based start line


def router_record(cve, side, function, dest):
    prefix = f"/tmp/{cve}/{side}/scan/work/cpp.json"
    for r in br.route_factfile(prefix):
        if r.get("function") == function and r.get("dest") == dest:
            return r
    # some producers key dest differently; fall back to function match
    for r in br.route_factfile(prefix):
        if r.get("function") == function:
            return r
    return None


def build_prompts(case):
    cve, side = case["cve"], case["side"]
    src = f"/tmp/{cve}/{side}/scan/work/csrc/{SRC[cve]}"
    body, fn_line = function_body(src, case["function"])
    if body is None:
        raise SystemExit(f"function {case['function']} not found in {src}")
    rec = router_record(cve, side, case["function"], case["dest"])
    if rec is None:
        raise SystemExit(f"no router record for {case['id']}")
    cq = br.render_for_condition_c(rec)

    code_block = (f"```c\n// {SRC[cve]} (function begins at line {fn_line})\n"
                  f"{body}\n```")
    highlight = (f"Highlighted operation: a write through `{case['dest']}` in "
                 f"`{case['function']}` (buffer-write the analyzer could not "
                 f"prove in-bounds), at {rec.get('file')}:{rec.get('line')}.")
    evidence = "Established facts (from static analysis):\n" + "\n".join(
        f"  - {f}" for f in rec["established_facts"])

    # shared prefix used byte-for-byte by BOTH B and C
    shared = f"{code_block}\n\n{highlight}\n\n{evidence}"
    cq_block = (f"Uncertainty category: {cq['uncertainty_category']}\n"
                f"Focused question: {cq['focused_question']}")

    prompt_a = (f"{code_block}\n\n{highlight}\n\n"
                f"Classify this operation as safe, vulnerable, or unknown, and "
                f"explain your reasoning.\n{JSON_INSTR}")
    prompt_b = f"{shared}\n\n{B_INSTR}\n{JSON_INSTR}"
    prompt_c = f"{shared}\n\n{cq_block}\n\n{B_INSTR}\n{JSON_INSTR}"

    # HARD guarantees:
    # 1. B and C share the exact evidence+code+highlight prefix.
    assert prompt_b.startswith(shared), case["id"]
    assert prompt_c.startswith(shared), case["id"]
    # 2. C is B with ONLY the category/question block inserted before the instruction.
    assert prompt_c == f"{shared}\n\n{cq_block}\n\n{B_INSTR}\n{JSON_INSTR}"
    assert prompt_b == f"{shared}\n\n{B_INSTR}\n{JSON_INSTR}"
    # 3. removing the cq block from C yields exactly B.
    reconstructed_b = prompt_c.replace(f"{cq_block}\n\n", "", 1)
    assert reconstructed_b == prompt_b, f"B/C differ by more than category+question: {case['id']}"
    # 4. the evidence text is identical in B and C.
    assert evidence in prompt_b and evidence in prompt_c

    return {
        "id": case["id"], "cve": cve, "side": side,
        "function": case["function"], "dest": case["dest"],
        "ground_truth": case["gt"], "development_only": True,
        "scanner_bucket": rec.get("uncertainty_bucket"),
        "scanner_reason": rec.get("reason_code"),
        "scanner_route": rec.get("recommended_route"),
        "condition_C_render": cq,
        "shared_prefix_sha256": hashlib.sha256(shared.encode()).hexdigest(),
        "prompts": {"A": prompt_a, "B": prompt_b, "C": prompt_c},
    }


def main():
    out = [build_prompts(c) for c in DEV_CASES]
    archive = os.path.join(HERE, "archive")
    os.makedirs(archive, exist_ok=True)
    with open(os.path.join(archive, "dev_prompts.json"), "w") as fh:
        json.dump(out, fh, indent=2, sort_keys=True)
    # also drop each prompt as a readable text file for inspection
    for case in out:
        for cond, text in case["prompts"].items():
            with open(os.path.join(archive, f"{case['id']}.{cond}.txt"), "w") as fh:
                fh.write(text + "\n")
    print(f"generated A/B/C prompts for {len(out)} development-only cases")
    print("B/C byte-identical-prefix + only-category/question-differs: ASSERTED for all")
    for c in out:
        print(f"  {c['id']:20} gt={c['ground_truth']:11} bucket={c['scanner_bucket']} "
              f"prefix_sha={c['shared_prefix_sha256'][:10]}")


if __name__ == "__main__":
    main()
