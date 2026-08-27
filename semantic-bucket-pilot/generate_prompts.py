#!/usr/bin/env python3
"""Generate the frozen A/B/C prompt files for the semantic-bucket pilot.

Design (locked): the three conditions differ ONLY in how the deterministic
scanner's uncertainty is represented to the LLM. Everything else — the code,
the highlighted operation, the model, the system instructions, the required
answer format — is held constant. The conditions form a strict subset ladder:

    A = code + highlighted operation
    B = A + established facts + generic "unresolved" status
    C = B + typed uncertainty category + focused question

The B and C EVIDENCE (established-facts) field is byte-for-byte identical: C is
literally the full B body with exactly two things appended (the category line
and the focused question). This is enforced structurally here — C is built by
string-concatenating B's body with the appendix, so the two can never drift.

Per-case inputs live in sources/:
    sources/<id>.code.txt   the sanitized code, with a "<<< HIGHLIGHTED
                            OPERATION" marker comment on the flagged line
                            (identical across all three conditions)
    sources/<id>.facts.txt  the established-facts block (shared verbatim by B
                            and C; NEVER states the conclusion or the reason for
                            unresolvedness — the reason is signaled generically
                            in B and, only in C, elaborated as category+question)
    sources/<id>.meta.json  {highlighted_operation, uncertainty_category,
                            focused_question, bucket, routable}

Output: prompts/<id>_A.txt, prompts/<id>_B.txt, prompts/<id>_C.txt.
The system instructions (prompts/system_instructions.txt) are prepended at
call time by the runner, not here, so they stay identical across conditions.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "sources"
OUT = ROOT / "prompts"

# Fixed instruction text, identical wording across cases so the ONLY variation
# between conditions is the evidence, not the phrasing of the ask.
A_INSTRUCTION = (
    "TChecker flagged the highlighted operation for review. Based on the code, "
    "classify the highlighted operation as safe, vulnerable, or unknown, and "
    "explain your reasoning."
)
B_INSTRUCTION = (
    "TChecker identified the highlighted operation and established the facts "
    "listed below, but the result remains unresolved. Based on the code and "
    "these facts, classify the operation as safe, vulnerable, or unknown, and "
    "explain your reasoning."
)


def _header(case_id, highlighted_operation):
    return (f"CASE ID: {case_id}\n\n"
            f"HIGHLIGHTED OPERATION: {highlighted_operation}\n\n"
            f"CODE:\n\n```c\n")


def build(case_id):
    code = (SRC / f"{case_id}.code.txt").read_text().rstrip("\n")
    meta = json.loads((SRC / f"{case_id}.meta.json").read_text())
    facts = (SRC / f"{case_id}.facts.txt").read_text().rstrip("\n")

    header = _header(case_id, meta["highlighted_operation"])
    code_block = header + code + "\n```\n"

    # A: code + highlighted operation + generic classify ask (no facts).
    a = code_block + "\n" + A_INSTRUCTION + "\n"

    # B: A's code block + B instruction + established facts.
    b = (code_block + "\n" + B_INSTRUCTION + "\n\n"
         "ESTABLISHED FACTS (from TChecker's deterministic analysis):\n\n"
         + facts + "\n")

    # C: literally B, plus exactly the category line and focused question.
    # Built by concatenation so the B/C facts field can never diverge.
    c_appendix = (f"\nUncertainty category: {meta['uncertainty_category']}\n\n"
                  f"Focused question:\n{meta['focused_question']}\n")
    c = b + c_appendix

    OUT.mkdir(exist_ok=True)
    (OUT / f"{case_id}_A.txt").write_text(a)
    (OUT / f"{case_id}_B.txt").write_text(b)
    (OUT / f"{case_id}_C.txt").write_text(c)

    # Structural self-check: C must contain B verbatim as a prefix, and the
    # facts block must appear byte-identical in both.
    assert c.startswith(b), f"{case_id}: C is not a strict superset of B"
    assert facts in b and facts in c, f"{case_id}: facts field missing/edited"
    return {"case_id": case_id, "A_bytes": len(a), "B_bytes": len(b), "C_bytes": len(c),
            "facts_bytes": len(facts), "bucket": meta["bucket"], "routable": meta["routable"]}


def main(argv):
    ids = argv or sorted(p.stem.replace(".code", "") for p in SRC.glob("*.code.txt"))
    report = [build(i) for i in ids]
    for r in report:
        print(f"{r['case_id']}  bucket={r['bucket']:<26} routable={r['routable']!s:<5} "
              f"A={r['A_bytes']}b B={r['B_bytes']}b C={r['C_bytes']}b "
              f"(C-B delta={r['C_bytes']-r['B_bytes']}b, facts={r['facts_bytes']}b shared)")


if __name__ == "__main__":
    main([a for a in sys.argv[1:]])
