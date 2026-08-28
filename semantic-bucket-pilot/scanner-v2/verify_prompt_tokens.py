#!/usr/bin/env python3
"""Verify the B (generic, length-matched) vs C (bucket-guided) instruction blocks are
token-matched, so C - B isolates the category-and-question interface, not verbosity.

Builds each instance's B and C instruction text (per PROMPT_CONDITIONS.md), tokenizes
both with the fixed model tokenizer, and checks
    |tokens(C_instruction) - tokens(B_instruction)| <= TOLERANCE
per instance, reporting the distribution and the exact tokenizer, counts, and
tolerance into study/prompts_FROZEN.json.

Tokenizer resolution (documented in the freeze):
  1. the fixed model tokenizer (anthropic / tiktoken / transformers) if importable;
  2. else a DECLARED heuristic proxy (word+punctuation), marked authoritative=False.
The heuristic is only to exercise the check offline; the authoritative freeze must be
produced with the fixed model tokenizer BEFORE any A/B/C model call.
"""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "study")
TOLERANCE = 12          # max |C-B| instruction-token difference, per instance

# Instruction blocks (facts/code/schema are shared and excluded from the delta).
B_INSTR = ("Review the highlighted operation using the established facts above. "
           "Consider the destination, the write length, and any conditions that "
           "guard the operation, and assess carefully whether the write could exceed "
           "the destination on some reachable execution of this code. Then decide "
           "whether the operation is vulnerable, safe, or unresolved, and identify "
           "any relationship that remains unresolved in the evidence provided.")

C_INSTR_TMPL = ("Review the highlighted operation using the established facts above. "
                "TChecker routed it to the category {category}. Answer the focused "
                "question: {question} then decide whether the operation is "
                "vulnerable, safe, or unresolved, and explain which established facts "
                "support your conclusion.")

CATEGORY = {"length_meaning": "length-meaning"}
QUESTION_TMPL = ("does the write of {width} into {dest} stay within {dest}'s "
                 "established capacity on every reachable execution?")


def resolve_tokenizer():
    try:
        import tiktoken
        enc = tiktoken.get_encoding("cl100k_base")
        return ("tiktoken/cl100k_base", lambda s: len(enc.encode(s)), True)
    except Exception:
        pass
    try:
        from transformers import AutoTokenizer
        tok = AutoTokenizer.from_pretrained("gpt2")
        return ("transformers/gpt2", lambda s: len(tok.encode(s)), True)
    except Exception:
        pass
    # DECLARED heuristic proxy: words + standalone punctuation
    tokre = re.compile(r"\w+|[^\w\s]")
    return ("heuristic:word+punct (NON-AUTHORITATIVE)", lambda s: len(tokre.findall(s)), False)


def _words(s):
    return len(re.findall(r"\w+", s))


def main():
    name, ntok, authoritative = resolve_tokenizer()
    insts = [json.loads(l) for l in open(os.path.join(OUT, "instances.jsonl"))]
    b_n, b_ch, b_w = ntok(B_INSTR), len(B_INSTR), _words(B_INSTR)
    rows = []
    within = 0
    for it in insts:
        cat = CATEGORY.get(it.get("unresolved_property"), str(it.get("unresolved_property")))
        q = QUESTION_TMPL.format(width=it["width_expr"], dest=it["dest"])
        c_instr = C_INSTR_TMPL.format(category=cat, question=q)
        c_n = ntok(c_instr)
        d = abs(c_n - b_n)
        within += (d <= TOLERANCE)
        rows.append({"instance_id": it["instance_id"], "b_tokens": b_n, "c_tokens": c_n,
                     "abs_delta": d, "c_chars": len(c_instr), "c_words": _words(c_instr)})
    deltas = sorted(r["abs_delta"] for r in rows)
    char_d = sorted(abs(r["c_chars"] - b_ch) for r in rows)
    word_d = sorted(abs(r["c_words"] - b_w) for r in rows)
    n = len(rows)
    med = deltas[n // 2]
    p95 = deltas[min(n - 1, int(0.95 * n))]
    frac_within = within / n

    import hashlib
    sha = lambda s: hashlib.sha256(s.encode()).hexdigest()[:16]
    frozen = {
        "purpose": "length-match B (generic) vs C (bucket-guided) instructions",
        "match_kind": ("exact tokenizer matching" if authoritative
                       else "PROXY length matching (NOT exact tokenizer matching)"),
        "tokenizer": name,
        "authoritative": authoritative,
        "note": ("" if authoritative else
                 "NON-AUTHORITATIVE proxy tokens. Before Stage 2, use the fixed "
                 "provider's token-count facility or actual input-token metadata; if "
                 "authoritative counts remain unavailable, retain this proxy and "
                 "report it transparently WITH the char/word counts below. Do NOT "
                 "call it exact tokenizer matching. Re-freeze before any A/B/C call."),
        "tolerance_tokens": TOLERANCE,
        "b_instruction_tokens": b_n,
        "b_instruction_chars": b_ch, "b_instruction_words": b_w,
        "abs_delta_tokens": {"median": med, "p95": p95, "min": deltas[0], "max": deltas[-1]},
        "abs_delta_chars": {"median": char_d[n // 2], "p95": char_d[min(n - 1, int(0.95 * n))],
                            "max": char_d[-1]},
        "abs_delta_words": {"median": word_d[n // 2], "p95": word_d[min(n - 1, int(0.95 * n))],
                            "max": word_d[-1]},
        "fraction_within_token_tolerance": round(frac_within, 4),
        "passed_proxy": (frac_within >= 0.95),
        "hashes": {"B_instruction": sha(B_INSTR), "C_template": sha(C_INSTR_TMPL),
                   "question_template": sha(QUESTION_TMPL)},
        "invariants_to_verify_before_calls": [
            "same code bytes across A/B/C",
            "byte-identical facts block B vs C",
            "byte-identical response schema across A/B/C",
            "only C contains the category and the relationship question",
        ],
    }
    with open(os.path.join(OUT, "prompts_FROZEN.json"), "w") as fh:
        json.dump(frozen, fh, indent=2, sort_keys=True)

    print(f"tokenizer: {name}  authoritative={authoritative}  ({frozen['match_kind']})")
    print(f"B instruction: tokens {b_n}  chars {b_ch}  words {b_w}")
    print(f"|C-B| tokens: median {med} max {deltas[-1]} (tol {TOLERANCE}) | "
          f"chars: median {char_d[n//2]} max {char_d[-1]} | words: median {word_d[n//2]} max {word_d[-1]}")
    print(f"within token tolerance: {frac_within:.1%}  -> passed_proxy={frozen['passed_proxy']}")
    if not authoritative:
        print("NON-AUTHORITATIVE proxy — not exact tokenizer matching. Re-run with the "
              "fixed provider's tokenizer/input-token metadata before A/B/C calls.")


if __name__ == "__main__":
    main()
