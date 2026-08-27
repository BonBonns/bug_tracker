#!/usr/bin/env python3
"""Prompt generator v2 (FROZEN interface for the confirmatory A/B/C experiment).

Fixes the missing-macro problem the mechanics dry run surfaced: v1 showed only
the enclosing function, so for macro-heavy code the reviewer could not see the
destination's capacity (e.g. mozjpeg `BUFSIZE`) or the write widths
(`PUT_BITS`/`CHECKBUF15`/`EMIT_*`). v2 prepends the `#define`s TRANSITIVELY
REQUIRED to interpret the highlighted operation, resolved across the whole
checkout (source + headers), and uses the IDENTICAL expanded code context in
A, B, and C.

Design invariants (asserted by callers / the freeze test):
  * PROMPT_GENERATOR_VERSION is frozen; changing the expansion or templates is a
    NEW version, not an in-place edit.
  * The expanded code block is byte-identical across A, B, C.
  * B and C share a byte-identical prefix; C differs ONLY by the inserted
    category/question block (which is auto-derived by the frozen bucket_router).
  * Macro expansion is transitive-closure over real `#define`s found in the
    checkout; it never invents a definition. Unresolved references (e.g. a
    compiler builtin) are listed as such, not fabricated.

This module is pure and deterministic given the checkout + operation.
"""
import os
import re

PROMPT_GENERATOR_VERSION = "2"

JSON_INSTR = ('Respond ONLY with a JSON object of the form '
              '{"classification": "safe|vulnerable|unknown", "reasoning": "..."}.')
B_INSTR = ("TChecker identified the highlighted operation and established the "
           "facts listed above, but the result remains unresolved. Based on the "
           "code and these facts, classify the operation as safe, vulnerable, or "
           "unknown, and explain your reasoning.")

_IDENT = re.compile(r"[A-Za-z_]\w*")
_DEFINE = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*)")


def _read(path):
    return open(path, errors="replace").read()


def collect_defines(checkout_dir):
    """Map macro name -> {'text': full #define incl. continuations, 'file': rel,
    'refs': set(identifiers in the body)}. Scans every .c/.h in the checkout.
    First definition wins (stable); collisions are recorded but not merged."""
    defines = {}
    for root, _dirs, files in os.walk(checkout_dir):
        for fn in sorted(files):
            if not fn.endswith((".c", ".h")):
                continue
            path = os.path.join(root, fn)
            rel = os.path.relpath(path, checkout_dir)
            lines = _read(path).split("\n")
            i = 0
            while i < len(lines):
                m = _DEFINE.match(lines[i])
                if not m:
                    i += 1
                    continue
                name = m.group(1)
                block = [lines[i]]
                while block[-1].rstrip().endswith("\\") and i + 1 < len(lines):
                    i += 1
                    block.append(lines[i])
                if name not in defines:
                    body = "\n".join(block)
                    # identifiers referenced in the macro body, minus the name and
                    # the macro's own parameter list
                    head = block[0]
                    params = set()
                    pm = re.match(r"^\s*#\s*define\s+\w+\(([^)]*)\)", head)
                    if pm:
                        params = {p.strip() for p in pm.group(1).split(",") if p.strip()}
                    refs = {t for t in _IDENT.findall("\n".join(block))
                            if t != name and t not in params}
                    defines[name] = {"text": body, "file": rel, "refs": refs}
                i += 1
    return defines


def macro_closure(seed_text, defines, cap=64):
    """Transitive set of macro names (defined in the checkout) reachable from the
    identifiers in seed_text. Capped to avoid runaway; the cap is reported."""
    resolved, queue = {}, []
    for t in set(_IDENT.findall(seed_text)):
        if t in defines:
            queue.append(t)
    hit_cap = False
    while queue:
        if len(resolved) >= cap:
            hit_cap = True
            break
        name = queue.pop(0)
        if name in resolved:
            continue
        resolved[name] = defines[name]
        for r in defines[name]["refs"]:
            if r in defines and r not in resolved:
                queue.append(r)
    return resolved, hit_cap


def function_body(src_path, fname):
    lines = _read(src_path).split("\n")
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
    return "\n".join(body), start + 1


def build_code_block(checkout_dir, src_rel, fname):
    """The expanded code context: transitively-required #defines (ordered by
    file then name for determinism) followed by the enclosing function. Same for
    A/B/C. Returns (code_block, meta)."""
    src_path = os.path.join(checkout_dir, src_rel)
    body, fn_line = function_body(src_path, fname)
    if body is None:
        raise ValueError(f"function {fname} not found in {src_rel}")
    defines = collect_defines(checkout_dir)
    resolved, hit_cap = macro_closure(body, defines, cap=64)

    # deterministic order; keep only macros actually reachable from the function
    ordered = sorted(resolved.items(), key=lambda kv: (kv[1]["file"], kv[0]))
    macro_lines = []
    for name, d in ordered:
        macro_lines.append(f"// from {d['file']}")
        macro_lines.append(d["text"])
    macro_section = ("// --- definitions the highlighted operation depends on "
                     "(transitively expanded) ---\n" + "\n".join(macro_lines)
                     + "\n") if macro_lines else ""

    code_block = (f"```c\n{macro_section}"
                  f"// {src_rel} (function begins at line {fn_line})\n"
                  f"{body}\n```")
    meta = {"prompt_generator_version": PROMPT_GENERATOR_VERSION,
            "fn_start_line": fn_line,
            "included_macros": [n for n, _ in ordered],
            "macro_closure_capped": hit_cap}
    return code_block, meta


def build_abc(checkout_dir, src_rel, fname, dest, rec, cq):
    """Build the three prompts. rec is the frozen bucket_router record (for
    established_facts + file/line); cq is render_for_condition_c(rec)."""
    code_block, meta = build_code_block(checkout_dir, src_rel, fname)
    highlight = (f"Highlighted operation: a write through `{dest}` in `{fname}` "
                 f"(a buffer write the analyzer could not prove in-bounds), at "
                 f"{rec.get('file')}:{rec.get('line')}.")
    evidence = "Established facts (from static analysis):\n" + "\n".join(
        f"  - {f}" for f in rec["established_facts"])
    shared = f"{code_block}\n\n{highlight}\n\n{evidence}"
    cq_block = (f"Uncertainty category: {cq['uncertainty_category']}\n"
                f"Focused question: {cq['focused_question']}")

    prompt_a = (f"{code_block}\n\n{highlight}\n\n"
                f"Classify this operation as safe, vulnerable, or unknown, and "
                f"explain your reasoning.\n{JSON_INSTR}")
    prompt_b = f"{shared}\n\n{B_INSTR}\n{JSON_INSTR}"
    prompt_c = f"{shared}\n\n{cq_block}\n\n{B_INSTR}\n{JSON_INSTR}"

    # invariants
    assert prompt_b.startswith(shared) and prompt_c.startswith(shared)
    assert prompt_c.replace(f"{cq_block}\n\n", "", 1) == prompt_b, \
        "B/C differ by more than the category/question block"
    assert code_block in prompt_a and code_block in prompt_b and code_block in prompt_c, \
        "code block not identical across A/B/C"
    return {"A": prompt_a, "B": prompt_b, "C": prompt_c}, meta
