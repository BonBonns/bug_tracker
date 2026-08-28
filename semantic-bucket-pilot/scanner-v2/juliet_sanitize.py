#!/usr/bin/env python3
"""Neutralize Juliet oracle tells for model input, WITHOUT removing the discriminating
code. Strips all comments (POTENTIAL FLAW / FIX / CWE notes) and deterministically
renames label-bearing identifiers (bad, good, goodG2B, goodB2G, BadSource,
GoodSource, badSink, CWE... function names) to neutral tokens. The actual logic that
separates vulnerable from safe (e.g. the memset length feeding strlen(data)) is left
intact — that is what the model must reason about.

Used to build the model packets AND to run the leakage audit on them.
"""
import re

# tokens that must never survive into a model packet (case-insensitive scan)
LEAK_TOKENS = [
    "potential flaw", "fix:", "flaw", "cwe", "goodg2b", "goodb2g",
    "badsource", "goodsource", "badsink", "goodsink", "vulnerab", "\\bsafe\\b",
    "overflow", "\\bbad\\b", "\\bgood\\b",
]
_LEAK_RE = [re.compile(t, re.IGNORECASE) for t in LEAK_TOKENS]

_BLOCK = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE = re.compile(r"//[^\n]*")
# identifiers that encode the label (whole-word)
_LABEL_ID = re.compile(r"\b\w*(?:good|bad)\w*\b", re.IGNORECASE)
_CWE_ID = re.compile(r"\bCWE\w+\b")


def strip_comments(src):
    return _LINE.sub("", _BLOCK.sub(" ", src))


def neutralize(func_src, func_name=None):
    """Return (sanitized_source, rename_map). Deterministic per input."""
    s = strip_comments(func_src)
    rename = {}

    def repl(m):
        tok = m.group(0)
        if tok not in rename:
            rename[tok] = f"id_{len(rename):02d}"
        return rename[tok]

    s = _LABEL_ID.sub(repl, s)
    s = _CWE_ID.sub(lambda m: rename.setdefault(m.group(0), f"id_{len(rename):02d}"), s)
    # collapse leftover blank lines from stripped comments
    s = re.sub(r"\n\s*\n\s*\n", "\n\n", s)
    return s.strip(), rename


def leakage_scan(text):
    """Return the list of forbidden oracle tokens still present (empty = clean)."""
    found = []
    for t, rx in zip(LEAK_TOKENS, _LEAK_RE):
        if rx.search(text):
            found.append(t)
    return found


if __name__ == "__main__":
    import sys
    src = open(sys.argv[1], errors="replace").read()
    out, rm = neutralize(src)
    leaks = leakage_scan(out)
    print(f"renamed {len(rm)} identifiers; residual leaks: {leaks}")
    print("---")
    print(out[:1200])
