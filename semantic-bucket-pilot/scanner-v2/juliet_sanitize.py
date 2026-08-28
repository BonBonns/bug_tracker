#!/usr/bin/env python3
"""Neutralize Juliet oracle tells for model input, WITHOUT removing the discriminating
code. Strips all comments (POTENTIAL FLAW / FIX / CWE notes) and deterministically
renames label-bearing identifiers (bad, good, goodG2B, goodB2G, BadSource,
GoodSource, badSink, CWE... function names) to neutral tokens. The actual logic that
separates vulnerable from safe (e.g. the memset length feeding strlen(data)) is left
intact — that is what the model must reason about.

Used to build the model packets AND to run the leakage audit on them.
"""
import hashlib
import re

# Substrings that must never survive into a model packet (case-insensitive; ANY
# occurrence, not just whole-word — "goodG2BSink" contains "good").
LEAK_TOKENS = [
    "potential flaw", "flaw", "fix", "omitbad", "omitgood",
    "bad", "good", "g2b", "b2g",
    "badsource", "goodsource", "badsink", "goodsink",
    "cwe", "testcase", "vulnerab", "overflow", "#include",
]
_LEAK_RE = [re.compile(re.escape(t), re.IGNORECASE) for t in LEAK_TOKENS]

_BLOCK = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE = re.compile(r"//[^\n]*")
_INCLUDE = re.compile(r"^\s*#\s*include[^\n]*", re.MULTILINE)
# any identifier containing a label substring (good/bad/g2b/b2g), or a CWE/testcase id
_LABEL_ID = re.compile(r"\b\w*(?:good|bad|g2b|b2g)\w*\b", re.IGNORECASE)
_CWE_ID = re.compile(r"\b\w*(?:CWE\d+|testcase)\w*\b", re.IGNORECASE)


def strip_comments(src):
    return _INCLUDE.sub("", _LINE.sub("", _BLOCK.sub(" ", src)))


def neutralize(func_src, func_name=None, extra_tokens=()):
    """Return (sanitized_source, rename_map). Strips comments/includes, renames any
    label/CWE/testcase-bearing identifier, and any caller-supplied extra tokens
    (e.g. the source file basename). Deterministic per input."""
    s = strip_comments(func_src)
    rename = {}

    def repl(m):
        tok = m.group(0)
        rename.setdefault(tok, f"id_{len(rename):02d}")
        return rename[tok]

    s = _LABEL_ID.sub(repl, s)
    s = _CWE_ID.sub(repl, s)
    for t in extra_tokens:
        if t:
            s = re.sub(re.escape(t), "id_file", s, flags=re.IGNORECASE)
    s = re.sub(r"\n\s*\n\s*\n", "\n\n", s)
    return s.strip(), rename


def leakage_scan(text):
    """Return the list of forbidden oracle tokens still present (empty = clean)."""
    found = []
    for t, rx in zip(LEAK_TOKENS, _LEAK_RE):
        if rx.search(text):
            found.append(t)
    return found


# ------------------------------------------------------------ structural skeletons
_C_KEYWORDS = {"if", "else", "for", "while", "do", "switch", "case", "default",
               "goto", "return", "break", "continue", "sizeof"}
# Storage-class / cv-qualifiers are declaration decorations, NOT control/data-flow
# topology. In Juliet the safe helpers are declared `static` while the vulnerable
# `bad` is public — a single `static` token must not split a vulnerable/safe pair
# into two flow families. Dropped at flow level; kept verbatim at exact-program level.
_SPECIFIERS = {"static", "const", "extern", "inline", "register", "volatile", "auto"}
_TYPES = {"char", "wchar_t", "int", "short", "long", "unsigned", "signed", "size_t",
          "void", "float", "double", "wchar", "uint8_t", "int8_t"}
_SINKS = {"memcpy", "memmove", "strcpy", "strncpy", "wcscpy", "wcsncpy", "strcat",
          "wcscat", "sprintf", "snprintf", "swprintf"}
_LENS = {"strlen", "wcslen"}
_SETS = {"memset", "wmemset"}
# Wide-literal prefixes (L'..'/L"..", u/U/u8) are consumed WITH the literal so a
# wide-char variant does not tokenize an extra "L" identifier and split from its
# narrow-char twin at the flow-topology level (type is a generator-stratum axis).
_TOKEN = re.compile(r"(?:L|u8|u|U)?'(?:\\.|[^'])*'"
                    r"|(?:L|u8|u|U)?\"(?:\\.|[^\"])*\""
                    r"|[A-Za-z_]\w*|\d+\.?\d*|[^\s\w]")
_LITERAL = re.compile(r"^(?:L|u8|u|U)?['\"]|^\d")   # string/char (incl wide prefix) or number


def _tokenize(src):
    return _TOKEN.findall(strip_comments(src))


def flow_skeleton(func_src):
    """Control/data-flow topology fingerprint: keep C control keywords, call shape and
    punctuation; canonicalize TYPE and SINK (so char/wchar and memcpy/memmove do NOT
    split flow families); erase identifier names and literal values. Same topology ->
    same skeleton, regardless of names/literals/type/sink."""
    out = []
    for t in _tokenize(func_src):
        low = t.lower()
        if low in _SPECIFIERS:
            continue                             # drop storage-class / cv-qualifiers
        if t in _C_KEYWORDS:
            out.append(t)
        elif low in _TYPES:
            out.append("TYPE")
        elif low in _SINKS:
            out.append("SINK")
        elif low in _LENS:
            out.append("LEN")
        elif low in _SETS:
            out.append("SET")
        elif _LITERAL.match(t):
            out.append("L")                      # literal (incl wide-char prefix)
        elif re.match(r"^[A-Za-z_]", t):
            out.append("V")                      # identifier
        else:
            out.append(t)                        # punctuation / operator
    return hashlib.sha256(" ".join(out).encode()).hexdigest()[:16]


def exact_program_skeleton(func_src):
    """Finest level: keep literal VALUES and type/sink identity; erase only names and
    comments. Two programs differing in any literal or sink land in different exact
    families."""
    out = []
    for t in _tokenize(func_src):
        if t in _C_KEYWORDS or t.lower() in _SPECIFIERS or t.lower() in _TYPES \
                or t.lower() in _SINKS or t.lower() in _LENS or t.lower() in _SETS:
            out.append(t.lower())               # keep storage-class at exact level
        elif re.match(r"^[A-Za-z_]", t):
            out.append("V")
        else:
            out.append(t)                        # keep literals + punctuation verbatim
    return hashlib.sha256(" ".join(out).encode()).hexdigest()[:16]


if __name__ == "__main__":
    import sys
    src = open(sys.argv[1], errors="replace").read()
    out, rm = neutralize(src)
    leaks = leakage_scan(out)
    print(f"renamed {len(rm)} identifiers; residual leaks: {leaks}")
    print("---")
    print(out[:1200])
