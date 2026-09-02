#!/usr/bin/env python3
"""ESCAPE-PARITY-BOUNDARY -- parser-only site classifier, language-neutral.

The defect shape is language-independent:

    A quote is escaped when preceded by an ODD-length consecutive escape run.
    A quote terminates the string when preceded by an EVEN-length escape run.

    A boundary rule that inspects a fixed single preceding position cannot establish
    that parity, whether it is written as  s[i-1] != '\\\\'  in C++,
    *(p-1) != '\\\\'  in C, or  s[i-1] !== '\\\\'  in JavaScript, or as a
    one-character negative lookbehind in a regex.

TARGET LANGUAGES: JavaScript/TypeScript (jssrc2cpg) and C/C++ (c2cpg). Each has its own
producer, because the CPG spellings genuinely differ -- character literals keep their
source escaping in C/C++ but not in JS, and C/C++ has three character-access forms where
JS has two. Both producers emit the SAME fact schema and both feed this one classifier,
so a finding means the same thing in either language.

REGEX DIALECTS are a separate axis from language. A JS regex literal and a std::regex
pattern are both ECMAScript (std::regex's default grammar is ECMAScript), so both go to
the ECMAScript adapter. PCRE is reachable only as the historical design reference and can
never be requested for corpus analysis.

reportable is false on every record in this revision.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "parser_model"))
from boundary_model import (  # noqa: E402
    classify_ecmascript, ECMASCRIPT, CORPUS_ANALYSIS,
    SINGLE_CHAR_LOOKBEHIND, NEGATED_CLASS_ONE_CHAR, NO_ESCAPE_AWARENESS,
)

CANDIDATE = "ESCAPE_PARITY_PARSER_CANDIDATE"
NEGATIVE = "NEGATIVE"
ABSTAINED = "ABSTAINED"

SINGLE_POSITION_INDEX_CHECK = "SINGLE_POSITION_INDEX_CHECK"
PARITY_ESTABLISHED_IN_METHOD = "PARITY_ESTABLISHED_IN_METHOD"
UNRESOLVED_REGEX_CONSTRUCTION = "UNRESOLVED_REGEX_CONSTRUCTION"
UNRESOLVED_DELIMITER_IDENTITY = "UNRESOLVED_DELIMITER_IDENTITY"

LANGUAGES = {"JAVASCRIPT": "jssrc2cpg", "C_CPP": "c2cpg"}


def _rows(path, n):
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            out.append((line.split("\t") + [""] * n)[:n])
    return out


def _unescape(s):
    out, i = [], 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            nx = s[i + 1]
            if nx in "\\nt":
                out.append({"\\": "\\", "n": "\n", "t": "\t"}[nx]); i += 2; continue
        out.append(s[i]); i += 1
    return "".join(out)


def derive(raw_dir, language=None):
    raw = Path(raw_dir)
    if language is None:
        lang_rows = _rows(raw / "language.tsv", 2)
        language = lang_rows[0][0] if lang_rows else "JAVASCRIPT"
    frontend = LANGUAGES.get(language, "?")

    regex_sites = _rows(raw / "regex_sites.tsv", 9)
    quote_sites = _rows(raw / "parser_quote_sites.tsv", 8)
    index_checks = _rows(raw / "parser_index_checks.tsv", 11)
    parity_rows = _rows(raw / "parity_mechanisms.tsv", 6)

    parity_methods = {}
    for f_, meth, mid, line, nid, mech in parity_rows:
        parity_methods.setdefault(mid, []).append(
            {"mechanism": mech, "node_id": nid, "line": line})

    checks_by_method = {}
    for (f_, meth, mid, line, cid, qid, eid, iid, off, base, idx) in index_checks:
        checks_by_method.setdefault(mid, []).append(
            {"check_node_id": cid, "quote_cmp_node_id": qid, "escape_cmp_node_id": eid,
             "index_expr_node_id": iid, "index_offset": off, "base_expr": base,
             "index_var": idx, "line": line})

    findings = []

    def base(f_, meth, mid, line, nid, kind):
        return {"language": language, "frontend": frontend, "file": f_,
                "unit": f_.split("/")[-1], "method": meth, "method_node_id": mid,
                "line": line, "site_kind": kind, "site_node_id": nid,
                "escape_char": "\\", "reportable": False}

    # --- regex boundary rules (JS literals / RegExp, and C++ std::regex) ------
    for f_, meth, mid, line, nid, resolution, pattern, flags, detail in regex_sites:
        rec = base(f_, meth, mid, line, nid,
                   "REGEX_LITERAL" if resolution == "RESOLVED_LITERAL" else "REGEX_CONSTRUCTED")
        rec["pattern_resolution"] = resolution
        rec["pattern"] = _unescape(pattern)
        rec["flags"] = flags
        if resolution == "UNRESOLVED_DYNAMIC":
            rec.update(regex_dialect=ECMASCRIPT, evidence_role=CORPUS_ANALYSIS,
                       boundary_rule=UNRESOLVED_REGEX_CONSTRUCTION,
                       classification=ABSTAINED,
                       abstention_reason=UNRESOLVED_REGEX_CONSTRUCTION)
            findings.append(rec)
            continue
        # both JS regex literals and std::regex are ECMAScript-grammar patterns
        r = classify_ecmascript(rec["pattern"], flags)
        rec.update(regex_dialect=r["regex_dialect"], evidence_role=r["evidence_role"],
                   flags_affect_verdict=r["flags_affect_verdict"],
                   boundary_rule=r["verdict"] if r["verdict"] else r["abstention_reason"])
        if r["abstained"]:
            rec.update(classification=ABSTAINED, abstention_reason=r["abstention_reason"],
                       abstention_detail=r["detail"])
        elif r["is_candidate"]:
            rec["classification"] = CANDIDATE
        else:
            rec.update(classification=NEGATIVE, negative_reason=r["verdict"])
        findings.append(rec)

    # --- hand-written character-scanning parsers (JS and C/C++ alike) ---------
    # A boundary rule is decided per method, so one unresolved delimiter blocks
    # the whole method: a quote comparison against a literal is not evidence of
    # a parity-correct parser when the escape character it is paired with is
    # configurable. Without this, a method like d05 would report one abstention
    # and one confident NO_ESCAPE_AWARENESS negative about the same rule.
    methods_with_unresolved = {row[2] for row in quote_sites if row[7] == "UNRESOLVED"}

    for f_, meth, mid, line, cmp_id, other_id, access_kind, delim_res in quote_sites:
        rec = base(f_, meth, mid, line, cmp_id, "CHARACTER_SCANNER")
        rec.update(compared_expr_node_id=other_id, char_access_kind=access_kind,
                   delimiter_resolution=delim_res or "LITERAL",
                   pattern_resolution="N/A", pattern="", flags="",
                   regex_dialect=None, evidence_role=CORPUS_ANALYSIS)
        my_checks = checks_by_method.get(mid, [])
        if delim_res == "UNRESOLVED" or mid in methods_with_unresolved:
            # The scanner compares a character against a delimiter whose value
            # cannot be pinned down -- a configurable quote or escape character.
            # Neither verdict is available: the site cannot be cleared, and it
            # cannot be called a candidate either. It abstains, which is still
            # far better than the site being invisible.
            rec.update(boundary_rule=UNRESOLVED_DELIMITER_IDENTITY,
                       classification=ABSTAINED,
                       abstention_reason=UNRESOLVED_DELIMITER_IDENTITY)
        elif mid in parity_methods:
            rec["parity_mechanisms"] = parity_methods[mid]
            rec.update(boundary_rule=PARITY_ESTABLISHED_IN_METHOD,
                       classification=NEGATIVE, negative_reason=PARITY_ESTABLISHED_IN_METHOD)
        elif my_checks:
            rec["single_position_checks"] = my_checks
            rec.update(boundary_rule=SINGLE_POSITION_INDEX_CHECK, classification=CANDIDATE)
        else:
            rec.update(boundary_rule=NO_ESCAPE_AWARENESS, classification=NEGATIVE,
                       negative_reason=NO_ESCAPE_AWARENESS)
        findings.append(rec)

    return {
        "schema": "escape-parity-boundary/sites-0.2",
        "language": language,
        "frontend": frontend,
        "property": "quoted-string escape-run parity at the quote boundary",
        "note": (
            "Parser-only layer. Classifies whether a quote-boundary rule can establish "
            "the parity of the complete consecutive escape run. Site discovery is "
            "structural, from CPG node identities; regexes are never found by searching "
            "source text. Regex patterns are parsed by the dialect adapter matching where "
            "they run -- ECMAScript for JavaScript regex literals and for std::regex, "
            "whose default grammar is ECMAScript. Delayed-source/transform/consumer "
            "reachability is a separate layer and is not included here. No impact, "
            "severity or exploitability claim is made; reportable is false throughout."),
        "classification_vocabulary": [CANDIDATE],
        "findings": findings,
    }


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1], *(sys.argv[2:3] or [None])), indent=2))
