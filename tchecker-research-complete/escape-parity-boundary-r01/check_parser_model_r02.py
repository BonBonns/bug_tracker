#!/usr/bin/env python3
"""ESCAPE-PARITY parser-model gate -- 15 required parser controls, dialect-separated.

This gate covers the PARSER-ONLY layer: how a quote-boundary rule is recovered from a
resolved AST/CPG site and classified. It contains no delayed-dataflow reachability; that
layer is added only after this one is frozen.

The dialect boundary is the point of this gate. The historical differential is PHP/PCRE
and the corpus is ECMAScript. They use SEPARATE adapters over one shared parity rule, and
successful parsing of a PCRE pattern is never evidence that the ECMAScript path is
correct. Every ECMAScript conclusion below is confirmed with node's own RegExp engine and
every PCRE conclusion with PHP's own PCRE engine.

  P1  escape runs of length 0..6 before a quote, exercised in BOTH engines
  P2  odd runs -> the quote is escaped (the value continues)
  P3  even runs -> the quote terminates the value
  P4  one-character negative lookbehind -> candidate
  P5  explicit parity-counting construction -> negative
  P6  backslashes inside character classes
  P7  escaped backslashes inside regex literals
  P8  alternation affecting the quote branch
  P9  nested and non-capturing groups
  P10 lookbehind unrelated to quote termination -> never a candidate
  P11 dynamically constructed RegExp -> abstain unless the pattern identity is uniquely
      resolved
  P12 regex-looking text inside strings and comments -> never discovered as a site
  P13 PCRE-only syntax is never silently interpreted as ECMAScript
  P14 flags recorded as evidence; g/s/m/u/i do not move the parity conclusion
  P15 the real 7.109 and 7.110 patterns classified correctly, under PCRE
  P16 every record carries regex_dialect and evidence_role, and the role guard holds
  P17 structural site identity is retained from the CPG (distinct nodes stay distinct)
"""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "parser_model"))
from boundary_model import (  # noqa: E402
    classify, classify_ecmascript, classify_pcre_historical,
    ECMASCRIPT, PCRE, CORPUS_ANALYSIS, HISTORICAL_DESIGN_DIFFERENTIAL,
    FOREIGN_DIALECT_SYNTAX, UNMODELLED_BOUNDARY_SHAPE,
    PARITY_ESTABLISHED, SINGLE_CHAR_LOOKBEHIND, NEGATED_CLASS_ONE_CHAR,
    NO_ESCAPE_AWARENESS, ESCAPE_IMPOSSIBLE_IN_BODY, NO_QUOTED_STRING_CONSTRUCT,
)

results = []


def tooth(name, ok, detail=""):
    results.append((name, ok, detail))


# ---------------------------------------------------------------- fact loading
def _unescape(s):
    out, i = [], 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "\\":
                out.append("\\"); i += 2; continue
            if n == "n":
                out.append("\n"); i += 2; continue
            if n == "t":
                out.append("\t"); i += 2; continue
        out.append(s[i]); i += 1
    return "".join(out)


sites = []
for line in (HERE / "fixtures_parser" / "raw" / "regex_sites.tsv").read_text().splitlines():
    if not line.strip():
        continue
    p = (line.split("\t") + [""] * 9)[:9]
    sites.append({"file": p[0], "package": p[0].split("/")[0], "method": p[1],
                  "method_id": p[2], "line": p[3], "node_id": p[4], "resolution": p[5],
                  "pattern": _unescape(p[6]), "flags": p[7], "detail": p[8]})


def sites_of(pkg):
    return [s for s in sites if s["package"] == pkg]


def es_verdicts(pkg):
    """Classify every ECMAScript site of a fixture package through the corpus path."""
    out = []
    for s in sites_of(pkg):
        if s["resolution"] == "UNRESOLVED_DYNAMIC":
            out.append({"site": s, "record": None})
            continue
        out.append({"site": s, "record": classify_ecmascript(s["pattern"], s["flags"])})
    return out


# ---------------------------------------------------------------- P1 / P2 / P3
matrix = [json.loads(l) for l in
          (HERE / "parity_matrix" / "pcre_matrix.jsonl").read_text().splitlines()]
matrix += [json.loads(l) for l in
           (HERE / "parity_matrix" / "ecmascript_matrix.jsonl").read_text().splitlines()]
rules = {r["id"]: r for r in json.loads((HERE / "parity_matrix" / "rules.json").read_text())}
by_rule = {}
for row in matrix:
    by_rule.setdefault(row["rule_id"], {})[row["run_length"]] = row

RUNS = list(range(7))
engines = {row["dialect"] for row in matrix}
tooth("P1 escape runs 0..6 exercised for every rule, in BOTH engines separately",
      len(by_rule) == len(rules)
      and all(set(v) == set(RUNS) for v in by_rule.values())
      and engines == {"PCRE", "ECMASCRIPT"}
      and not any(row.get("engine_error") for row in matrix),
      f"rules={len(by_rule)} engines={engines}")

# A parity-establishing rule must obey the parity rule at EVERY run length; the
# one-position rule must obey it on odd runs and violate it on even runs >= 2.
PARITY_RULES = ("pcre_historical_corrected", "es_classic_parity", "es_unrolled_parity")
ONECHAR_RULES = ("pcre_historical_faulty", "es_one_char_lookbehind")

odd_ok = all(by_rule[r][n]["matches_parity_rule"] for r in PARITY_RULES + ONECHAR_RULES
             for n in RUNS if n % 2 == 1)
tooth("P2 odd runs -> the quote is escaped and the value continues "
      "(all parity rules AND the one-position rules agree here)", odd_ok, "")

even_parity_ok = all(by_rule[r][n]["matches_parity_rule"] for r in PARITY_RULES
                     for n in RUNS if n % 2 == 0)
even_onechar_bad = all(not by_rule[r][n]["matches_parity_rule"] for r in ONECHAR_RULES
                       for n in RUNS if n % 2 == 0 and n >= 2)
tooth("P3 even runs -> the quote terminates: parity rules obey it at every even run, "
      "the one-position rules violate it at every even run >= 2",
      even_parity_ok and even_onechar_bad,
      f"parity_ok={even_parity_ok} onechar_violates={even_onechar_bad}")

# ---------------------------------------------------------------- P4 / P5
p14 = es_verdicts("p14-flags")
onechar = [v for v in p14 if v["record"] and v["record"]["verdict"] == SINGLE_CHAR_LOOKBEHIND]
tooth("P4 one-character negative lookbehind (ECMAScript, from a real CPG site) -> candidate",
      len(onechar) == 4 and all(v["record"]["is_candidate"] for v in onechar)
      and all(v["record"]["regex_dialect"] == ECMASCRIPT for v in onechar),
      str([v["site"]["flags"] for v in onechar]))

p06 = es_verdicts("p06-class-backslash")
explicit_pair = [v for v in p06 if "\\\\\\\\" in v["site"]["pattern"]]
tooth("P5 explicit parity-counting construction (escape-PAIR alternative) -> negative",
      len(explicit_pair) == 1
      and explicit_pair[0]["record"]["verdict"] == PARITY_ESTABLISHED
      and explicit_pair[0]["record"]["is_candidate"] is False,
      str([(v["site"]["pattern"], v["record"]["verdict"]) for v in p06]))

# ---------------------------------------------------------------- P6 / P7
by_pat = {v["site"]["pattern"]: v["record"] for v in p06}
tooth("P6 backslashes inside character classes are parsed as escape atoms, not as "
      "class terminators (a class excluding the escape char, and one that cannot "
      "contain one at all)",
      by_pat[r"'([^'\\]*(?:\\.[^'\\]*)*)'"]["verdict"] == PARITY_ESTABLISHED
      and by_pat[r"'([^'\\]*)'"]["verdict"] == ESCAPE_IMPOSSIBLE_IN_BODY,
      str({k: v["verdict"] for k, v in by_pat.items()}))
tooth("P7 escaped backslashes inside regex literals survive the CPG round trip and parse "
      "as an escape PAIR",
      by_pat[r"'((?:\\\\|[^'\\])*)'"]["verdict"] == PARITY_ESTABLISHED,
      str(by_pat.get(r"'((?:\\\\|[^'\\])*)'")))

# ---------------------------------------------------------------- P8
p08 = {v["site"]["pattern"]: v["record"] for v in es_verdicts("p08-alternation-quote-branch")}
tooth("P8 alternation: an incomplete rule in ONE branch still yields a candidate; an "
      "alternation whose quoted branches are all parity-establishing does not",
      p08[r"(?:\d+|'(.*?)(?<!\\)')"]["verdict"] == SINGLE_CHAR_LOOKBEHIND
      and p08[r"""(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")"""]["verdict"] == PARITY_ESTABLISHED,
      str({k: v["verdict"] for k, v in p08.items()}))

# ---------------------------------------------------------------- P9
p09 = {v["site"]["pattern"]: v["record"] for v in es_verdicts("p09-nested-groups")}
tooth("P9 nested and non-capturing groups do not hide either verdict",
      p09[r"'(((?:(?:[^'\\])|(?:\\.))*))'"]["verdict"] == PARITY_ESTABLISHED
      and p09[r"'((?:(.*?)))(?<!\\)'"]["verdict"] == SINGLE_CHAR_LOOKBEHIND,
      str({k: v["verdict"] for k, v in p09.items()}))

# ---------------------------------------------------------------- P10
p10 = es_verdicts("p10-unrelated-lookbehind")
tooth("P10 lookbehinds unrelated to quote termination are never candidates",
      len(p10) == 3 and all(v["record"]["is_candidate"] is False for v in p10)
      and all(v["record"]["verdict"] == NO_QUOTED_STRING_CONSTRUCT for v in p10),
      str([(v["site"]["pattern"], v["record"]["verdict"]) for v in p10]))

# ---------------------------------------------------------------- P11
p11a = es_verdicts("p11a-dynamic-resolved")
p11b = sites_of("p11b-dynamic-unresolved")
tooth("P11 dynamic RegExp: classified only when the pattern identity is uniquely "
      "resolved, abstained when it is not",
      len(p11a) == 1 and p11a[0]["site"]["resolution"] == "RESOLVED_CONST_STRING"
      and p11a[0]["record"]["verdict"] == SINGLE_CHAR_LOOKBEHIND
      and p11a[0]["record"]["is_candidate"] is True
      and len(p11b) == 1 and p11b[0]["resolution"] == "UNRESOLVED_DYNAMIC"
      and p11b[0]["pattern"] == "",
      str((p11a[0]["site"]["resolution"], p11b[0]["resolution"])))

# ---------------------------------------------------------------- P12
p12 = sites_of("p12-regex-in-text")
tooth("P12 regex-looking text in strings and comments is never discovered as a site "
      "(exactly one real regex in that fixture, discovered structurally from the CPG)",
      len(p12) == 1 and p12[0]["pattern"] == r"'((?:[^'\\]|\\.)*)'"
      and classify_ecmascript(p12[0]["pattern"])["verdict"] == PARITY_ESTABLISHED,
      str([s["pattern"] for s in p12]))

# ---------------------------------------------------------------- P13
PCRE_ONLY = [
    (r"'((?:[^'\\]++|\\.)*+)'", "possessive quantifier (the real 7.110 pattern)"),
    (r"'(?>[^']*)'", "atomic group"),
    (r"(?i)'(.*?)(?<!\\)'", "inline modifier group"),
    (r"'(?#note)(.*?)(?<!\\)'", "comment group"),
    (r"(?P<v>'(.*?)')", "PCRE named group"),
    (r"\A'(.*?)'\z", "PCRE-only anchors"),
]
p13_rows = []
for pat, what in PCRE_ONLY:
    es = classify_ecmascript(pat)
    pc = classify(pat, PCRE, HISTORICAL_DESIGN_DIFFERENTIAL)
    p13_rows.append((what, es["abstained"], es.get("abstention_reason"), pc["abstained"]))
tooth("P13 PCRE-only syntax is never silently interpreted as ECMAScript "
      "(every construct abstains with FOREIGN_DIALECT_SYNTAX under the ECMAScript "
      "adapter, while the PCRE adapter parses it)",
      all(r[1] and r[2] == FOREIGN_DIALECT_SYNTAX and not r[3] for r in p13_rows),
      str(p13_rows))

# ---------------------------------------------------------------- P14
flag_records = [v["record"] for v in p14 if v["record"]]
onechar_flag_variants = {}
for v in p14:
    if v["record"] and v["site"]["pattern"] == r"'(.*?)(?<!\\)'":
        onechar_flag_variants[v["site"]["flags"]] = v["record"]["verdict"]
tooth("P14 flags are recorded as evidence and do not move the parity conclusion: the "
      "same rule under no flags / g / gs / gimsu yields one verdict, and no record "
      "claims a flag-dependent verdict",
      set(onechar_flag_variants) == {"", "g", "gs", "gimsu"}
      and len(set(onechar_flag_variants.values())) == 1
      and all(r["flags_affect_verdict"] is False for r in flag_records)
      and all(r["unknown_flags"] == [] for r in flag_records),
      str(onechar_flag_variants))

# ---------------------------------------------------------------- P15
faulty = classify_pcre_historical(r"'(.*?)(?<!\\)'", "S")
corrected = classify_pcre_historical(r"'((?:[^'\\]++|\\.)*+)'", "sS")
tooth("P15 the real 7.109 and 7.110 patterns classify correctly under PCRE "
      "(faulty -> candidate, corrected -> negative), each tagged as historical evidence",
      faulty["verdict"] == SINGLE_CHAR_LOOKBEHIND and faulty["is_candidate"] is True
      and corrected["verdict"] == PARITY_ESTABLISHED and corrected["is_candidate"] is False
      and faulty["regex_dialect"] == PCRE == corrected["regex_dialect"]
      and faulty["evidence_role"] == HISTORICAL_DESIGN_DIFFERENTIAL
      and corrected["evidence_role"] == HISTORICAL_DESIGN_DIFFERENTIAL,
      f"{faulty['verdict']} / {corrected['verdict']}")

# ---------------------------------------------------------------- P16
all_records = [v["record"] for v in
               (p14 + p06 + p10 + p11a + es_verdicts("p08-alternation-quote-branch")
                + es_verdicts("p09-nested-groups")) if v["record"]] + [faulty, corrected]
role_guard_held = False
try:
    classify(r"'(.*?)'", PCRE, CORPUS_ANALYSIS)
except ValueError:
    role_guard_held = True
tooth("P16 every record carries regex_dialect and evidence_role, and PCRE evidence "
      "cannot be requested for corpus analysis at all",
      all(r["regex_dialect"] in (ECMASCRIPT, PCRE) for r in all_records)
      and all(r["evidence_role"] in (CORPUS_ANALYSIS, HISTORICAL_DESIGN_DIFFERENTIAL)
              for r in all_records)
      and all(r["evidence_role"] == CORPUS_ANALYSIS
              for r in all_records if r["regex_dialect"] == ECMASCRIPT)
      and all(r["evidence_role"] == HISTORICAL_DESIGN_DIFFERENTIAL
              for r in all_records if r["regex_dialect"] == PCRE)
      and role_guard_held,
      f"role_guard_held={role_guard_held} n={len(all_records)}")

# ---------------------------------------------------------------- P17
ids = [s["node_id"] for s in sites_of("p14-flags")]
same_text = [s for s in sites_of("p14-flags") if s["pattern"] == r"'(.*?)(?<!\\)'"]
tooth("P17 structural site identity is retained: four sites share identical rule text "
      "and remain four distinct CPG node identities",
      len(same_text) == 4 and len({s["node_id"] for s in same_text}) == 4
      and len(ids) == len(set(ids)),
      str([s["node_id"] for s in same_text]))

passed = sum(1 for _, ok, _ in results if ok)
for name, ok, detail in results:
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "\n        <- " + detail[:400]))
print(f"ESCAPE_PARITY_PARSER_MODEL={passed}/{len(results)}")
print("PROMOTION_GATE=" + ("PASS" if passed == len(results) else "FAIL"))
sys.exit(0 if passed == len(results) else 1)
