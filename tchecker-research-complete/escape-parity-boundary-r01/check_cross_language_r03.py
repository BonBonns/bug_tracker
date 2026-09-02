#!/usr/bin/env python3
"""ESCAPE-PARITY-BOUNDARY -- cross-language detection gate (JavaScript + C/C++).

The target engines are JavaScript/TypeScript and C/C++. The PHP finding that motivated
this property is a SHAPE REFERENCE only: it specifies the defect, it is not an analysis
target and contributes nothing to any corpus total.

The defect shape, restated language-neutrally:

    A quote is escaped when preceded by an ODD-length consecutive escape run.
    A quote terminates the string when preceded by an EVEN-length escape run.

    A boundary rule that inspects a fixed single preceding position cannot establish
    that parity -- written as s[i-1], *(p-1), s.at(i-1), or a one-character regex
    lookbehind.

  X1  C++ subscript form            s[i] == q && s[i-1] != '\\'      -> candidate
  X2  C++ pointer form              *p == q && *(p-1) != '\\'        -> candidate
  X3  C++ member-call form          s.at(i) == q && s.at(i-1) != '\\'-> candidate
  X4  C++ bounds-guarded form       (i == 0 || s[i-1] != '\\')       -> still a candidate
  X5  C++ explicit escape-run counting                               -> negative
  X6  C++ parity-aware state machine                                 -> negative
  X7  C++ no escape awareness (a different shape)                    -> negative
  X8  C++ std::regex classified through the ECMAScript adapter (its default grammar),
      never the PCRE one
  X9  JavaScript detects the same shape, through its own producer
  X10 both languages share ONE verdict vocabulary
  X11 the C++ engine reproduces the parity signature at runtime, runs 0..6
  X12 all three engines (native C++, ECMAScript, PCRE) show the SAME signature for the
      one-position rule, and it differs from the no-escape-awareness shape
  X13 C/C++ character literals are decoded from their source escaping
  X14 site identity is retained from the CPG in both languages
  X15 reportable=false, and no finding carries impact/severity/exploitability language
"""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "parser_model"))
from escape_parity_sites import derive, CANDIDATE, NEGATIVE, ABSTAINED  # noqa: E402
from boundary_model import ECMASCRIPT, PCRE  # noqa: E402

cpp = derive(HERE / "fixtures_cpp" / "raw")
js = derive(HERE / "fixtures_parser" / "raw")
cpp_by = {}
for f in cpp["findings"]:
    cpp_by.setdefault(f["unit"], []).append(f)

results = []


def tooth(name, ok, detail=""):
    results.append((name, ok, detail))


def one(unit, kind=None):
    rows = [r for r in cpp_by.get(unit, []) if kind is None or r["site_kind"] == kind]
    return rows[0] if len(rows) == 1 else None


for key, unit, note in (
        ("X1", "q01_index_onechar.cpp", "subscript  s[i-1]"),
        ("X2", "q02_pointer_onechar.cpp", "pointer    *(p-1)"),
        ("X3", "q03_at_onechar.cpp", "member     s.at(i-1)"),
        ("X4", "q08_guarded_onechar.cpp", "bounds-guarded (i==0 || s[i-1]...)")):
    f = one(unit, "CHARACTER_SCANNER")
    ok = (f is not None and f["classification"] == CANDIDATE
          and f["boundary_rule"] == "SINGLE_POSITION_INDEX_CHECK"
          and f["language"] == "C_CPP"
          and f["single_position_checks"][0]["index_offset"] == "1")
    tooth(f"{key} C++ one-position rule, {note} -> candidate", ok, str(f))

f5 = one("q04_counting_negative.cpp", "CHARACTER_SCANNER")
tooth("X5 C++ explicit escape-run counting -> negative",
      f5 is not None and f5["classification"] == NEGATIVE
      and {m["mechanism"] for m in f5["parity_mechanisms"]} >= {"MODULO_TWO",
                                                                "ESCAPE_RUN_COUNT_LOOP"},
      str(f5 and f5.get("parity_mechanisms")))

f6 = one("q05_toggle_negative.cpp", "CHARACTER_SCANNER")
tooth("X6 C++ parity-aware state machine -> negative",
      f6 is not None and f6["classification"] == NEGATIVE
      and any(m["mechanism"] == "BOOLEAN_TOGGLE" for m in f6["parity_mechanisms"]),
      str(f6 and f6.get("parity_mechanisms")))

f7 = one("q06_no_escape_awareness.cpp", "CHARACTER_SCANNER")
tooth("X7 C++ scanner with no escape awareness -> negative (a different shape, not this "
      "property's target)",
      f7 is not None and f7["classification"] == NEGATIVE
      and f7["boundary_rule"] == "NO_ESCAPE_AWARENESS", str(f7))

rx = sorted(cpp_by.get("q07_std_regex.cpp", []), key=lambda r: r["boundary_rule"])
tooth("X8 C++ std::regex is classified by the ECMAScript adapter (std::regex's default "
      "grammar), never the PCRE one; the one-char class form is a candidate and the "
      "parity form is not",
      len(rx) == 2
      and all(r["regex_dialect"] == ECMASCRIPT for r in rx)
      and not any(r["regex_dialect"] == PCRE for r in rx)
      and rx[0]["boundary_rule"] == "NEGATED_CLASS_ONE_CHAR"
      and rx[0]["classification"] == CANDIDATE
      and rx[1]["boundary_rule"] == "PARITY_ESTABLISHED"
      and rx[1]["classification"] == NEGATIVE,
      str([(r["boundary_rule"], r["regex_dialect"]) for r in rx]))

js_cands = [f for f in js["findings"] if f["classification"] == CANDIDATE]
tooth("X9 JavaScript detects the same shape through its own producer",
      js["language"] == "JAVASCRIPT" and len(js_cands) >= 1
      and any(f["boundary_rule"] == "SINGLE_CHAR_LOOKBEHIND" for f in js_cands),
      f"js candidates={len(js_cands)}")

cpp_vocab = {f["classification"] for f in cpp["findings"]}
js_vocab = {f["classification"] for f in js["findings"]}
allowed = {CANDIDATE, NEGATIVE, ABSTAINED}
tooth("X10 both languages share ONE verdict vocabulary",
      cpp_vocab <= allowed and js_vocab <= allowed
      and cpp["schema"] == js["schema"]
      and cpp["classification_vocabulary"] == js["classification_vocabulary"],
      f"cpp={sorted(cpp_vocab)} js={sorted(js_vocab)}")

# --- X11 / X12: runtime parity signatures, one per engine --------------------
def sig(path, rule_id, key="rule_id"):
    rows = [json.loads(l) for l in Path(path).read_text().splitlines()]
    runs = {r["run_length"]: r["matches_parity_rule"] for r in rows if r[key] == rule_id}
    return "".join("." if runs.get(n) else "X" for n in range(7)) if len(runs) == 7 else "?"


cpp_onechar = sig("parity_matrix/cpp_matrix.jsonl", "cpp_onechar_subscript")
cpp_count = sig("parity_matrix/cpp_matrix.jsonl", "cpp_explicit_counting")
cpp_toggle = sig("parity_matrix/cpp_matrix.jsonl", "cpp_parity_toggle")
cpp_noesc = sig("parity_matrix/cpp_matrix.jsonl", "cpp_no_escape_aware")
tooth("X11 the C++ engine reproduces the parity signature at runtime over escape runs "
      "0..6: the one-position parser is correct at run 0 and every odd run and wrong at "
      "every even run >= 2, while both parity-aware parsers are correct throughout",
      cpp_onechar == "..X.X.X" and cpp_count == "......." and cpp_toggle == ".......",
      f"onechar={cpp_onechar} counting={cpp_count} toggle={cpp_toggle}")

es_onechar = sig("parity_matrix/ecmascript_matrix.jsonl", "es_one_char_lookbehind")
pcre_onechar = sig("parity_matrix/pcre_matrix.jsonl", "pcre_historical_faulty")
tooth("X12 all three engines -- native C++, ECMAScript, PCRE -- show the SAME signature "
      "for the one-position rule (..X.X.X), and the no-escape-awareness shape shows the "
      "complementary one (.X.X.X.), confirming they are different defects",
      cpp_onechar == es_onechar == pcre_onechar == "..X.X.X" and cpp_noesc == ".X.X.X.",
      f"cpp={cpp_onechar} es={es_onechar} pcre={pcre_onechar} noesc={cpp_noesc}")

# --- X13: C literal decoding -------------------------------------------------
checks = [c for f in cpp["findings"] if f["site_kind"] == "CHARACTER_SCANNER"
          for c in f.get("single_position_checks", [])]
tooth("X13 C/C++ character literals are decoded from their source escaping (the escape "
      "comparison is found although the literal is written '\\\\' in source)",
      len(checks) >= 4 and all(c["index_offset"] == "1" for c in checks)
      and {c["base_expr"] for c in checks} == {"s", "<deref>"},
      str([(c["base_expr"], c["index_var"], c["index_offset"]) for c in checks]))

# --- X14: site identity ------------------------------------------------------
cpp_ids = [f["site_node_id"] for f in cpp["findings"]]
js_ids = [f["site_node_id"] for f in js["findings"]]
tooth("X14 site identity is retained from the CPG in both languages (every site carries "
      "a distinct node id and a method identity)",
      len(cpp_ids) == len(set(cpp_ids)) and len(js_ids) == len(set(js_ids))
      and all(f["method_node_id"] not in ("", "-1") for f in cpp["findings"] + js["findings"]),
      f"cpp={len(cpp_ids)} js={len(js_ids)}")

# --- X15: discipline ---------------------------------------------------------
banned = ("vulnerab", "exploit", "attacker", "severity", "cvss", "payload", "malicious")
blob = (json.dumps(cpp["findings"]) + json.dumps(js["findings"])).lower()
tooth("X15 reportable=false on every finding, and no finding carries impact/severity/"
      "exploitability language",
      all(f["reportable"] is False for f in cpp["findings"] + js["findings"])
      and not [b for b in banned if b in blob],
      str([b for b in banned if b in blob]))

passed = sum(1 for _, ok, _ in results if ok)
for name, ok, detail in results:
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "\n        <- " + detail[:350]))
print(f"ESCAPE_PARITY_CROSS_LANGUAGE={passed}/{len(results)}")
print("PROMOTION_GATE=" + ("PASS" if passed == len(results) else "FAIL"))
sys.exit(0 if passed == len(results) else 1)
