#!/usr/bin/env python3
"""ESCAPE-PARITY-BOUNDARY -- delimiter-identity gate (R05), JavaScript + C/C++.

Earlier revisions recorded a quoted-string boundary site only when one side of
the comparison was a quote *literal*. Real parsers routinely parameterise their
delimiters -- `input[p - 1] === escapeChar` -- and every such site was invisible:
not a candidate, not a negative, not even an abstention. That gap was found by
running the property over PapaParse, whose scanner carries the same one-position
shape this property flagged in Gecko and which the analyser never considered.

R05 resolves a delimiter variable to its literal value when every assignment
reaching it in the file is a literal, and abstains when any assignment is not.
Resolution is deliberately all-or-nothing: a configurable quote character
genuinely cannot be decided statically, and an abstention states that, where
silence stated nothing at all.

  D1  a variable resolving to one quote literal behaves exactly like the literal:
      the one-position rule is still a candidate
  D2  resolving delimiters must not turn a parity-correct parser into a
      candidate
  D3  an unresolved quote character abstains -- and is RECORDED, which is the
      whole point of the revision
  D4  a variable resolving to a NON-quote delimiter creates no site at all;
      resolution must not invent sites that were never there
  D5  an unresolved ESCAPE character blocks the whole method: a quote compared
      against a literal is not evidence of correctness when the escape it is
      paired with is configurable
  D6  the real-parser shape (search-established position, both delimiters
      configurable) abstains rather than vanishing
  D7  inline literals are unchanged by the revision
  D8  C/C++ reproduces D1, D3, D2 and D4 through its own producer
  D9  no site whose delimiter identity is unresolved is ever a candidate
  D10 every character-scanner record carries a delimiter_resolution
  D11 the earlier fixture corpora keep their verdicts under the revision
  D12 reportable=false, and no record carries impact or severity language
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "parser_model"))
from escape_parity_sites import (  # noqa: E402
    derive, CANDIDATE, NEGATIVE, ABSTAINED,
    SINGLE_POSITION_INDEX_CHECK, PARITY_ESTABLISHED_IN_METHOD,
    UNRESOLVED_DELIMITER_IDENTITY,
)

results = []


def tooth(name, ok, detail=""):
    results.append((name, ok, detail))


js = derive(HERE / "fixtures_delim" / "raw", "JAVASCRIPT")["findings"]
cpp = derive(HERE / "fixtures_delim_cpp" / "raw", "C_CPP")["findings"]


def by_unit(findings, prefix):
    return [f for f in findings if f["file"].startswith(prefix)]


def sole(findings, prefix):
    rows = by_unit(findings, prefix)
    return rows[0] if len(rows) == 1 else None


# ---------------------------------------------------------------- D1 .. D7
d01 = sole(js, "d01-")
tooth("D1 resolved quote variable -> candidate on the one-position rule",
      d01 is not None and d01["classification"] == CANDIDATE
      and d01["boundary_rule"] == SINGLE_POSITION_INDEX_CHECK
      and d01["delimiter_resolution"] == "RESOLVED",
      json.dumps(d01, sort_keys=True)[:180] if d01 else "no single record")

d02 = sole(js, "d02-")
tooth("D2 resolved delimiters + parity counting -> negative",
      d02 is not None and d02["classification"] == NEGATIVE
      and d02["boundary_rule"] == PARITY_ESTABLISHED_IN_METHOD,
      json.dumps(d02, sort_keys=True)[:180] if d02 else "no single record")

d03 = sole(js, "d03-")
tooth("D3 unresolved quote character -> recorded, and abstains",
      d03 is not None and d03["classification"] == ABSTAINED
      and d03["abstention_reason"] == UNRESOLVED_DELIMITER_IDENTITY,
      json.dumps(d03, sort_keys=True)[:180] if d03 else "no single record")

tooth("D4 a non-quote delimiter creates no site",
      by_unit(js, "d04-") == [],
      "%d record(s)" % len(by_unit(js, "d04-")))

d05 = by_unit(js, "d05-")
tooth("D5 an unresolved escape blocks every verdict in its method",
      len(d05) > 0 and all(f["classification"] == ABSTAINED for f in d05),
      ", ".join("%s/%s" % (f["classification"], f["boundary_rule"]) for f in d05))

d06 = by_unit(js, "d06-")
tooth("D6 the real-parser shape abstains rather than vanishing",
      len(d06) > 0 and all(f["classification"] == ABSTAINED for f in d06),
      ", ".join("%s L%s" % (f["classification"], f["line"]) for f in d06))

d07 = sole(js, "d07-")
tooth("D7 inline literals unchanged by the revision",
      d07 is not None and d07["classification"] == CANDIDATE
      and d07["delimiter_resolution"] == "LITERAL",
      json.dumps(d07, sort_keys=True)[:180] if d07 else "no single record")

# ------------------------------------------------------------------- D8
e01, e02, e03 = sole(cpp, "e01"), sole(cpp, "e02"), sole(cpp, "e03")
tooth("D8 C/C++ reproduces resolved-candidate, unresolved-abstain, "
      "resolved-parity-negative and non-quote-silent",
      e01 is not None and e01["classification"] == CANDIDATE
      and e01["delimiter_resolution"] == "RESOLVED"
      and e02 is not None and e02["classification"] == ABSTAINED
      and e02["abstention_reason"] == UNRESOLVED_DELIMITER_IDENTITY
      and e03 is not None and e03["classification"] == NEGATIVE
      and by_unit(cpp, "e04") == [],
      "; ".join("%s=%s" % (f["file"], f["classification"]) for f in cpp))

# ------------------------------------------------------------------- D9
unresolved = [f for f in js + cpp
              if f.get("delimiter_resolution") == "UNRESOLVED"]
tooth("D9 an unresolved delimiter is never a candidate",
      len(unresolved) > 0 and all(f["classification"] != CANDIDATE
                                  for f in unresolved),
      "%d unresolved site(s), candidates among them: %d"
      % (len(unresolved),
         sum(1 for f in unresolved if f["classification"] == CANDIDATE)))

# ------------------------------------------------------------------ D10
scanners = [f for f in js + cpp if f["site_kind"] == "CHARACTER_SCANNER"]
tooth("D10 every character-scanner record carries a delimiter resolution",
      len(scanners) > 0
      and all(f.get("delimiter_resolution") in ("LITERAL", "RESOLVED", "UNRESOLVED")
              for f in scanners),
      "%d scanner record(s)" % len(scanners))

# ------------------------------------------------------------------ D11
# The earlier corpora must keep their verdicts: this revision widens what is
# SEEN, it does not move any verdict that was already reachable.
PRIOR = json.loads((HERE / "fixtures_delim" / "PRE_R05_VERDICTS.json").read_text())
prior_ok, prior_detail = True, []
for path, expected in PRIOR["baselines"].items():
    lang = "C_CPP" if "cpp" in path else "JAVASCRIPT"
    got = sorted(({"file": f["file"], "line": f["line"], "site_kind": f["site_kind"],
                   "classification": f["classification"],
                   "boundary_rule": f.get("boundary_rule")}
                  for f in derive(HERE / path, lang)["findings"]),
                 key=lambda r: (r["file"], r["line"], r["site_kind"]))
    moved = [(a, b) for a, b in zip(expected, got) if a != b]
    if got != expected:
        prior_ok = False
        prior_detail.append("%s: %d site(s) differ, first %r vs %r"
                            % (path, max(len(moved), abs(len(got) - len(expected))),
                               moved[0][0] if moved else None,
                               moved[0][1] if moved else None))
    else:
        prior_detail.append("%s: %d sites unchanged" % (path, len(got)))
tooth("D11 every earlier per-site verdict is unchanged", prior_ok,
      "; ".join(prior_detail))

# ------------------------------------------------------------------ D12
BANNED = ("vulnerab", "exploit", "severity", "attacker", "impact",
          "critical", "cve", "payload")
bad = []
for f in js + cpp:
    blob = json.dumps(f).lower()
    if f.get("reportable") is not False:
        bad.append("%s: reportable is not false" % f["file"])
    for w in BANNED:
        if w in blob:
            bad.append("%s: %r" % (f["file"], w))
tooth("D12 reportable=false and no impact or severity language",
      not bad, "; ".join(bad[:4]))

# ------------------------------------------------------------------- report
width = max(len(n) for n, _, _ in results)
for name, ok, detail in results:
    print("%-*s  %s" % (width, name, "PASS" if ok else "FAIL"))
    if not ok and detail:
        print("%s  %s" % (" " * width, detail))
passed = sum(1 for _, ok, _ in results if ok)
print("\nESCAPE_PARITY_DELIMITER_IDENTITY=%d/%d" % (passed, len(results)))
print("PROMOTION_GATE=%s" % ("PASS" if passed == len(results) else "FAIL"))
sys.exit(0 if passed == len(results) else 1)
