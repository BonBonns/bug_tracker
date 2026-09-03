#!/usr/bin/env python3
"""ESCAPE-PARITY-BOUNDARY-R01 control gate -- 14 required controls plus discipline checks.

Every fact consumed here was produced by the real, unmodified pipeline
(jssrc2cpg -> producers/escape_parity_facts.sc -> escape_parity_r01.py) over the
compiled fixtures in fixtures_r01/. The historical differential rows are produced by
historical/differential.php and historical/xcheck_boundary.php against the two published
parser forms.

  K1  one-character negative-lookbehind rule, even-length escape run -> parser candidate
  K2  the same rule with an odd-length escape run -> still a parser candidate (the rule's
      structure, not the sample data, decides)
  K3  a parser that explicitly counts consecutive escape characters -> negative,
      and the contrasting one-position custom parser is still a candidate (so the
      negative is discriminating, not blanket)
  K4  a parity-aware state-machine parser -> negative
  K5  a stored value processed during a later restore -> delayed-source evidence
  K6  an immediate in-memory transformation -> not delayed/second-order
  K7  decode -> replace -> encode -> structured consumer -> complete reachable chain
  K8  the same transformation followed only by logging -> parser candidate only, with
      the logging destination recorded as positive evidence
  K9  dynamically constructed regex with an unresolved pattern -> abstain
  K10 unresolved replacement callback -> chain abstention (the boundary rule stands)
  K11 a parity-correct parser with a separate formatting problem -> outside this property
  K12 multiple parser candidates with ambiguous consumer linkage -> abstain, none promoted
  K13 the same rule text at two program points -> two distinct retained identities
  K14 historical faulty/corrected differential -> candidate / negative, with the published
      behavioural confirmation on both escape-run parities
  K15 reportable=false on every record
  K16 no impact/severity/exploitability language anywhere in the output
  K17 execution timing is carried as evidence only and never reaches a classification
"""
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from escape_parity_r01 import derive, CANDIDATE, REACHABLE, NEGATIVE, ABSTAINED  # noqa: E402

result = derive(HERE / "fixtures_r01" / "raw")
by_pkg = {}
for f in result["findings"]:
    by_pkg.setdefault(f["package"], []).append(f)

results = []


def tooth(name, ok, detail=""):
    results.append((name, ok, detail))


def one(pkg):
    rows = by_pkg.get(pkg, [])
    return rows[0] if len(rows) == 1 else None


# --- K1 / K2 -----------------------------------------------------------------
for key, pkg, note in (("K1", "c01-lookbehind-even", "even-length escape run"),
                       ("K2", "c02-lookbehind-odd", "odd-length escape run")):
    f = one(pkg)
    tooth(f"{key} one-character negative-lookbehind rule, {note} -> parser candidate",
          f is not None and f["classification"] == CANDIDATE
          and f["boundary_rule"] == "SINGLE_CHAR_LOOKBEHIND"
          and f["site_kind"] == "REGEX_LITERAL", str(f))

# --- K3 ----------------------------------------------------------------------
f3, f3b = one("c03-explicit-count"), one("c03b-custom-onechar")
tooth("K3 explicit consecutive-escape counting -> negative, while the contrasting "
      "one-position custom parser stays a candidate",
      f3 is not None and f3["classification"] == NEGATIVE
      and f3["boundary_rule"] == "PARITY_ESTABLISHED_IN_METHOD"
      and any(m["mechanism"] == "MODULO_TWO" for m in f3.get("parity_mechanisms", []))
      and f3b is not None and f3b["classification"] == CANDIDATE
      and f3b["boundary_rule"] == "SINGLE_POSITION_INDEX_CHECK"
      and f3b["single_position_checks"][0]["index_offset"] == "1",
      f"{f3} || {f3b}")

# --- K4 ----------------------------------------------------------------------
f4 = one("c04-parity-state-machine")
tooth("K4 parity-aware state-machine parser -> negative",
      f4 is not None and f4["classification"] == NEGATIVE
      and any(m["mechanism"] == "BOOLEAN_TOGGLE" for m in f4.get("parity_mechanisms", [])),
      str(f4))

# --- K5 ----------------------------------------------------------------------
f5 = one("c05-delayed-source")
src5 = f5["chain"]["delayed_sources"] if f5 else []
tooth("K5 stored value processed during a later restore -> delayed-source evidence "
      "(resolved through a real import, not a name)",
      len(src5) == 1 and src5[0]["source_kind"] == "STORED_FILE_READ"
      and src5[0]["resolution"] == "RESOLVED_IMPORT"
      and src5[0]["api_identity"] == "fs.readFileSync"
      and src5[0]["import_node_id"] not in ("", "-1"), str(src5))

# --- K6 ----------------------------------------------------------------------
f6 = one("c06-immediate")
tooth("K6 immediate in-memory transformation -> not classified as delayed/second-order",
      f6 is not None and f6["chain"]["delayed_sources"] == []
      and "NO_DELAYED_SOURCE_REACHES_TRANSFORMATION" in f6["chain"]["reasons"]
      and f6["classification"] == CANDIDATE, str(f6 and f6["chain"]["reasons"]))

# --- K7 ----------------------------------------------------------------------
f7 = one("c07-full-chain")
c7 = f7["chain"] if f7 else {}
tooth("K7 decode -> replace -> encode -> structured consumer -> complete reachable chain",
      f7 is not None and f7["classification"] == REACHABLE
      and c7.get("status") == "ESTABLISHED"
      and len(c7.get("delayed_sources", [])) == 1
      and len(c7.get("replace_sites", [])) == 1
      and len(c7.get("encodes", [])) == 1
      and [x["consumer_identity"] for x in c7.get("consumers", [])] == ["JSON.parse"]
      and c7.get("reasons") == [], str(c7))

# --- K8 ----------------------------------------------------------------------
f8 = one("c08-log-only")
c8 = f8["chain"] if f8 else {}
tooth("K8 transformation followed only by logging -> parser candidate only, logging "
      "destination recorded as positive evidence",
      f8 is not None and f8["classification"] == CANDIDATE
      and c8.get("consumers") == []
      and [x["consumer_identity"] for x in c8.get("logging_only_consumers", [])] == ["console.log"]
      and len(c8.get("delayed_sources", [])) == 1, str(c8))

# --- K9 ----------------------------------------------------------------------
f9 = one("c09-dynamic-regex")
tooth("K9 dynamically constructed regex, unresolved pattern -> abstain",
      f9 is not None and f9["classification"] == ABSTAINED
      and f9["abstention_reason"] == "UNRESOLVED_REGEX_CONSTRUCTION"
      and f9["pattern"] == "", str(f9))

# --- K10 ---------------------------------------------------------------------
f10 = one("c10-unresolved-callback")
tooth("K10 unresolved replacement callback -> chain abstention, boundary rule still stands",
      f10 is not None and f10["classification"] == CANDIDATE
      and f10["chain"]["status"] == "ABSTAINED"
      and f10.get("chain_abstention_reason") == ["UNRESOLVED_CALLBACK_IDENTITY"], str(f10))

# --- K11 ---------------------------------------------------------------------
f11 = one("c11-correct-with-other-defect")
tooth("K11 parity-correct parser with an unrelated formatting problem -> outside this property",
      f11 is not None and f11["classification"] == NEGATIVE
      and f11["boundary_rule"] == "PARITY_ESTABLISHED_IN_METHOD", str(f11))

# --- K12 ---------------------------------------------------------------------
f12 = by_pkg.get("c12-ambiguous-consumer", [])
tooth("K12 multiple parser candidates with ambiguous consumer linkage -> abstain, "
      "neither promoted to consumer-reachable",
      len(f12) == 2
      and all(x["classification"] == CANDIDATE for x in f12)
      and all(x["chain"]["status"] == "ABSTAINED" for x in f12)
      and all("AMBIGUOUS_CONSUMER_LINKAGE" in x.get("chain_abstention_reason", []) for x in f12)
      and len({x["site_node_id"] for x in f12}) == 2, str(f12))

# --- K13 ---------------------------------------------------------------------
f13 = by_pkg.get("c13-same-text-two-sites", [])
tooth("K13 identical rule text at two program points -> two distinct retained identities",
      len(f13) == 2
      and len({x["pattern"] for x in f13}) == 1
      and len({x["site_node_id"] for x in f13}) == 2
      and len({x["method_node_id"] for x in f13}) == 2
      and len({x["chain"]["replace_sites"][0]["node_id"] for x in f13}) == 2, str(f13))

# --- K14 ---------------------------------------------------------------------
f14a, f14b = one("c14a-historical-faulty"), one("c14b-historical-corrected")
hist = (HERE / "historical" / "differential_output.txt").read_text()
x_rows = [json.loads(l) for l in
          (HERE / "historical" / "xcheck_output.txt").read_text().strip().splitlines()]
x = {r["id"]: r for r in x_rows}
tooth("K14 historical faulty/corrected differential -> candidate / negative, with the "
      "published behavioural confirmation on both escape-run parities",
      f14a is not None and f14a["classification"] == CANDIDATE
      and f14a["boundary_rule"] == "SINGLE_CHAR_LOOKBEHIND"
      and f14b is not None and f14b["classification"] == NEGATIVE
      and f14b["boundary_rule"] == "PARITY_ESTABLISHED"
      # the faulty form mishandles an even-length run; the corrected form does not
      and x["historical_faulty"]["even_ok"] is False
      and x["historical_corrected"]["even_ok"] is True
      # and the corrected form preserves the odd-run behaviour too
      and x["historical_faulty"]["odd_ok"] is True
      and x["historical_corrected"]["odd_ok"] is True
      and "DIFFER: YES" in hist,
      f"{f14a and f14a['classification']} / {f14b and f14b['classification']}")

# --- discipline --------------------------------------------------------------
tooth("K15 reportable=false on every record",
      len(result["findings"]) > 0 and all(f["reportable"] is False for f in result["findings"]),
      "")

# The findings themselves must never carry impact/severity/exploitability language.
# The schema-level `note` is a DISCLAIMER and is allowed to name what it disclaims, so
# it is linted separately: it may say "makes no severity claim", but the per-finding
# records may not contain such vocabulary at all.
banned = ("vulnerab", "exploit", "attacker", "severity", "cvss", "payload", "malicious",
          "impact")
findings_blob = json.dumps(result["findings"]).lower()
hits = [b for b in banned if b in findings_blob]
# "vulnerab" is banned outright, disclaimer included.
whole_blob = json.dumps(result).lower()
if "vulnerab" in whole_blob and "vulnerab" not in hits:
    hits.append("vulnerab(schema)")
tooth("K16 no impact/severity/exploitability language in any finding record "
      "(the schema disclaimer is linted separately and may name what it disclaims)",
      not hits, str(hits))

timing_words = ("cron", "schedul", "timing", "admin", "deferred", "interval")
verdict_fields = []
for f in result["findings"]:
    for k in ("classification", "boundary_rule", "negative_reason", "abstention_reason"):
        if f.get(k):
            verdict_fields.append(str(f[k]).lower())
    verdict_fields.extend(str(x).lower() for x in f.get("chain_abstention_reason", []))
tooth("K17 execution timing is evidence only -- no verdict field is derived from it",
      all("execution_timing_evidence" in f for f in result["findings"])
      and not any(w in v for v in verdict_fields for w in timing_words),
      str([v for v in verdict_fields if any(w in v for w in timing_words)]))

passed = sum(1 for _, ok, _ in results if ok)
for name, ok, detail in results:
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "\n        <- " + detail[:400]))
print(f"ESCAPE_PARITY_BOUNDARY_R01={passed}/{len(results)}")
print("PROMOTION_GATE=" + ("PASS" if passed == len(results) else "FAIL"))
sys.exit(0 if passed == len(results) else 1)
