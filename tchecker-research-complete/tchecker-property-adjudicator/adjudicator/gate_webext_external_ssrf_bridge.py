#!/usr/bin/env python3
"""Frozen live-run gate for JS-SSRF-SOURCE-R02."""
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIX = ROOT / "fixtures" / "webext_ssrf_bridge"
CONTROLLED = FIX / "external_controlled"
REAL = FIX / "real_no_sink" / "raw"
PRODUCER = ROOT / "producers" / "export_ssrf_integ.sc"
results = []


def tooth(name, ok, detail=""):
    results.append((name, bool(ok), detail))


def nonblank(path):
    if not path.is_file():
        raise FileNotFoundError(path)
    return [line.split("\t") for line in path.read_text().splitlines() if line.strip()]


raw = CONTROLLED / "raw"
sources = nonblank(raw / "source_facts.tsv")
relations = nonblank(raw / "propagation_relations.tsv")
outcomes = nonblank(raw / "property_outcome.tsv")
transforms = nonblank(raw / "transform_identity.tsv")
ev = json.loads((CONTROLLED / "evidence_final.json").read_text())

families = Counter(row[3] for row in sources)
tooth("E1 exactly three controlled candidates", len(sources) == 3, str(sources))
tooth("E2 external-message and tab-URL classes remain separated",
      families == {"WEBEXT_EXTERNAL_MESSAGE_INPUT": 2, "WEBEXT_TAB_URL_INPUT": 1}, str(families))
tooth("E3 direct and named external handlers both emit",
      {row[0] for row in sources if row[3] == "WEBEXT_EXTERNAL_MESSAGE_INPUT"}
      == {"30064771082", "30064771100"}, str(sources))
tooth("E4 tab-URL R01 finding remains unchanged",
      any(row[:4] == ["30064771110", "3", "30064771111", "WEBEXT_TAB_URL_INPUT"] for row in sources), str(sources))
tooth("E5 only concrete message.url/tab.url reads start paths",
      Counter(row[5] for row in relations) == {"message.url": 2, "tab.url": 1}, str(relations))
tooth("E6 all three direct paths are property ESTABLISHED",
      len(outcomes) == 3 and all(row[2:] == ["ESTABLISHED", "-1", "-1"] for row in outcomes), str(outcomes))
tooth("E7 direct paths have no invented transform", transforms == [], str(transforms))
tooth("E8 external-message adjudication closes without LLM hinting",
      ev.get("origin", {}).get("origin_family") == "WEBEXT_EXTERNAL_MESSAGE_INPUT"
      and ev.get("property_outcome") == "ESTABLISHED"
      and ev.get("deterministic_coverage") == "SEMANTICALLY_CLOSED"
      and ev.get("semantically_unresolved__SEMANTICALLY_UNRESOLVED") == [], str(ev))

real = {name: nonblank(REAL / name) for name in (
    "source_facts.tsv", "propagation_relations.tsv", "property_outcome.tsv", "transform_identity.tsv")}
tooth("E9 real Mozilla add-on remains no-sink", all(not rows for rows in real.values()), str(real))

producer = PRODUCER.read_text()
tooth("E10 producer requires exact REF identity and one-hop base field read",
      "i.refOut.l.exists(_.id == p.id)" in producer
      and "a.argumentIndex == 1 && a.id == i.id" in producer
      and "WEBEXT_EXTERNAL_MESSAGE_INPUT" in producer, "producer identity contract missing")

passed = sum(ok for _, ok, _ in results)
for name, ok, detail in results:
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "   <- " + detail))
print(f"WEBEXT_EXTERNAL_SSRF_BRIDGE={passed}/{len(results)}")
print("PROMOTION_GATE=" + ("PASS" if passed == len(results) else "FAIL"))
sys.exit(0 if passed == len(results) else 1)
