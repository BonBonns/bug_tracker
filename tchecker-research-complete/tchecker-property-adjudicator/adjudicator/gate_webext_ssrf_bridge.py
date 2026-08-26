#!/usr/bin/env python3
"""Frozen integration gate for JS-SSRF-SOURCE-R01.

The fixture is a snapshot of two live Joern runs:
  * a controlled WebExtension corpus containing four fetch calls, where only the
    use-scoped tabs.onUpdated tab.url source reaches one fetch sink; and
  * a real Mozilla add-on whose bridged tab URL source reaches no network sink.

The gate deliberately does not execute Joern.  The strict source-adapter gate
tests input rejection; this gate preserves the class-specific producer and
adjudicator contract after the expensive live runs.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIX = ROOT / "fixtures" / "webext_ssrf_bridge"
CONTROLLED = FIX / "controlled"
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

tooth("W1 exactly one controlled source-to-sink candidate", len(sources) == 1, str(sources))
tooth("W2 source family remains WEBEXT_TAB_URL_INPUT",
      len(sources) == 1 and sources[0][3] == "WEBEXT_TAB_URL_INPUT", str(sources))
tooth("W3 concrete source is the individual tab.url STATE_READ",
      len(relations) == 1 and relations[0][3:6] == ["30064771111", "3", "tab.url"], str(relations))
tooth("W4 direct tab.url -> fetch property is deterministically ESTABLISHED",
      outcomes == [["30064771110", "30064771111", "ESTABLISHED", "-1", "-1"]], str(outcomes))
tooth("W5 direct path has no invented transform", transforms == [], str(transforms))
tooth("W6 adjudicator closes without semantic hinting",
      ev.get("deterministic_coverage") == "SEMANTICALLY_CLOSED"
      and ev.get("disposition") == "RESOLVED_CANDIDATE_BY_PROPERTY_ANALYSIS"
      and ev.get("semantically_unresolved__SEMANTICALLY_UNRESOLVED") == [], str(ev))
tooth("W7 adjudicator preserves SSRF class and property",
      ev.get("sink", {}).get("class") == "ssrf"
      and ev.get("security_property") == "ATTACKER_CONTROL_OF_REQUEST_HOST"
      and ev.get("origin", {}).get("origin_family") == "WEBEXT_TAB_URL_INPUT", str(ev))

real_rows = {name: nonblank(REAL / name) for name in (
    "source_facts.tsv", "propagation_relations.tsv", "property_outcome.tsv", "transform_identity.tsv")}
tooth("W8 real Mozilla add-on remains a no-sink result",
      all(not rows for rows in real_rows.values()), str(real_rows))

producer = PRODUCER.read_text()
tooth("W9 producer bridge is optional and does not replace legacy HTTP sources",
      'browserSourceTsv: String = ""' in producer
      and 'HTTP_HOST_INPUT' in producer
      and 'WEBEXT_TAB_URL_INPUT' in producer, "producer contract missing")

passed = sum(ok for _, ok, _ in results)
for name, ok, detail in results:
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "   <- " + detail))
print(f"WEBEXT_SSRF_BRIDGE={passed}/{len(results)}")
print("PROMOTION_GATE=" + ("PASS" if passed == len(results) else "FAIL"))
sys.exit(0 if passed == len(results) else 1)
