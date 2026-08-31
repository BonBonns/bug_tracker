#!/usr/bin/env python3
"""Computes every total for the NPM JS/TS<->C/C++ project scope -- properties.csv rows
with npm_applicable == TRUE only -- programmatically from data/*.csv, plus
data/npm_readiness.csv (the READY_TO_WIRE_WITH_CURRENT_FACTS / NEEDS_SPECIALIZED_EXPORT /
NEEDS_SOUNDNESS_WORK / UNVERIFIED / ALREADY_EXECUTED breakdown requested for this scope
only). PHP/WordPress properties are a separate project and are excluded from every total
here by construction (npm_applicable == FALSE), not by a second, independent judgment call.

Read-only: aggregates this study's own CSV tables, does not invoke any scanner/contract/
exporter/pipeline file.

Run: python3 compute_npm_totals.py
"""
import csv
import sys
from collections import defaultdict
from pathlib import Path

DATA = Path(__file__).parent / "data"


def load(name):
    with open(DATA / name, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main():
    properties = load("properties.csv")
    implementations = load("implementations.csv")
    pipeline_invocations = load("pipeline_invocations.csv")
    historical_runs = load("historical_runs.csv")
    npm_readiness = load("npm_readiness.csv")

    npm_props = [p for p in properties if p["npm_applicable"] == "TRUE"]
    npm_ids = {p["property_id"] for p in npm_props}
    all_ids = {p["property_id"] for p in properties}

    # --- referential integrity ---------------------------------------------
    errors = []
    readiness_ids = {r["property_id"] for r in npm_readiness}
    if readiness_ids != npm_ids:
        missing = npm_ids - readiness_ids
        extra = readiness_ids - npm_ids
        if missing:
            errors.append(f"npm_readiness.csv missing rows for npm-applicable properties: {sorted(missing)}")
        if extra:
            errors.append(f"npm_readiness.csv has rows for non-npm-applicable properties: {sorted(extra)}")
    VALID_STATUSES = {"READY_TO_WIRE_WITH_CURRENT_FACTS", "NEEDS_SPECIALIZED_EXPORT",
                       "NEEDS_SOUNDNESS_WORK", "UNVERIFIED", "ALREADY_EXECUTED"}
    for r in npm_readiness:
        if r["readiness_status"] not in VALID_STATUSES:
            errors.append(f"npm_readiness.csv: invalid readiness_status {r['readiness_status']!r} for {r['property_id']}")
    if errors:
        print("REFERENTIAL INTEGRITY ERRORS -- fix data before trusting any total below:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)

    # --- promotability rollup, restricted to npm scope ------------------------
    status_by_prop = defaultdict(set)
    for r in implementations:
        if r["property_id"] in npm_ids:
            status_by_prop[r["property_id"]].add(r["status"])

    sound, unverified, unsound = [], [], []
    for pid in sorted(npm_ids):
        statuses = status_by_prop.get(pid, set())
        if "SOUND" in statuses:
            sound.append(pid)
        elif statuses <= {"UNVERIFIED", "UNSOUND"} and "UNVERIFIED" in statuses:
            unverified.append(pid)
        else:
            unsound.append(pid)

    # --- stopped pipeline, restricted to npm scope -----------------------------
    pipeline_props = sorted({r["property_id"] for r in pipeline_invocations if r["property_id"] in npm_ids})

    # --- historical evidence, restricted to npm scope AND real npm native-addon target
    hist_npm_native = sorted({r["property_id"] for r in historical_runs
                               if r["property_id"] in npm_ids and r["status"] == "COMPLETE"
                               and r["ecosystem_scope"] == "NPM_NATIVE_ADDON_CORPUS"})
    hist_npm_general = sorted({r["property_id"] for r in historical_runs
                                if r["property_id"] in npm_ids and r["status"] == "COMPLETE"
                                and r["ecosystem_scope"] == "NPM_PACKAGE_GENERAL"} - set(hist_npm_native))
    hist_other_ecosystem = sorted({r["property_id"] for r in historical_runs
                                    if r["property_id"] in npm_ids and r["status"] == "COMPLETE"
                                    and r["ecosystem_scope"] == "OTHER_ECOSYSTEM"}
                                   - set(hist_npm_native) - set(hist_npm_general))

    # --- readiness breakdown ---------------------------------------------------
    readiness_counts = defaultdict(list)
    for r in npm_readiness:
        readiness_counts[r["readiness_status"]].append(r["property_id"])

    print("=" * 78)
    print("NPM JS/TS<->C/C++ PROJECT SCOPE -- COMPUTED TOTALS")
    print("(properties.csv WHERE npm_applicable == TRUE; PHP/WordPress excluded by")
    print(" construction, not by a second judgment call)")
    print("=" * 78)

    print(f"\nTotal repository-wide implemented properties: {len(all_ids)}")
    print(f"npm-applicable properties (this project's scope): {len(npm_ids)}")
    print(f"Excluded as out-of-project (PHP/WordPress, separate appendix): {len(all_ids) - len(npm_ids)}")

    print(f"\nPromotability, within npm scope only:")
    print(f"  SOUND:      {len(sound)}  -- {', '.join(sound)}")
    print(f"  UNVERIFIED: {len(unverified)}  -- {', '.join(unverified)}")
    print(f"  UNSOUND:    {len(unsound)}  -- {', '.join(unsound)}")
    assert len(sound) + len(unverified) + len(unsound) == len(npm_ids)

    print(f"\nExecuted by the stopped 494-package pipeline: {len(pipeline_props)} of {len(npm_ids)}")
    print(f"  Properties: {', '.join(pipeline_props)}")
    print(f"  NOT executed: {len(npm_ids) - len(pipeline_props)}")

    print(f"\nHistorical evidence, npm scope, by ecosystem_scope:")
    print(f"  NPM_NATIVE_ADDON_CORPUS (same target class as the 494-package corpus): {len(hist_npm_native)}")
    print(f"    Properties: {', '.join(hist_npm_native) if hist_npm_native else '(none)'}")
    print(f"  NPM_PACKAGE_GENERAL (npm-published, not confirmed native-addon-specific): {len(hist_npm_general)}")
    print(f"    Properties: {', '.join(hist_npm_general) if hist_npm_general else '(none)'}")
    print(f"  OTHER_ECOSYSTEM (real validation, but off the npm native-addon corpus -- wolfSSL/")
    print(f"  Tor/Mozilla-C/WordPress/RocketChat/Mozilla-JS-apps -- NOT counted as npm-scoped evidence): {len(hist_other_ecosystem)}")
    print(f"    Properties: {', '.join(hist_other_ecosystem) if hist_other_ecosystem else '(none)'}")

    print(f"\nReadiness breakdown (npm scope, {len(npm_readiness)} rows):")
    for status in ["ALREADY_EXECUTED", "READY_TO_WIRE_WITH_CURRENT_FACTS", "NEEDS_SPECIALIZED_EXPORT",
                    "NEEDS_SOUNDNESS_WORK", "UNVERIFIED"]:
        props = readiness_counts.get(status, [])
        print(f"  {status}: {len(props)}")
        print(f"    {', '.join(props) if props else '(none)'}")
    total_readiness = sum(len(v) for v in readiness_counts.values())
    assert total_readiness == len(npm_ids), f"readiness rows ({total_readiness}) != npm-applicable properties ({len(npm_ids)})"

    print("\n" + "=" * 78)
    print("CENTRAL PROJECT CONCLUSION:")
    print(f"  The stopped npm pipeline evaluated {len(pipeline_props)} of {len(npm_ids)} npm-applicable")
    print("  implemented properties -- not 1 of 26 repository-wide properties. That is the")
    print("  number relevant to whether the npm native-addon dataset was comprehensively")
    print("  scanned. The PHP/WordPress family is a separate project and does not affect")
    print("  this total in either direction.")
    print("=" * 78)


if __name__ == "__main__":
    main()
