#!/usr/bin/env python3
"""Computes every total in ANALYZER_CLASS_INVENTORY.md programmatically from the
normalized tables in data/*.csv, instead of asserting numbers by hand.

This script reads and aggregates the inventory's own study data (five CSV tables
describing already-existing, already-documented scanner/gate/study artifacts). It
does not modify, run, or invoke any scanner, contract, exporter, or pipeline file --
consistent with the standing "read-only" instruction for this whole inventory task.

Run: python3 compute_totals.py
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
    infrastructure = load("infrastructure.csv")
    pipeline_invocations = load("pipeline_invocations.csv")
    historical_runs = load("historical_runs.csv")

    prop_ids = {p["property_id"] for p in properties}

    # --- referential integrity checks -----------------------------------------
    errors = []
    for row in implementations:
        if row["property_id"] not in prop_ids:
            errors.append(f"implementations.csv: unknown property_id {row['property_id']!r} (impl_id={row['impl_id']})")
    for row in pipeline_invocations:
        if row["property_id"] not in prop_ids:
            errors.append(f"pipeline_invocations.csv: unknown property_id {row['property_id']!r}")
    for row in historical_runs:
        if row["property_id"] not in prop_ids:
            errors.append(f"historical_runs.csv: unknown property_id {row['property_id']!r}")
    for row in infrastructure:
        for pid in filter(None, row["feeds_property_ids"].split(";")):
            if pid not in prop_ids:
                errors.append(f"infrastructure.csv: unknown feeds_property_id {pid!r} (infra_id={row['infra_id']})")
    if errors:
        print("REFERENTIAL INTEGRITY ERRORS -- fix data before trusting any total below:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)

    # --- 1. implemented properties ---------------------------------------------
    implemented_ids = {r["property_id"] for r in implementations}
    n_implemented = len(prop_ids)
    n_with_impl = len(implemented_ids)

    # --- 2. promotable properties (roll up implementation status per property) -
    status_by_prop = defaultdict(set)
    for r in implementations:
        status_by_prop[r["property_id"]].add(r["status"])

    promotable, unverified, not_promotable = [], [], []
    for pid in sorted(prop_ids):
        statuses = status_by_prop.get(pid, set())
        if "SOUND" in statuses:
            promotable.append(pid)
        elif statuses and statuses <= {"UNSOUND"}:
            not_promotable.append(pid)
        elif statuses <= {"UNVERIFIED", "UNSOUND"} and "UNVERIFIED" in statuses:
            unverified.append(pid)
        elif not statuses:
            not_promotable.append(pid)  # implemented-property list should be empty here; defensive only
        else:
            not_promotable.append(pid)

    # --- 3. npm-applicable properties -------------------------------------------
    npm_applicable = [p["property_id"] for p in properties if p["npm_applicable"] == "TRUE"]

    # --- 4. implementation files --------------------------------------------------
    n_impl_rows = len(implementations)
    distinct_files = {r["file_path"] for r in implementations}
    n_distinct_files = len(distinct_files)

    # --- 5. infrastructure ----------------------------------------------------
    n_infra = len(infrastructure)

    # --- 6. executed by the stopped 494-package pipeline ------------------------
    pipeline_props = sorted({r["property_id"] for r in pipeline_invocations})

    # --- 7. executed by any OTHER historical corpus run (COMPLETE only) --------
    hist_complete = sorted({r["property_id"] for r in historical_runs if r["status"] == "COMPLETE"})
    hist_incomplete = sorted({r["property_id"] for r in historical_runs if r["status"] != "COMPLETE"} - set(hist_complete))

    # =============================================================================
    print("=" * 78)
    print("ANALYZER CLASS INVENTORY -- COMPUTED TOTALS (from data/*.csv, not asserted)")
    print("=" * 78)
    print(f"\n1. Implemented properties (rows in properties.csv):            {n_implemented}")
    print(f"   (of which have >=1 implementation row in implementations.csv: {n_with_impl})")
    if n_implemented != n_with_impl:
        print("   *** WARNING: some properties have zero implementations -- investigate. ***")

    print(f"\n2. Promotable properties (>=1 SOUND implementation):            {len(promotable)}")
    print(f"   Properties: {', '.join(promotable)}")
    print(f"\n   UNVERIFIED (no SOUND impl, none explicitly UNSOUND either):   {len(unverified)}")
    print(f"   Properties: {', '.join(unverified)}")
    print(f"\n   NOT promotable (every implementation UNSOUND):                {len(not_promotable)}")
    print(f"   Properties: {', '.join(not_promotable)}")

    print(f"\n3. npm-applicable properties:                                   {len(npm_applicable)} of {n_implemented}")
    non_npm = sorted(prop_ids - set(npm_applicable))
    print(f"   Excluded (not npm-applicable): {', '.join(non_npm)}")

    print(f"\n4. Implementation rows (property x file mappings):              {n_impl_rows}")
    print(f"   Distinct implementation files:                                {n_distinct_files}")
    shared = {f: [r['property_id'] for r in implementations if r['file_path'] == f]
              for f in distinct_files}
    shared = {f: props for f, props in shared.items() if len(set(props)) > 1}
    if shared:
        print("   Files shared across multiple properties:")
        for f, props in shared.items():
            print(f"     - {f}: {', '.join(sorted(set(props)))}")

    print(f"\n5. Infrastructure components (not counted as properties):       {n_infra}")
    print(f"   {', '.join(r['infra_id'] for r in infrastructure)}")

    print(f"\n6. Properties executed by the stopped 494-package pipeline:     {len(pipeline_props)}")
    print(f"   Properties: {', '.join(pipeline_props)}")

    print(f"\n7. Properties executed by any OTHER historical corpus run:      {len(hist_complete)}")
    print(f"   Properties: {', '.join(hist_complete)}")
    if hist_incomplete:
        print(f"   Attempted but INCOMPLETE/ABANDONED (not counted above):        {len(hist_incomplete)}")
        print(f"   Properties: {', '.join(hist_incomplete)}")

    overlap = sorted(set(pipeline_props) & set(hist_complete))
    print(f"\n   Overlap between #6 and #7 (evaluated by both):                 {len(overlap)}")
    print(f"   Properties: {', '.join(overlap) if overlap else '(none)'}")

    never_run = sorted(prop_ids - set(pipeline_props) - set(hist_complete) - set(hist_incomplete))
    print(f"\n   Properties with NO corpus-scale run evidence found (any kind): {len(never_run)}")
    print(f"   Properties: {', '.join(never_run)}")

    print("\n" + "=" * 78)
    print("STRONGEST CONCLUSION (re-derived, not re-asserted):")
    print(f"  The stopped 494-package pipeline evaluated exactly {len(pipeline_props)} of {n_implemented}")
    print(f"  implemented properties. {len(hist_complete) - len(overlap)} other properties have real,")
    print("  completed, non-fixture corpus-scale run evidence from OTHER historical runs")
    print(f"  documented elsewhere in this repository -- {n_implemented - len(pipeline_props) - (len(hist_complete) - len(overlap))} properties have no corpus-scale run evidence at all.")
    print("=" * 78)


if __name__ == "__main__":
    main()
