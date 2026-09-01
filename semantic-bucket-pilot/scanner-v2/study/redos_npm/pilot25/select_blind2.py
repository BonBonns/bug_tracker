#!/usr/bin/env python3
"""REDOS-PILOT-BLIND2-R01: a second, genuinely blind pre-registered selection, run with the
CORRECTED prefilter (prefilter_select_25.py's R02 state -- file-exclusion parity + string-aware
comment stripping, frozen and regression-validated in audit/PREFILTER_FIX.md) over the SAME frozen
494-package corpus, per direct instruction task 6: "Select a new blind package set using a newly
frozen rule before viewing outcomes."

Reuses pilot25's own frozen scoring/selection logic verbatim (load_eligible, iter_js_ts_members,
score_source_text, classify_dangerous, the same descending-score/ascending-row-index selection
rule, the same N_SELECT=25 ceiling) -- this is NOT a new rule, it is the same rule with the R02
correction applied, run over a corpus with the already-used 21 packages EXCLUDED by package_name
(not just package@version) so this really is held-out data: reusing even a different version of
an already-inspected package would not be blind, since its source is what the fix was tuned
against.

Written and committed BEFORE any package in it is scanned by the real Joern pipeline -- same
discipline as pilot25_selection.json itself.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import prefilter_select_25 as pf  # noqa: E402

PILOT25_SELECTION = os.path.join(HERE, "pilot25_selection.json")
OUT_PATH = os.path.join(HERE, "pilot_blind2_selection.json")


def excluded_package_names():
    sel = json.load(open(PILOT25_SELECTION))
    return set(s["package_name"] for s in sel["selected"])


def main():
    excluded = excluded_package_names()
    print(f"excluding {len(excluded)} package names already used as the development/regression "
          f"set (pilot25): {sorted(excluded)}", file=sys.stderr)

    rows = pf.load_eligible()
    rows = [r for r in rows if r["package_name"] not in excluded]
    print(f"eligible corpus rows after exclusion (frozen order): {len(rows)} "
          f"(of {len(rows) + sum(1 for _ in excluded)} total-ish; exact count logged above)",
          file=sys.stderr)

    results = []
    for i, r in enumerate(rows):
        try:
            import urllib.request
            req = urllib.request.Request(r["tarball_url"],
                                          headers={"User-Agent": "redos-pilot-blind2/1.0"})
            with urllib.request.urlopen(req, timeout=pf.PER_PACKAGE_TIMEOUT) as resp:
                data = resp.read()
        except Exception as e:
            print(f"[{i+1}/{len(rows)}] {r['package_name']}@{r['version']}: FETCH_FAILED ({e})",
                  file=sys.stderr)
            continue
        has_export_any = False
        total_regex_literals = 0
        total_dangerous = 0
        try:
            for text in pf.iter_js_ts_members(data):
                he, nr, nd = pf.score_source_text(text)
                has_export_any = has_export_any or he
                total_regex_literals += nr
                total_dangerous += nd
        except Exception as e:
            print(f"[{i+1}/{len(rows)}] {r['package_name']}@{r['version']}: EXTRACT_FAILED ({e})",
                  file=sys.stderr)
            continue
        qualifies = has_export_any and total_regex_literals > 0 and total_dangerous > 0
        print(f"[{i+1}/{len(rows)}] {r['package_name']}@{r['version']}: "
              f"export={has_export_any} regex_literals={total_regex_literals} "
              f"dangerous={total_dangerous} qualifies={qualifies}", file=sys.stderr)
        if qualifies:
            results.append({
                "row_index": r["row_index"],
                "package_name": r["package_name"],
                "version": r["version"],
                "tarball_url": r["tarball_url"],
                "supported_sink_count": total_dangerous,
                "regex_literals_seen": total_regex_literals,
            })

    results.sort(key=lambda x: (-x["supported_sink_count"], x["row_index"]))
    selected = results[:pf.N_SELECT]

    out = {
        "schema": "redos-pilot-blind2-selection/1.0",
        "supersedes_prefilter_note": "runs prefilter_select_25.py's R02 (file-exclusion parity + "
                                      "string-aware comment stripping) implementation verbatim; "
                                      "not a new scoring rule, the corrected version of the same "
                                      "one",
        "corpus_source": "npm_corpus/eligible_packages.tsv (frozen, 494-package corpus, ANALYZED "
                          "rows only)",
        "excluded_as_development_set": sorted(excluded),
        "n_excluded_package_names": len(excluded),
        "n_eligible_rows_scanned": len(rows),
        "n_qualifying_packages": len(results),
        "n_selected": len(selected),
        "selection_rule": "descending supported_sink_count (corrected R02 prefilter proxy for the "
                           "frozen Stage 2 DANGEROUS shape), ties by ascending row_index in "
                           "eligible_packages.tsv -- identical rule to pilot25_selection.json, "
                           "corrected implementation, disjoint package set",
        "selected": selected,
    }
    with open(OUT_PATH, "w") as f:
        json.dump(out, f, indent=2)
    print(json.dumps({k: v for k, v in out.items() if k != "selected"}, indent=2))


if __name__ == "__main__":
    main()
