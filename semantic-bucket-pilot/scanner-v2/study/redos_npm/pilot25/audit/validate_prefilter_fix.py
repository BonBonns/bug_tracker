#!/usr/bin/env python3
"""PREFILTER-FIX-R01 regression validation: re-scores all 21 pilot packages with the CORRECTED
prefilter (fresh tarball fetch, same as the original run) and compares against the real Joern-
based `dangerous_sinks` ground truth already recorded in pilot25_results.json. Per direct
instruction point 4: "use these 21 packages strictly as the development/regression set."

Success criterion: the corrected prefilter's own n_dangerous count should now be 0 for every one
of the 14 real NO_COMPLEXITY_CANDIDATE packages (the real divergence this fix targets), and
should stay >= 1 for the 7 real packages that DO have a genuine dangerous sink (the 6
COMPLEXITY_ONLY + phplike) -- confirming the fix narrows false-positive selection without
introducing new false negatives on this same real, already-verified ground truth.
"""
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PILOT25_DIR = os.path.dirname(HERE)
sys.path.insert(0, PILOT25_DIR)
import prefilter_select_25 as pf  # noqa: E402

RESULTS_PATH = os.path.join(PILOT25_DIR, "pilot25_results.json")


def fetch_tarball(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "redos-pilot25-validate/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def score_package(tarball_url):
    data = fetch_tarball(tarball_url)
    has_export_any = False
    total_regex_literals = 0
    total_dangerous = 0
    for text in pf.iter_js_ts_members(data):
        he, nr, nd = pf.score_source_text(text)
        has_export_any = has_export_any or he
        total_regex_literals += nr
        total_dangerous += nd
    return total_dangerous, total_regex_literals


def main():
    d = json.load(open(RESULTS_PATH))
    sel = json.load(open(os.path.join(PILOT25_DIR, "pilot25_selection.json")))
    url_by_pkgver = {f"{s['package_name']}@{s['version']}": s["tarball_url"]
                      for s in sel["selected"]}

    rows = []
    for r in d["results"]:
        key = f"{r['package_name']}@{r['version']}"
        real_dangerous = r.get("producer_summary", {}).get("dangerous_sinks", 0)
        url = url_by_pkgver.get(key)
        try:
            new_score, new_literals = score_package(url)
        except Exception as e:
            rows.append({"package": key, "real_dangerous_sinks": real_dangerous,
                         "corrected_prefilter_score": None, "error": str(e)})
            continue
        rows.append({"package": key, "real_dangerous_sinks": real_dangerous,
                      "corrected_prefilter_score": new_score,
                      "corrected_regex_literals_seen": new_literals})
        print(f"{key}: real_dangerous_sinks={real_dangerous} "
              f"corrected_prefilter_score={new_score} (literals={new_literals})",
              file=sys.stderr)

    # success criteria
    n_correct_zero = sum(1 for r in rows if r["real_dangerous_sinks"] == 0
                          and r.get("corrected_prefilter_score") == 0)
    n_still_nonzero_had_zero = sum(1 for r in rows if r["real_dangerous_sinks"] == 0
                                    and (r.get("corrected_prefilter_score") or 0) > 0)
    n_real_positive_still_detected = sum(1 for r in rows if r["real_dangerous_sinks"] > 0
                                          and (r.get("corrected_prefilter_score") or 0) > 0)
    n_real_positive_now_missed = sum(1 for r in rows if r["real_dangerous_sinks"] > 0
                                      and (r.get("corrected_prefilter_score") or 0) == 0)

    out = {
        "n_packages": len(rows),
        "n_real_no_complexity_candidate": sum(1 for r in rows if r["real_dangerous_sinks"] == 0),
        "n_now_correctly_zero": n_correct_zero,
        "n_still_falsely_nonzero": n_still_nonzero_had_zero,
        "n_real_positives": sum(1 for r in rows if r["real_dangerous_sinks"] > 0),
        "n_real_positives_still_detected": n_real_positive_still_detected,
        "n_real_positives_now_missed_REGRESSION": n_real_positive_now_missed,
        "rows": rows,
    }
    out_path = os.path.join(HERE, "prefilter_fix_validation.json")
    json.dump(out, open(out_path, "w"), indent=2)
    print(json.dumps({k: v for k, v in out.items() if k != "rows"}, indent=2))


if __name__ == "__main__":
    main()
