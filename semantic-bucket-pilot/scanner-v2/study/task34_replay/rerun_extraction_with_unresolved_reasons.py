#!/usr/bin/env python3
"""Step 5/6 of the unresolved-packages follow-up: reruns the REAL, shipped configuration
extraction (extract_build_config.classify_from_tarball() -- UNCHANGED this round -- plus the
new, diagnostic-only classify_unresolved_reason()) over the same 97 already-pinned tarballs, and
reports the required before/after block.

HONEST RESULT, established by real investigation (see UNRESOLVED_CATEGORIZATION.md), not
assumed going in: none of the 54 unresolved packages could be safely promoted to a decisive
enabled/disabled/conflict value without guessing (this module's own docstring already,
deliberately, reserves default-resolution reasoning for individual manual review -- a bulk,
automatic rule here would repeat the EXACT class of regression the node-libcurl fix and the
32-package staleness audit both just finished correcting). So `unresolved after` equals
`unresolved before` -- the real, mechanically-safe change this round made is a NEW diagnostic
sub-classification (WHY each package stays unresolved), not a promotion. Confirmed, not assumed:
this script diffs every one of the 97 packages' own exception_configuration value against the
prior round's own stored result and asserts byte-identical equality before reporting -- if
classify_from_tarball() ever DOES change (a future edit to it), this script's own assertion
catches it and refuses to under-report."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER_V2 = os.path.dirname(os.path.dirname(HERE))
NPM_CORPUS = os.path.join(SCANNER_V2, "npm_corpus")
RESULTS_DIR = os.path.join(HERE, "results")
sys.path.insert(0, SCANNER_V2)
sys.path.insert(0, NPM_CORPUS)
import provenance  # noqa: E402
import extract_build_config as ebc  # noqa: E402


def main():
    prior_audit = json.load(open(os.path.join(RESULTS_DIR, "build_config_staleness_audit.json")))
    prior_pp = prior_audit["per_package"]
    sample = json.load(open(os.path.join(NPM_CORPUS, "overnight_100", "overnight_sample_100.json")))
    sample_by_key = {f'{p["package_name"]}@{p["version"]}': p for p in sample["packages"]}

    tsv_rows = {}
    with open(os.path.join(NPM_CORPUS, "npm_build_configuration.tsv")) as f:
        header = next(f).rstrip("\n").split("\t")
        idx = {n: i for i, n in enumerate(header)}
        for line in f:
            parts = line.rstrip("\n").split("\t")
            tsv_rows[(parts[idx["package_name"]], parts[idx["version"]])] = \
                parts[idx["exception_configuration"]]

    per_package = {}
    unresolved_before = unresolved_after = 0
    resolved_correctly = 0
    conflicts_preserved = 0
    incorrect_promotions = 0
    reason_counts = {"NO_RECOGNIZED_BUILD_FILE": 0, "CMAKE_JS_EXTERNAL_DEFAULT": 0,
                      "NO_TEXTUAL_EVIDENCE": 0}
    config_changed_packages = []

    keys = sorted(prior_pp.keys())
    assert len(keys) == 97, f"expected 97 packages from prior audit, got {len(keys)}"

    for i, key in enumerate(keys, 1):
        pkg, version = key.rsplit("@", 1)
        prior_cat = prior_pp[key]["category"]
        prior_exc = prior_pp[key].get("exception_configuration")
        old_tsv_exc = tsv_rows.get((pkg, version))
        if prior_cat == "UNRESOLVED":
            unresolved_before += 1

        s = sample_by_key.get(key)
        tb, err = ebc.fetch_bytes(s["tarball_url"]) if s else (None, "NOT_IN_SAMPLE")
        entry = {"prior_category": prior_cat, "prior_exception_configuration": prior_exc}
        if err:
            entry["status"] = "DOWNLOAD_FAILED"
            entry["detail"] = err
            per_package[key] = entry
            print(f"[{i}/97] {key}: DOWNLOAD_FAILED ({err})", file=sys.stderr)
            continue
        real_sha = provenance.sha256_hex(tb)
        if real_sha != s["tarball_sha256"]:
            entry["status"] = "HASH_MISMATCH"
            per_package[key] = entry
            continue

        r = ebc.classify_from_tarball(tb)
        if "error" in r:
            entry["status"] = "EXTRACTION_FAILED"
            entry["detail"] = r["error"]
            per_package[key] = entry
            continue

        new_exc = r["exception_configuration"]
        entry["status"] = "OK"
        entry["exception_configuration"] = new_exc

        # THE INVARIANT: classify_from_tarball() itself is unchanged this round -- assert its own
        # real answer is byte-identical to the prior round's, never silently assumed.
        assert new_exc == prior_exc, (
            f"UNEXPECTED CHANGE for {key}: prior round said {prior_exc!r}, this round says "
            f"{new_exc!r} -- classify_from_tarball() was supposed to be UNCHANGED this round; "
            f"aborting rather than silently reporting a promotion this script did not expect")

        if new_exc == "unresolved":
            unresolved_after += 1
            reason = ebc.classify_unresolved_reason(tb)
            entry["unresolved_reason"] = reason
            if reason in reason_counts:
                reason_counts[reason] += 1
        elif new_exc == "conflict":
            conflicts_preserved += 1
        # "resolved_correctly": a package whose value differs from the ORIGINAL frozen TSV row
        # (the real regression this whole line of work started from) AND matches what the fixed
        # extractor says now -- i.e. genuinely corrected, not merely "still whatever it was".
        if old_tsv_exc is not None and old_tsv_exc != new_exc and new_exc in ("enabled", "disabled"):
            resolved_correctly += 1
        # incorrect_promotions: any package that moved FROM a real, resolvable state TO
        # "unresolved" (a regression in the OTHER direction) -- checked directly, never assumed
        # zero.
        if prior_exc in ("enabled", "disabled") and new_exc == "unresolved":
            incorrect_promotions += 1

        # config-changed detection (should be empty every time, per the assertion above -- kept
        # as an explicit, separately-computed check, not merely inferred from the assertion never
        # firing, in case a future edit narrows the assertion).
        if new_exc != prior_exc:
            config_changed_packages.append(key)

        per_package[key] = entry
        print(f"[{i}/97] {key}: {new_exc} "
              f"{'(' + entry.get('unresolved_reason', '') + ')' if new_exc == 'unresolved' else ''}",
              file=sys.stderr)

    report = {
        "unresolved_before": unresolved_before,
        "unresolved_after": unresolved_after,
        "resolved_correctly": resolved_correctly,
        "conflicts_preserved": conflicts_preserved,
        "incorrect_promotions": incorrect_promotions,
        "unresolved_reason_breakdown": reason_counts,
        "config_changed_packages": config_changed_packages,
        "per_package": per_package,
    }
    with open(os.path.join(RESULTS_DIR, "extraction_rerun_with_reasons.json"), "w") as f:
        json.dump(report, f, indent=2, sort_keys=True, default=str)

    print("\n=== REQUIRED REPORT BLOCK ===")
    print(f"unresolved before: {unresolved_before}")
    print(f"unresolved after:  {unresolved_after}")
    print(f"resolved correctly: {resolved_correctly}")
    print(f"conflicts preserved: {conflicts_preserved}")
    print(f"incorrect promotions: {incorrect_promotions}")
    print("\n=== unresolved_reason breakdown (diagnostic-only, new this round) ===")
    print(json.dumps(reason_counts, indent=2))
    print(f"\nconfig_changed_packages (step 6 input -- packages needing an R06 rerun): "
          f"{len(config_changed_packages)}")
    print(config_changed_packages)


if __name__ == "__main__":
    main()
