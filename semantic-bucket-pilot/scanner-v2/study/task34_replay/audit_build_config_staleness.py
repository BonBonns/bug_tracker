#!/usr/bin/env python3
"""Cheap configuration-only audit, per direct instruction: node-libcurl's own
npm_build_configuration.tsv row was found stale (fix_libcurl_build_config_regression.py), so
Resource Guard results for the OTHER 96 successfully-replayed packages cannot yet be assumed
current either -- this was explicitly disclosed, not audited, in APPLICABILITY_GATE_RESULTS.md's
own CORRECTIONS section. This script closes that open risk.

Steps (exactly as instructed):
  1. Re-run the fixed build-configuration extractor (extract_build_config.py -- both real
     regression fixes present: gyp `!`-list-removal polarity, node_addon_api_except gyp-target
     evidence) on all 97 already-pinned tarballs (the SAME tarball_url/tarball_sha256 identity
     already recorded in npm_corpus/overnight_100/overnight_sample_100.json -- no new packages,
     no new URLs, continuing the same narrow download exception task #34 already established).
  2. Compare every new result against its frozen npm_build_configuration.tsv row.
  3. Record unchanged / changed / conflict / unresolved counts.
  4. Rerun R06 ONLY for packages whose authoritative configuration changed (never R05 -- R05
     predates R06's own applicability gate and never contributes to reportability at all, so
     re-deriving it here would not change one bit of the reportability funnel).
  5. Regenerate the Resource Guard section / reportability funnel (separate follow-up script,
     run after this one, only if this audit finds any real CHANGED package).
  6. No Joern rebuild anywhere -- R06 reruns (step 4) use each changed package's preserved
     cpp_raw from evidence_bundles_100, exactly like fix_libcurl_build_config_regression.py and
     replay_100_bundles.py's own original R06 rerun already did.

"Target-aware": for every binding.gyp found, this script ALSO runs
extract_build_config.classify_target_aware() (never wired into the corpus-wide TSV output
schema itself -- its own module docstring says so) purely as a DIAGNOSTIC cross-check: does the
real per-target breakdown ever disagree internally in a way the flat, package-wide verdict
papers over (i.e., would classify_from_tarball() report "enabled"/"disabled" cleanly while two
real targets actually disagree)? Recorded as `target_level_internal_disagreement` per package;
never itself changes the CHANGED/UNCHANGED/CONFLICT/UNRESOLVED bucket, since
npm_build_configuration.tsv -- the thing being audited against -- is itself package-wide only.

Never touches disk with tarball bytes: classify_from_tarball()/classify_target_aware() operate
on in-memory bytes only, via extract_build_config.fetch_bytes(); nothing is extracted to a
directory, so there is nothing to delete afterward (a stronger version of the "delete extracted
source immediately" discipline task #34's own narrow exception required -- here, extraction to
disk never happens at all)."""
import io
import json
import os
import re
import subprocess
import sys
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER_V2 = os.path.dirname(os.path.dirname(HERE))
RESULTS_DIR = os.path.join(HERE, "results")
NPM_CORPUS = os.path.join(SCANNER_V2, "npm_corpus")
TSV_PATH = os.path.join(NPM_CORPUS, "npm_build_configuration.tsv")
SAMPLE_PATH = os.path.join(NPM_CORPUS, "overnight_100", "overnight_sample_100.json")
BUNDLE_DIR = os.path.join(NPM_CORPUS, "overnight_100", "evidence_bundles_100")

sys.path.insert(0, SCANNER_V2)
sys.path.insert(0, NPM_CORPUS)
import provenance  # noqa: E402
import applicability_gate as ag  # noqa: E402
import adjudication_registry as ar  # noqa: E402
import staged_enablement as se  # noqa: E402
import vendored_attribution as va  # noqa: E402
import six_property_aggregator as agg  # noqa: E402
import extract_build_config as ebc  # noqa: E402


def load_replayed_identities():
    idents = []
    with open(os.path.join(RESULTS_DIR, "replay_records_v4.jsonl")) as f:
        for line in f:
            d = json.loads(line)
            if d.get("outcome") == "REPLAYED":
                idents.append((d["package_name"], d["version"]))
    return idents


def load_tsv_rows():
    rows = {}
    with open(TSV_PATH) as f:
        header = next(f).rstrip("\n").split("\t")
        idx = {n: i for i, n in enumerate(header)}
        for line in f:
            parts = line.rstrip("\n").split("\t")
            key = (parts[idx["package_name"]], parts[idx["version"]])
            rows[key] = {"exception_configuration": parts[idx["exception_configuration"]],
                         "line_idx": None}
    return rows, header


def load_sample_by_key():
    with open(SAMPLE_PATH) as f:
        sample = json.load(f)
    return {(p["package_name"], p["version"]): p for p in sample["packages"]}


def find_binding_gyp(tarball_bytes):
    """Returns real binding.gyp CONTENT bytes if the tarball has exactly one at any depth, else
    None -- classify_target_aware() is only meaningful for a real, unambiguous binding.gyp;
    never guessed when a package layout is unusual."""
    try:
        tf = tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz")
    except Exception:
        return None
    candidates = [m for m in tf.getmembers()
                  if m.isfile() and m.name.lower().endswith("binding.gyp")]
    if len(candidates) != 1:
        tf.close()
        return None
    f = tf.extractfile(candidates[0])
    content = f.read() if f else None
    tf.close()
    return content


def classify_one(pkg, version, tarball_url, expected_sha256):
    tb, err = ebc.fetch_bytes(tarball_url)
    if err:
        return {"status": "DOWNLOAD_FAILED", "detail": err}
    real_sha = provenance.sha256_hex(tb) if hasattr(provenance, "sha256_hex") else None
    if real_sha is None:
        import hashlib
        real_sha = hashlib.sha256(tb).hexdigest()
    if real_sha != expected_sha256:
        return {"status": "HASH_MISMATCH",
                "detail": f"expected {expected_sha256} got {real_sha}"}
    r = ebc.classify_from_tarball(tb)
    if "error" in r:
        return {"status": "EXTRACTION_FAILED", "detail": r["error"]}

    target_disagreement = None
    gyp_content = find_binding_gyp(tb)
    if gyp_content is not None:
        per_target = ebc.classify_target_aware(gyp_content)
        if per_target:
            configs = {t["exception_configuration"] for t in per_target}
            # a real internal disagreement: more than one distinct real per-target verdict,
            # while the package-wide flat verdict reports something single/clean (never flags
            # a package-wide "conflict" as a "disagreement" -- that already IS disagreement,
            # visible in the TSV comparison itself).
            if len(configs) > 1 and r["exception_configuration"] != "conflict":
                target_disagreement = sorted(configs)

    return {"status": "OK", "exception_configuration": r["exception_configuration"],
            "disable_evidence": r["disable_evidence"], "enable_evidence": r["enable_evidence"],
            "config_file_families": r["config_file_families"],
            "target_level_internal_disagreement": target_disagreement}


def categorize(old_exc, new_result):
    if new_result["status"] != "OK":
        return "UNRESOLVED"
    new_exc = new_result["exception_configuration"]
    if new_exc == "conflict":
        return "CONFLICT"
    if new_exc == "unresolved":
        return "UNRESOLVED"
    if new_exc == old_exc:
        return "UNCHANGED"
    return "CHANGED"


def bundle_filename(pkg_name, version):
    # SAME convention as replay_100_bundles.py's own bundle_filename() -- scoped package names
    # (e.g. "@2060.io/ffi-napi") contain a real "/" that is not valid inside a bundle's own
    # flat filename, so it is replaced with "__", exactly as the bundles were originally written.
    return f"{pkg_name.replace('/', '__')}@{version}.tar.gz"


def rerun_r06(pkg, version, corrected_build_config):
    bundle_path = os.path.join(BUNDLE_DIR, bundle_filename(pkg, version))
    if not os.path.isfile(bundle_path):
        raise RuntimeError(f"bundle missing for changed package: {bundle_path}")
    import tempfile
    work_dir = tempfile.mkdtemp(prefix="build_config_audit_r06_")
    with tarfile.open(bundle_path, "r:gz") as tf:
        tf.extractall(work_dir)
    cpp_raw_dir = os.path.join(work_dir, "cpp_raw")
    bc_path = os.path.join(work_dir, "build_config_audited.json")
    with open(bc_path, "w") as f:
        json.dump(corrected_build_config, f)
    out_path = os.path.join(work_dir, "r06_out_audited.json")
    rc = subprocess.run(
        [sys.executable, os.path.join(SCANNER_V2, "resource_guard_verdict_r06.py"),
         cpp_raw_dir, out_path, "--real", "--build-config", bc_path],
        capture_output=True, text=True, timeout=300)
    if rc.returncode != 0:
        raise RuntimeError(f"R06 rerun failed for {pkg}@{version}: {rc.stderr[-2000:]}")
    return json.load(open(out_path)).get("findings", [])


CHECKPOINT_PATH_NAME = "build_config_staleness_audit.json"


def main():
    idents = load_replayed_identities()
    assert len(idents) == 97, f"expected 97 replayed identities, got {len(idents)}"
    tsv_rows, _ = load_tsv_rows()
    sample_by_key = load_sample_by_key()

    checkpoint_path = os.path.join(RESULTS_DIR, CHECKPOINT_PATH_NAME)
    per_package = {}
    counts = {"UNCHANGED": 0, "CHANGED": 0, "CONFLICT": 0, "UNRESOLVED": 0}

    resumed = False
    if os.path.isfile(checkpoint_path):
        prior = json.load(open(checkpoint_path))
        prior_pp = prior.get("per_package") or {}
        expected_keys = {f"{p}@{v}" for p, v in idents}
        if set(prior_pp) == expected_keys and prior.get("audited_count") == len(idents):
            print("RESUMING from existing classification checkpoint -- skipping the network "
                  "re-download/re-classification phase (already complete and covers all 97 "
                  "identities).", file=sys.stderr)
            per_package = prior_pp
            for v in per_package.values():
                counts[v["category"]] += 1
            resumed = True

    if not resumed:
        for i, key in enumerate(idents, 1):
            pkg, version = key
            old_exc = tsv_rows.get(key, {}).get("exception_configuration")
            sample = sample_by_key.get(key)
            if sample is None or old_exc is None:
                per_package[f"{pkg}@{version}"] = {"category": "UNRESOLVED",
                                                     "detail": "not found in TSV/sample manifest"}
                counts["UNRESOLVED"] += 1
                continue
            result = classify_one(pkg, version, sample["tarball_url"], sample["tarball_sha256"])
            cat = categorize(old_exc, result)
            counts[cat] += 1
            entry = {"category": cat, "old_exception_configuration": old_exc, **result}
            per_package[f"{pkg}@{version}"] = entry
            print(f"[{i}/97] {pkg}@{version}: {old_exc} -> "
                  f"{result.get('exception_configuration', result.get('status'))} [{cat}]",
                  file=sys.stderr)

        # checkpoint the (network-expensive) classification phase BEFORE the R06-rerun phase, so
        # a failure in step 4 never loses this work -- steps 1-3 are the audit's own real record
        # regardless of whether step 4 succeeds.
        with open(checkpoint_path, "w") as f:
            json.dump({"audited_count": len(idents), "counts": dict(counts),
                        "per_package": per_package, "v5_written": False,
                        "_checkpoint": "classification phase complete, R06 rerun phase pending"},
                       f, indent=2, sort_keys=True, default=str)

    # --- step 4: rerun R06 for every package whose AUTHORITATIVE configuration changed in any
    #     way that could change R06's own candidate-eligibility -- CHANGED (a new decisive
    #     enabled/disabled value) AND CONFLICT (real ambiguity where the frozen TSV recorded a
    #     decisive value). R06's own verdict-construction logic (resource_guard_verdict_r06.py)
    #     ONLY proceeds to a real state (GUARD_MISSING/ESTABLISHED) when exc_config=="disabled"
    #     -- so a CONFLICT-bucket package whose OLD (frozen) value was "disabled" carries the
    #     EXACT SAME regression risk as a CHANGED-bucket package: a real candidate built on a
    #     premise (clean "disabled") that the corrected, authoritative extraction shows was
    #     never actually true (real ambiguity, not a clean "disabled"). Both buckets rerun here;
    #     UNCHANGED and (already-was-"unresolved") UNRESOLVED packages never had a real R06
    #     candidate under the frozen TSV's OWN "unresolved" default in the first place (R06
    #     already abstains via BUILD_CONFIGURATION_UNRESOLVED for those), so nothing to correct.
    rerun_packages = []
    for key_str, v in per_package.items():
        if v.get("category") not in ("CHANGED", "CONFLICT"):
            continue
        # scoped packages (e.g. "@2060.io/ffi-napi@4.0.9") have TWO "@" -- split on the LAST one
        # to separate name from version correctly.
        pkg, version = key_str.rsplit("@", 1)
        rerun_packages.append((pkg, version, v.get("old_exception_configuration"), v))
    changed_packages = rerun_packages  # kept name for the audit-output field below

    r06_reruns = {}
    for pkg, version, old_exc, result in changed_packages:
        corrected_build_config = {
            "exception_configuration": result["exception_configuration"],
            "evidence": [{"note": result["enable_evidence"] or result["disable_evidence"]}],
            "citation": "study/task34_replay/audit_build_config_staleness.py "
                         "(re-extracted from the real pinned tarball, corpus-wide extractor)",
        }
        new_r06 = rerun_r06(pkg, version, corrected_build_config)
        r06_reruns[(pkg, version)] = new_r06

    v4_path = os.path.join(RESULTS_DIR, "replay_records_v4.jsonl")
    v5_path = os.path.join(RESULTS_DIR, "replay_records_v5.jsonl")
    if changed_packages:
        if os.path.exists(v5_path):
            os.remove(v5_path)
        with open(v4_path) as fin, open(v5_path, "a") as fout:
            for line in fin:
                rec = json.loads(line)
                key = (rec.get("package_name"), rec.get("version"))
                if key in r06_reruns:
                    old_r06_by_method = {f.get("method_id"): f for f in (rec.get("r06_findings") or [])}
                    new_r06 = r06_reruns[key]
                    for f in new_r06:
                        old = old_r06_by_method.get(f.get("method_id"))
                        if old and old.get("provenance", {}).get("resolved"):
                            f["provenance"] = dict(old["provenance"])
                        else:
                            f["provenance"] = {"resolved": False,
                                                 "reason": "NO_MATCHING_V4_PROVENANCE_TO_REUSE"}
                        provenance.finalize_reportability(
                            f, provenance.PROPERTY_CANDIDATE_RULES["r06_findings"](f))
                    rec["r06_findings"] = new_r06
                    ag.apply_applicability(rec)
                    ar.apply_known_adjudications(rec)
                    se.enforce_staged_enablement(rec)
                    va.attribute_record(rec)
                    rec["_six_property_summary"] = agg.aggregate_record(
                        rec, enabled_properties=se.ENABLED_PROPERTIES)
                    rec["_build_config_staleness_audit_fix"] = (
                        f"r06_findings regenerated: TSV said {tsv_rows[key]['exception_configuration']!r}, "
                        f"re-extraction from the real pinned tarball says "
                        f"{per_package[f'{key[0]}@{key[1]}']['exception_configuration']!r}")
                fout.write(json.dumps(rec, sort_keys=True, default=str) + "\n")

    audit_out = {
        "audited_count": len(idents),
        "counts": counts,
        "changed_packages": [f"{p}@{v}" for p, v, _, _ in changed_packages],
        "per_package": per_package,
        "v5_written": bool(changed_packages),
    }
    with open(os.path.join(RESULTS_DIR, "build_config_staleness_audit.json"), "w") as f:
        json.dump(audit_out, f, indent=2, sort_keys=True, default=str)

    print("\n=== BUILD-CONFIG STALENESS AUDIT: SUMMARY ===")
    print(json.dumps(counts, indent=2))
    print(f"CHANGED packages: {audit_out['changed_packages']}")
    print(f"v5 written: {audit_out['v5_written']}")


if __name__ == "__main__":
    main()
