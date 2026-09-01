#!/usr/bin/env python3
"""PROV-R01 (task #35) regression. Verifies provenance.py's join logic AND reportability formula
end to end, against real evidence only -- no synthetic manifests standing in for a real positive
finding, and no conflating "provenance resolved" with "safe to report."

Checks, in order:
  1. classify_vendored_hint() against the REAL vendored/package-owned path shapes task #28
     actually observed (re2's vendor/abseil-cpp, ffi-napi's deps/libffi).
  2. tarball_sha256 vs. source_tree_sha256 are REAL, DISTINCT hashes, and source_tree_sha256 is
     deterministic and reproducible independent of the tarball's own bytes.
  3. The reportable formula's four clauses, each independently: unresolved provenance vetoes
     reportable regardless of everything else (the one-way rule); scanner_candidate=False vetoes
     it; applicability_status defaulting to NOT_YET_DETERMINED (never APPLICABLE by construction)
     vetoes it; adjudication_status=CONFIRMED_FALSE_POSITIVE vetoes it even when everything else
     says yes; only when ALL FOUR clauses hold does reportable become True.
  4. THE CENTRAL REGRESSION TEST for the exact defect found and corrected: node-libcurl@5.1.2's
     real Easy::ReadFunction finding is reproduced fresh through run_pipeline_one.py's real
     orchestrator. As of the applicability-gate round's own second correction,
     npm_build_configuration.tsv's node-libcurl row was itself found stale ("disabled" -- predates
     extract_build_config.py's real gyp `!`-list-removal-polarity and node_addon_api_except fixes;
     live re-verification against the real published tarball, and independent reruns of both
     resource_guard_verdict_r05.py and resource_guard_verdict_r06.py against this real finding
     under the corrected value, confirm the real answer is "enabled"). With the TSV corrected,
     this real finding's verdict is CONTRACT_NOT_APPLICABLE and scanner_candidate=False -- the
     regression is fixed AT ITS ROOT CAUSE (the finding never becomes a candidate at all), not
     merely masked by adjudication_registry.py's independent, separately-cited adjudication (which
     still applies here too, on its own real merits, but is no longer the only thing standing
     between this site and an incorrect reportable=True). Two dedicated invariants below prove
     this is a real, independent double-veto, never a masking relationship: stripping the
     adjudication entirely (simulating "never reviewed") from BOTH the real R05 finding and the
     real R06 finding (run through applicability_gate.py directly) must still leave reportable
     False on the corrected verdict's own merits alone.
  5/6. The same real per-finding join verified for LOCK_BALANCE and PROTECTED_FIELD (freshly
     rebuilt real wolfSSL fixtures, not the stale committed raw facts) -- provenance resolves and
     scanner_candidate=True for their own real positive findings, but reportable still correctly
     stays False by default (no applicability/adjudication evidence exists for these either yet
     -- task #32).
"""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
import provenance  # noqa: E402
import resource_guard_verdict_r06  # noqa: E402
import applicability_gate  # noqa: E402

JOERN_HOME = "/home/user/bug_tracker/tchecker-research-complete/joern-install/joern-cli"
CPP_FRONTEND = "/home/user/bug_tracker/tchecker-research-complete/portable-engine-full-review-package/tests/gates/cpp-r06/frontend"


def _resolve_joern_toolchain():
    """Returns ('sh', JOERN_HOME) when the pinned bootstrap install's own launchers are
    present, else ('mvn', classpath) when the SAME pinned Joern v4.0.608 has been assembled
    from Maven Central (bootstrap.sh's release zip is unreachable in some environments; the
    Maven assembly is the identical version -- see check_napi_status.py's own recipe). The
    classpath is read from $NAPI_JOERN_CP, or the file named by $NAPI_JOERN_CP_FILE, or
    ~/joern-mvn/cp.txt. Returns ('none', None) if neither is available -- the gate then
    reports a real environment failure rather than silently passing."""
    if os.path.isfile(os.path.join(JOERN_HOME, "c2cpg.sh")):
        return "sh", JOERN_HOME
    cp = os.environ.get("NAPI_JOERN_CP")
    if not cp:
        cp_file = os.environ.get("NAPI_JOERN_CP_FILE",
                                 os.path.expanduser("~/joern-mvn/cp.txt"))
        if os.path.isfile(cp_file):
            cp = open(cp_file).read().strip()
    if cp:
        return "mvn", cp
    return "none", None

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


def build_single_file_bundle(src_path, work_dir):
    """Real c2cpg -> export -> the exact same chain run_pipeline_one.py uses, over ONE
    standalone source file, mirroring task #28's own real historical-case methodology (not a
    hand-built fixture)."""
    os.makedirs(work_dir, exist_ok=True)
    cpp_bin = os.path.join(work_dir, "cpp.cpg.bin")
    cpp_raw = os.path.join(work_dir, "cpp_raw")
    export_sc = f"{CPP_FRONTEND}/export_c_cpp_facts_v03.sc"
    kind, tc = _resolve_joern_toolchain()
    if kind == "none":
        raise RuntimeError(
            "no pinned Joern v4.0.608 toolchain available: neither the bootstrap install's "
            f"{JOERN_HOME}/c2cpg.sh nor a Maven-assembled classpath ($NAPI_JOERN_CP / "
            "$NAPI_JOERN_CP_FILE / ~/joern-mvn/cp.txt) was found")
    if kind == "sh":
        c2cpg = [f"{tc}/c2cpg.sh", "-o", cpp_bin,
                 "--define", "NAPI_DISABLE_CPP_EXCEPTIONS", src_path]
        export = [f"{tc}/joern", "--script", export_sc,
                  "--param", f"cpgFile={cpp_bin}", "--param", f"outDir={cpp_raw}"]
        run_cwd = None
    else:  # 'mvn': invoke the identical Joern entry points directly off the classpath
        open(os.path.join(work_dir, ".installation_root"), "w").close()  # ReplBridge marker
        java = ["java", "-Xmx4g", "-cp", tc]
        c2cpg = java + ["io.joern.c2cpg.Main", "-o", cpp_bin,
                        "--define", "NAPI_DISABLE_CPP_EXCEPTIONS", src_path]
        export = java + ["io.joern.joerncli.console.ReplBridge", "--script", export_sc,
                         "--param", f"cpgFile={cpp_bin}", "--param", f"outDir={cpp_raw}"]
        run_cwd = work_dir
    r = subprocess.run(c2cpg, capture_output=True, text=True, timeout=300, cwd=run_cwd)
    if not os.path.isfile(cpp_bin):
        raise RuntimeError(f"c2cpg failed: {r.stdout[-2000:]} {r.stderr[-2000:]}")
    r = subprocess.run(export, capture_output=True, text=True, timeout=300, cwd=run_cwd)
    if not os.path.isfile(os.path.join(cpp_raw, "methods.tsv")):
        raise RuntimeError(f"export failed: {r.stdout[-2000:]} {r.stderr[-2000:]}")
    return cpp_raw


def main():
    # --- 1. vendored-hint heuristic, against real paths task #28 actually observed -----------
    ck("re2 vendored abseil path -> VENDORED_HINT",
       provenance.classify_vendored_hint(
           "vendor/abseil-cpp/absl/base/internal/strerror.cc") == "VENDORED_HINT")
    ck("ffi-napi vendored libffi path -> VENDORED_HINT",
       provenance.classify_vendored_hint("deps/libffi/src/closures.c") == "VENDORED_HINT")
    ck("package-owned path -> PACKAGE_OWNED_HINT",
       provenance.classify_vendored_hint("src/add.cpp") == "PACKAGE_OWNED_HINT")

    # --- 2. tarball_sha256 vs source_tree_sha256 are real, distinct, and the tree hash is ------
    #        independent of the tarball's own bytes -----------------------------------------
    tmp_pkg = "/tmp/_prov_hash_test_pkg"
    shutil.rmtree(tmp_pkg, ignore_errors=True)
    os.makedirs(tmp_pkg)
    with open(os.path.join(tmp_pkg, "a.c"), "w") as f:
        f.write("int a(void) { return 1; }\n")
    m1 = provenance.build_source_manifest(tmp_pkg, b"TARBALL_BYTES_VERSION_ONE", "p", "1.0.0")
    m2 = provenance.build_source_manifest(tmp_pkg, b"COMPLETELY_DIFFERENT_TARBALL_BYTES", "p", "1.0.0")
    ck("tarball_sha256 differs when tarball bytes differ",
       m1["tarball_sha256"] != m2["tarball_sha256"])
    ck("source_tree_sha256 is IDENTICAL when only tarball bytes differ (same real file content)",
       m1["source_tree_sha256"] == m2["source_tree_sha256"])
    ck("tarball_sha256 != source_tree_sha256 (two real, distinct hashes, not aliases)",
       m1["tarball_sha256"] != m1["source_tree_sha256"])
    with open(os.path.join(tmp_pkg, "a.c"), "w") as f:
        f.write("int a(void) { return 2; }\n")  # real content change
    m3 = provenance.build_source_manifest(tmp_pkg, b"TARBALL_BYTES_VERSION_ONE", "p", "1.0.0")
    ck("source_tree_sha256 changes when real file content changes (same tarball bytes as m1)",
       m3["source_tree_sha256"] != m1["source_tree_sha256"])
    shutil.rmtree(tmp_pkg, ignore_errors=True)

    # --- 3. the reportable formula's four clauses, each independently ------------------------
    # NOTE: study/resource_guard/raw_c01_missing_check/'s own committed raw facts reference a
    # filename ("c01_missing_check.cpp") that predates this repo's fixture_source.cpp renaming
    # convention -- the committed file is literally named fixture_source.cpp, so a manifest
    # walk of that directory as-is would report PATH_NOT_IN_MANIFEST for every real method_id
    # (a real, disclosed mismatch, correctly caught elsewhere in this suite -- see the earlier
    # unresolved-node-id checks). For sections 3b-3e specifically, which need a REAL RESOLVED
    # join to test reportable's OTHER three clauses in isolation, build a clean scratch copy
    # under the real facts' own claimed filename instead of reusing the mismatched one.
    fixture_dir = HERE / "study" / "resource_guard" / "raw_c01_missing_check"
    method_map = provenance.load_method_file_map(str(fixture_dir))
    real_method_id = next(iter(method_map))
    real_claimed_filename = method_map[real_method_id]
    scratch_dir = pathlib.Path("/tmp/_prov_reportable_scratch")
    shutil.rmtree(scratch_dir, ignore_errors=True)
    scratch_dir.mkdir()
    shutil.copy(fixture_dir / "fixture_source.cpp", scratch_dir / real_claimed_filename)
    manifest = provenance.build_source_manifest(str(scratch_dir), b"placeholder", "test-pkg", "1.0.0")
    fixture_dir = scratch_dir  # 3b-3e's enrich_finding calls resolve pkg_dir against this now

    # 3a. unresolved provenance vetoes reportable REGARDLESS of every other field, even if
    #     someone (wrongly) tries to force the other three fields to "yes".
    unresolved = {"method_id": 99999999999, "scanner_candidate": True,
                  "applicability_status": "APPLICABLE", "adjudication_status": "NOT_ADJUDICATED"}
    provenance.enrich_finding(unresolved, unresolved["method_id"], method_map, manifest,
                               str(fixture_dir), "method_id")
    provenance.finalize_reportability(unresolved, is_scanner_candidate=True)
    ck("unresolved provenance -> reportable=False, even with scanner_candidate=True and "
       "applicability_status=APPLICABLE forced (the one-way rule)",
       unresolved["reportable"] is False)
    ck("unresolved provenance: provenance['resolved']=False", unresolved["provenance"]["resolved"] is False)

    # 3b. resolved provenance + NOT a scanner candidate -> still False, even with
    #     applicability_status forced to APPLICABLE before finalize_reportability runs.
    not_candidate = {"method_id": real_method_id, "applicability_status": "APPLICABLE"}
    provenance.enrich_finding(not_candidate, real_method_id, method_map, manifest,
                               str(fixture_dir), "method_id")
    provenance.finalize_reportability(not_candidate, is_scanner_candidate=False)
    ck("resolved provenance + APPLICABLE forced, but scanner_candidate=False -> reportable=False",
       not_candidate["reportable"] is False and not_candidate["scanner_candidate"] is False)

    # 3c. resolved + real candidate + DEFAULT applicability_status (no evidence yet) -> False.
    default_applicability = {"method_id": real_method_id}
    provenance.enrich_finding(default_applicability, real_method_id, method_map, manifest,
                               str(fixture_dir), "method_id")
    provenance.finalize_reportability(default_applicability, is_scanner_candidate=True)
    ck("resolved + real candidate, but applicability_status defaults to NOT_YET_DETERMINED "
       "(never APPLICABLE by construction) -> reportable=False",
       default_applicability["reportable"] is False
       and default_applicability["applicability_status"] == "NOT_YET_DETERMINED")

    # 3d. resolved + candidate + APPLICABLE + CONFIRMED_FALSE_POSITIVE adjudication -> False.
    vetoed = {"method_id": real_method_id, "applicability_status": "APPLICABLE",
              "adjudication_status": "CONFIRMED_FALSE_POSITIVE"}
    provenance.enrich_finding(vetoed, real_method_id, method_map, manifest,
                               str(fixture_dir), "method_id")
    provenance.finalize_reportability(vetoed, is_scanner_candidate=True)
    ck("resolved + candidate + APPLICABLE, but adjudication_status=CONFIRMED_FALSE_POSITIVE "
       "-> reportable=False (the adjudication veto)", vetoed["reportable"] is False)

    # 3e. the ONLY combination that produces reportable=True -- all four real conditions met.
    genuinely_reportable = {"method_id": real_method_id, "applicability_status": "APPLICABLE",
                             "adjudication_status": "NOT_ADJUDICATED"}
    provenance.enrich_finding(genuinely_reportable, real_method_id, method_map, manifest,
                               str(fixture_dir), "method_id")
    provenance.finalize_reportability(genuinely_reportable, is_scanner_candidate=True)
    ck("resolved + scanner_candidate + APPLICABLE + not confirmed-false-positive "
       "-> reportable=True (the only positive path)", genuinely_reportable["reportable"] is True)
    shutil.rmtree(scratch_dir, ignore_errors=True)

    # --- 3f. count_reportable_findings() (resource_guard_verdict_r06.py): synthetic, network-
    #         independent regression for the ported reporting-boundary helper, using the SAME
    #         four already-enriched findings from 3c/3d/3e above (a real CONTRACT_NOT_APPLICABLE-
    #         shaped abstention, an applicability veto, an adjudication veto, and the one genuine
    #         positive) -- covers the real defect this replaces an earlier lineage revision's own
    #         count_actionable_findings()/ACTIONABLE_VERDICTS for, without requiring network
    #         access or a real corpus run (section 4 below adds the real, non-synthetic version
    #         of this same check against node-libcurl's own real finding).
    synthetic_r06_findings = [default_applicability, vetoed, genuinely_reportable,
                               {"reportable": False}, {}]
    reportable_count = resource_guard_verdict_r06.count_reportable_findings(synthetic_r06_findings)
    ck("count_reportable_findings(): counts exactly the one genuinely reportable=True finding, "
       "never the applicability-veto, adjudication-veto, bare reportable=False, or a finding "
       "missing the field entirely (all default to excluded, never counted by len() or verdict "
       "alone)", reportable_count == 1)
    ck("count_reportable_findings([]) == 0 (empty list handled, not an error)",
       resource_guard_verdict_r06.count_reportable_findings([]) == 0)

    # --- 4. THE CENTRAL REGRESSION TEST: node-libcurl / Easy::ReadFunction (Resource Guard) ---
    npm_corpus = HERE / "npm_corpus"
    sys.path.insert(0, str(npm_corpus))
    import run_pipeline_one as P

    eligible = {}
    with open(npm_corpus / "eligible_packages.tsv") as f:
        header = next(f).rstrip("\n").split("\t")
        idx = {n: i for i, n in enumerate(header)}
        for line in f:
            parts = line.rstrip("\n").split("\t")
            eligible[(parts[idx["package_name"]], parts[idx["version"]])] = {
                "tarball_url": parts[idx["tarball_url"]]}
    build_config = {}
    with open(npm_corpus / "npm_build_configuration.tsv") as f:
        header = next(f).rstrip("\n").split("\t")
        idx = {n: i for i, n in enumerate(header)}
        for line in f:
            parts = line.rstrip("\n").split("\t")
            build_config[(parts[idx["package_name"]], parts[idx["version"]])] = \
                parts[idx["exception_configuration"]]

    pkg, version = "node-libcurl", "5.1.2"
    key = (pkg, version)
    if key not in eligible:
        print(f"SKIP node-libcurl diagnostic: {key} not in eligible_packages.tsv")
    else:
        info = eligible[key]
        exc = build_config.get(key)
        work_root = "/tmp/check_provenance_libcurl"
        shutil.rmtree(work_root, ignore_errors=True)
        t0 = time.time()
        rec = P.run_one(pkg, version, info["tarball_url"], exc, work_root)
        print(f"  node-libcurl run: {rec.get('status')} in {time.time()-t0:.1f}s", file=sys.stderr)
        ck("node-libcurl real run reaches ANALYZED", rec.get("status") == "ANALYZED")
        r05_findings = rec.get("r05_findings") or []
        rf = [f for f in r05_findings if "ReadFunction" in (f.get("method_name") or "")]
        ck("node-libcurl reproduces the real Easy::ReadFunction finding", len(rf) >= 1)
        if rf:
            f = rf[0]
            ck("*** THE FIX ITSELF: with npm_build_configuration.tsv corrected, real finding's "
               "verdict is CONTRACT_NOT_APPLICABLE, not the old stale-data-masked "
               "VALUE_ACQUISITION_GUARD_MISSING ***",
               f.get("verdict") == "CONTRACT_NOT_APPLICABLE")
            ck("*** scanner_candidate is now False on its own real evidentiary merits -- this "
               "site never becomes a candidate at all under the corrected build config, rather "
               "than becoming one and being caught downstream ***",
               f.get("scanner_candidate") is False)
            ck("real finding: provenance.resolved=True", f.get("provenance", {}).get("resolved") is True)
            ck("real finding: applicability_status defaults to NOT_YET_DETERMINED, not APPLICABLE",
               f.get("applicability_status") == "NOT_YET_DETERMINED")
            ck("*** reportable=False, even though provenance resolved ***"
               " -- provenance resolving a known confirmed-false-positive's file must NEVER make"
               " it reportable", f.get("reportable") is False)
            ck("ADJUDICATION-REGISTRY-R01, wired into the real pipeline (run_pipeline_one.py):"
               " this real finding's adjudication_status is ALSO CONFIRMED_FALSE_POSITIVE, with a"
               " real citation -- still applied on its own independent real merits even though "
               "it is no longer the only thing preventing reportable=True",
               f.get("adjudication_status") == "CONFIRMED_FALSE_POSITIVE"
               and f.get("adjudication_citation")
               == "study/resource_guard_r05/NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md")

            # *** THE SPECIFIC INVARIANT REQUIRED BY DIRECT INSTRUCTION: "add an invariant that
            # checks node-libcurl's applicability before adjudication" -- the adjudication
            # registry must be a real, SECOND, INDEPENDENT veto, never the only thing masking an
            # incorrect grant. Proven by stripping the adjudication from this SAME real finding
            # entirely (simulating "never reviewed") and recomputing reportable: it must STILL be
            # False, purely on the corrected verdict's own scanner_candidate=False merits.
            unadjudicated = dict(f)
            unadjudicated["provenance"] = dict(f["provenance"])
            unadjudicated["adjudication_status"] = "NOT_ADJUDICATED"
            unadjudicated.pop("adjudication_citation", None)
            unadjudicated.pop("adjudication_reason", None)
            provenance.finalize_reportability(unadjudicated, unadjudicated.get("scanner_candidate", False))
            ck("*** THE REQUIRED INVARIANT (R05): with adjudication stripped entirely, as if this "
               "site had never been individually reviewed, node-libcurl's real R05 finding STILL "
               "does not become reportable -- the corrected build config, not the adjudication, "
               "is what keeps this non-reportable; adjudication_registry.py is a real second, "
               "independent veto here, never the only thing masking an incorrect applicability "
               "grant ***", unadjudicated["reportable"] is False)
            src_path = f.get("provenance", {}).get("source_path")
            ck("real finding has a non-empty real source_path", bool(src_path))
            real_abs_path = os.path.join(work_root, "pkg", src_path) if src_path else None
            file_existed = real_abs_path and os.path.isfile(real_abs_path)
            ck("real finding's source_path resolves to an actual file on disk"
               " (checked before work_root cleanup)", file_existed)
            if file_existed:
                real_hash = provenance.sha256_hex(open(real_abs_path, "rb").read())
                ck("real finding's content_hash matches independently recomputed hash of the "
                   "real source file", real_hash == f.get("provenance", {}).get("content_hash"))
            ck("real finding retains its own method_id (pre-existing node identity, untouched)",
               "method_id" in f)

        # task #41 (R06/FIX01I merged into the driven lineage, real acceptance test): the SAME
        # real pipeline run above now also runs resource_guard_verdict_r06.py alongside R04/R05
        # -- its own real ReadFunction finding must reclassify from R05's own unconditional
        # attacker-influence claim to a real, disclosed SOURCE_BOUNDARY_UNRESOLVED.
        r06_findings = rec.get("r06_findings") or []
        rf6 = [f for f in r06_findings if "ReadFunction" in (f.get("method_name") or "")]
        ck("node-libcurl reproduces the real Easy::ReadFunction finding under R06 too "
           "(task #41)", len(rf6) >= 1)
        if rf6:
            f6 = rf6[0]
            sbe = f6.get("source_boundary_evidence")
            ck("*** task #41's own named acceptance test: R06's real ReadFunction finding "
               "reports source_boundary_evidence.source_boundary == 'SOURCE_BOUNDARY_UNRESOLVED' "
               "and attacker_controlled: False (R05's own unconditional attacker-influence claim "
               "for this exact site is corrected, post-integration, on a REAL pipeline run) ***",
               bool(sbe) and sbe.get("source_boundary") == "SOURCE_BOUNDARY_UNRESOLVED"
               and sbe.get("attacker_controlled") is False)
            ck("real R06 finding: provenance.resolved=True (same enrichment as R04/R05)",
               f6.get("provenance", {}).get("resolved") is True)
            ck("real R06 finding: reportable stays False (no real, separate, affirmative "
               "applicability step exists yet for this site -- applicability_status defaults "
               "to NOT_YET_DETERMINED, never APPLICABLE by construction)",
               f6.get("reportable") is False)
            # count_reportable_findings() (resource_guard_verdict_r06.py) is the current,
            # ported replacement for an earlier lineage revision's own count_actionable_findings()
            # -- verifies on this SAME real pipeline run that node-libcurl's own real
            # Easy::ReadFunction R06 finding, despite provenance resolving and carrying real
            # source_boundary_evidence, is correctly EXCLUDED from the reportable count.
            reportable_r06 = resource_guard_verdict_r06.count_reportable_findings(r06_findings)
            ck("*** count_reportable_findings() PORT REGRESSION: node-libcurl's real R06 "
               "findings (including Easy::ReadFunction) contribute 0 to the reportable count "
               "-- proves the ported reporting-boundary helper does not resurrect the old "
               "verdict-only 'actionable' shortcut this real false-positive would have passed ***",
               reportable_r06 == 0)

            # *** THE SPECIFIC INVARIANT REQUIRED BY DIRECT INSTRUCTION, R06 side: applicability_
            # gate.py (not wired into run_pipeline_one.py itself -- applied by the later post-
            # processing stage) must never grant node-libcurl's real R06 finding APPLICABLE at
            # all under the corrected build config, independent of adjudication. Proven by
            # running it directly against this SAME real finding with adjudication stripped
            # (simulating "never reviewed") -- applicability_gate's own condition 1
            # (verdict == VALUE_ACQUISITION_GUARD_MISSING) must fail on the corrected verdict's
            # own merits, never reaching an adjudication veto at all.
            f6_preadj = dict(f6)
            f6_preadj["provenance"] = dict(f6["provenance"])
            f6_preadj["adjudication_status"] = "NOT_ADJUDICATED"
            f6_preadj.pop("adjudication_citation", None)
            f6_preadj.pop("adjudication_reason", None)
            f6_preadj["applicability_status"] = "NOT_YET_DETERMINED"
            record_preadj = {"r06_findings": [f6_preadj]}
            applicability_gate.apply_applicability(record_preadj)
            # apply_applicability() only recomputes reportable for findings that clear its own
            # preconditions -- explicitly re-finalize here too, so this check proves reportable is
            # freshly False given the CURRENT field state, never a stale carryover value.
            provenance.finalize_reportability(f6_preadj, f6_preadj.get("scanner_candidate", False))
            ck("*** THE REQUIRED INVARIANT (R06): applicability_gate.py, run against node-"
               "libcurl's real R06 finding under the CORRECTED build config with NO adjudication "
               "applied at all, never grants applicability_status=APPLICABLE -- the corrected "
               "verdict (CONTRACT_NOT_APPLICABLE, not VALUE_ACQUISITION_GUARD_MISSING) fails "
               "applicability_gate's own condition 1 on its own real evidentiary merits, before "
               "adjudication ever gets a chance to veto anything ***",
               f6_preadj.get("applicability_status") != "APPLICABLE")
            ck("*** and reportable correctly stays False with zero adjudication applied -- this "
               "is the fix itself, not the adjudication registry masking a regression ***",
               f6_preadj.get("reportable") is False)
        shutil.rmtree(work_root, ignore_errors=True)

    # --- 5/6. LOCK_BALANCE and PROTECTED_FIELD: provenance resolves + scanner_candidate=True, --
    #          but reportable correctly stays False (no applicability/adjudication evidence -----
    #          exists for these yet -- task #32) --------------------------------------------
    lockcap = HERE / "study" / "lockcap"
    for name, subdir, script in (
        ("LOCK_BALANCE", "raw_real_vuln", "lock_balance_verdict.py"),
        ("PROTECTED_FIELD", "raw_xfn_real", "protected_field_verdict.py"),
    ):
        src = lockcap / subdir / "fixture_source.c"
        work_dir = f"/tmp/check_provenance_{name.lower()}"
        shutil.rmtree(work_dir, ignore_errors=True)
        try:
            cpp_raw = build_single_file_bundle(str(src), work_dir)
        except Exception as e:
            ck(f"{name}: fresh real c2cpg build succeeds", False)
            print(f"  {name} build error: {e}", file=sys.stderr)
            continue
        ck(f"{name}: fresh real c2cpg build succeeds", True)

        out_path = os.path.join(work_dir, "out.json")
        subprocess.run([sys.executable, str(HERE / script), cpp_raw, out_path],
                        capture_output=True, text=True)
        doc = json.load(open(out_path))
        findings = doc.get("findings", [])
        ck(f"{name}: real fixture produces its own real positive finding", len(findings) >= 1)

        manifest = provenance.build_source_manifest(str(src.parent), b"placeholder_tarball",
                                                       "wolfssl-fixture", "n/a")
        method_map = provenance.load_method_file_map(cpp_raw)
        for f in findings:
            provenance.enrich_finding(f, f.get("method_id"), method_map, manifest,
                                        str(src.parent), "method_id")
            provenance.finalize_reportability(f, is_scanner_candidate=True)
        resolved = [f for f in findings if f.get("provenance", {}).get("resolved") is True]
        ck(f"{name}: real finding's provenance resolves via method_id join, no scanner-file "
           "change needed", len(resolved) >= 1)
        if resolved:
            f = resolved[0]
            ck(f"{name}: scanner_candidate=True", f.get("scanner_candidate") is True)
            ck(f"{name}: reportable=False by default (no applicability/adjudication evidence "
               "exists yet -- task #32) even though provenance resolved",
               f.get("reportable") is False)
            ck(f"{name}: resolved source_path is real 'fixture_source.c'",
               f["provenance"]["source_path"] == "fixture_source.c")
            real_hash = provenance.sha256_hex(src.read_bytes())
            ck(f"{name}: content_hash matches independently recomputed real file hash",
               real_hash == f["provenance"]["content_hash"])
            ck(f"{name}: has real distinct tarball_sha256/source_tree_sha256",
               f["provenance"]["tarball_sha256"] != f["provenance"]["source_tree_sha256"])
        shutil.rmtree(work_dir, ignore_errors=True)

    print(f"\nPROVENANCE_CONTROLS={ok}/{total}")
    sys.exit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
