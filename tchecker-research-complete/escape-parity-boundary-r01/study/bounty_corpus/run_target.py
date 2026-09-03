#!/usr/bin/env python3
"""Run the FROZEN ESCAPE-PARITY-BOUNDARY layers once over a pinned target.

Nothing in the analyser is touched by this script. It builds a CPG over the
staged file set, measures parse coverage before looking at any finding, and
only then runs the parser layer and the reachability layer.

Parse coverage is a first-class outcome, not a footnote: a frontend that
silently parsed a fraction of the tree yields "no candidates" that mean
nothing, so a run below the threshold is reported as INFRASTRUCTURE_FAILURE
rather than as a clean negative.

usage: run_target.py <manifest.json> <stage_root> <cpg_path> <language> <out_dir>
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

R = Path("/home/user/bug_tracker/tchecker-research-complete/escape-parity-boundary-r01")
JH = Path("/home/user/bug_tracker/tchecker-research-complete/joern-install/joern-cli")
CHK = Path(__file__).resolve().parent / "cpg_files.sc"
sys.path.insert(0, str(R))
import escape_parity_sites          # noqa: E402
import escape_parity_chain          # noqa: E402

# Below this fraction of executable source files present in the CPG, the run
# is not evidence about the target -- it is evidence about the frontend.
COVERAGE_THRESHOLD = 0.80

PARSER_SC = {"JAVASCRIPT": "escape_parity_facts.sc",
             "C_CPP": "cpp_escape_parity_facts.sc"}
REACH_SC = {"JAVASCRIPT": "js_reachability_facts.sc",
            "C_CPP": "cpp_reachability_facts.sc"}
# c2cpg emits a FILE node for every translation unit it opens, headers
# included, so coverage for C/C++ is measured against sources *and* headers.
# Measuring 665 sources against 1,531 CPG files would have read as 230%
# coverage -- a ratio between two differently-defined populations, not a
# measurement -- so coverage is computed as a set intersection instead.
# jssrc2cpg handles JavaScript and TypeScript through one frontend, so both
# kinds count as executable source for the JAVASCRIPT language.
COVERED_KINDS = {"JAVASCRIPT": {"JAVASCRIPT", "TYPESCRIPT"},
                 "C_CPP": {"C_CPP_SOURCE", "C_CPP_HEADER"}}
EXEC_KINDS = {"JAVASCRIPT": {"JAVASCRIPT", "TYPESCRIPT"},
              "C_CPP": {"C_CPP_SOURCE"}}


def run(cmd, timeout):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def run_script(script, params, expect, timeout, tries=3):
    """Run a Joern script, retrying while it produces no output artifact.

    Joern's first invocation against a CPG whose workspace project has to be
    re-created can exit without running the script body: no facts written, no
    error line, exit status 0. Treating that as "the target has no findings"
    would turn an infrastructure condition into a clean negative, which is
    the exact failure this property is built to avoid. So the artifact's
    existence -- not the exit status -- decides success, and the number of
    attempts is recorded in the run record.
    """
    cmd = [str(JH / "joern"), "--script", str(script)]
    for k, v in params.items():
        cmd += ["--param", "%s=%s" % (k, v)]
    attempts = 0
    proc = None
    for _ in range(tries):
        attempts += 1
        proc = run(cmd, timeout)
        if os.path.exists(expect):
            break
    return proc, attempts, os.path.exists(expect)


def main():
    # Every path handed to Joern must be absolute. Joern resolves a relative
    # path against its own install directory, not the caller's, so a relative
    # output directory silently sends facts into the Joern tree while the
    # reducer reads an empty directory here -- a run that looks like a clean
    # negative but analysed nothing.
    manifest = os.path.abspath(sys.argv[1])
    stage = os.path.abspath(sys.argv[2])
    cpg = os.path.abspath(sys.argv[3])
    lang = sys.argv[4]
    out_dir = Path(sys.argv[5]).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    doc = json.load(open(manifest))
    n_exec = sum(1 for f in doc["files"] if f["kind"] in EXEC_KINDS[lang])
    expected = {f["path"] for f in doc["files"] if f["kind"] in COVERED_KINDS[lang]}
    rec = {
        "target": doc["target"], "language": lang,
        "commit": doc["commit"], "commit_date": doc["commit_date"],
        "file_set_sha256": doc["file_set_sha256"],
        "executable_source_files": n_exec,
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    t0 = time.time()

    if not os.path.exists(cpg) or not os.path.getsize(cpg):
        rec.update(status="INFRASTRUCTURE_FAILURE", stage="frontend")
        return finish(rec, out_dir, t0)

    names_file = out_dir / ("cpg_files_%s.txt" % lang.lower())
    if names_file.exists():
        names_file.unlink()
    chk, rec["cpg_files_attempts"], ok = run_script(
        CHK, {"cpgFile": cpg, "outFile": names_file}, str(names_file), 3600)
    if not ok:
        rec.update(status="INFRASTRUCTURE_FAILURE", stage="cpg_inventory",
                   detail=(chk.stdout + chk.stderr)[-400:])
        return finish(rec, out_dir, t0)
    line = next((l for l in chk.stdout.splitlines() if l.startswith("CPGCHECK")), "")
    cov = {k: int(v) for k, v in (p.split("=") for p in line.split()[1:])} if line else {}
    rec["cpg"] = cov

    # CPG file names are recorded relative to the staged root; normalise both
    # sides before intersecting so a path-shape difference is never mistaken
    # for a parse failure.
    seen = set()
    if names_file.exists():
        for raw_name in names_file.read_text().splitlines():
            nm = raw_name.strip()
            if not nm:
                continue
            nm = os.path.relpath(nm, stage) if os.path.isabs(nm) else nm
            seen.add(os.path.normpath(nm))
    covered = expected & seen
    rec["expected_files"] = len(expected)
    rec["covered_files"] = len(covered)
    rec["cpg_files_not_in_manifest"] = len(seen - expected)
    rec["parse_coverage"] = round(len(covered) / len(expected), 4) if expected else 0.0
    rec["coverage_threshold"] = COVERAGE_THRESHOLD
    if rec["parse_coverage"] < COVERAGE_THRESHOLD:
        missing = sorted(expected - covered)
        rec.update(status="INFRASTRUCTURE_FAILURE", stage="parse_coverage",
                   missing_sample=missing[:20],
                   detail="frontend covered %.1f%% of the frozen file set; a "
                          "finding count from this run would describe the "
                          "frontend, not the target"
                          % (100 * rec["parse_coverage"]))
        return finish(rec, out_dir, t0)

    raw = out_dir / ("raw_%s" % lang.lower())
    raw.mkdir(exist_ok=True)
    # Joern's first script run against a freshly imported CPG can fail while
    # the workspace project is still being materialised, and it fails without
    # writing facts and without an error line. That is an infrastructure
    # condition, not a result, so it gets one retry -- recorded, not hidden.
    quote_sites = raw / "parser_quote_sites.tsv"
    if quote_sites.exists():
        quote_sites.unlink()
    pr, rec["parser_producer_attempts"], ok = run_script(
        R / "producers" / PARSER_SC[lang], {"cpgFile": cpg, "rawDir": raw},
        str(quote_sites), 10800)
    if not ok:
        rec.update(status="INFRASTRUCTURE_FAILURE", stage="parser_producer",
                   detail=(pr.stdout + pr.stderr)[-400:])
        return finish(rec, out_dir, t0)

    sites = escape_parity_sites.derive(raw, lang)
    keys = sorted({k for f in sites["findings"]
                   if f["classification"] == "ESCAPE_PARITY_PARSER_CANDIDATE"
                   for k in (f["site_node_id"], f["method_node_id"])})
    rec["parser_layer"] = {
        "records": len(sites["findings"]),
        "candidates": sum(1 for f in sites["findings"]
                          if f["classification"] == "ESCAPE_PARITY_PARSER_CANDIDATE"),
    }
    anchors = raw / "parser_anchors.tsv"
    if anchors.exists():
        anchors.unlink()
    rr, rec["reachability_attempts"], ok = run_script(
        R / "producers" / REACH_SC[lang],
        {"cpgFile": cpg, "rawDir": raw, "parserMethodIds": ",".join(keys)},
        str(anchors), 10800)
    if not ok:
        rec.update(status="INFRASTRUCTURE_FAILURE", stage="reachability_producer",
                   detail=(rr.stdout + rr.stderr)[-400:])
        return finish(rec, out_dir, t0)
    rec["reachability_line"] = next(
        (l for l in rr.stdout.splitlines() if "REACHABILITY_FACTS" in l), "")

    # The anchor table enumerates every anchor the producer considered -- 31,863
    # rows and 5 MB on the Firefox run -- but only rows keyed to a finding's site
    # or method matter to the chain. Earlier this was deleted outright to keep
    # the archive small, which meant the stored facts no longer reproduced the
    # stored findings: re-deriving reported PARSER_NEVER_CALLED_IN_ANALYSED_SOURCE
    # for a parser that was in fact called. Prune to the rows that carry meaning
    # instead, so the archive stays both small and faithful.
    anchors_path = raw / "parser_anchors.tsv"
    if anchors_path.exists():
        keys = {k for f in sites["findings"]
                for k in (f.get("site_node_id"), f.get("method_node_id")) if k}
        kept = [ln for ln in anchors_path.read_text().splitlines()
                if ln.split("\t")[2:3] and ln.split("\t")[2] in keys]
        rec["anchor_rows_total"] = sum(1 for _ in anchors_path.open())
        rec["anchor_rows_kept"] = len(kept)
        anchors_path.write_text("".join(l + "\n" for l in kept))

    final = escape_parity_chain.derive(raw, lang)
    final["target"] = doc["target"]
    final["commit"] = doc["commit"]
    final["file_set_sha256"] = doc["file_set_sha256"]
    (out_dir / ("findings_%s.json" % lang.lower())).write_text(
        json.dumps(final, indent=1) + "\n")
    rec.update(status="ANALYZED", n_records=len(final["findings"]),
               classifications={c: sum(1 for f in final["findings"]
                                       if f["classification"] == c)
                                for c in sorted({f["classification"]
                                                 for f in final["findings"]})})
    return finish(rec, out_dir, t0)


def finish(rec, out_dir, t0):
    rec["elapsed_s"] = round(time.time() - t0, 1)
    path = out_dir / ("run_%s.json" % rec["language"].lower())
    path.write_text(json.dumps(rec, indent=1) + "\n")
    print(json.dumps(rec, indent=1))
    return 0 if rec.get("status") == "ANALYZED" else 1


if __name__ == "__main__":
    sys.exit(main())
