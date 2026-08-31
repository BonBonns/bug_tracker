#!/usr/bin/env python3
"""Overnight 100-package DIAGNOSTIC-ONLY run. Extends the real, proven run_pipeline_one.py
pipeline (download -> extract -> provenance manifest -> header staging -> c2cpg -> jssrc2cpg ->
export -> normalize -> polyglot link) with, for the first time in this npm-corpus pipeline, ALL
SIX property scanners:

  1. FALLIBLE_BOUNDED_RESOURCE  (resource_guard_verdict_r04.py + _r05.py -- already driven;
     labeled PRECISION_FIX_NOT_INTEGRATED since #41 has not merged R06/FIX01I into this lineage)
  2. LOCK_BALANCE               (lock_balance_verdict.py)
  3. PROTECTED_FIELD            (protected_field_verdict.py)
  4. OOB_WRITE / OOB_INDEX_WRITE (oob_write_verdict.py + oob_index_write_verdict.py --
     the latter carries PARAM-CAP-R01, task #44, labeled DEVELOPMENT_ONLY on its own candidates)
  5. OOB_READ                   (oob_read_verdict.py)
  6. OOB_COMPARE                (oob_compare_verdict.py -- labeled UNVALIDATED_PROPERTY, task #33)

DIAGNOSTIC-ONLY MODE (this script always runs in this mode -- there is no other mode): every
finding/candidate this run produces has reportable FORCED to False at final aggregation,
regardless of what provenance.py's own formula computed, with a preflight assertion that
aborts the run if any record is ever found with reportable=True. scanner_candidate, the raw
verdict, all evidence, applicability_status and adjudication_status are preserved untouched --
only reportable is forced. See enforce_diagnostic_only().

Reachability is REACHABILITY_UNRESOLVED for every finding in this run: promote_via_js_linkage.py
(real JS-linkage reachability promotion) is NOT used here (hard dependency on
resource_guard_verdict_r06.py, deliberately not integrated -- see the integration branch's own
commit history), and task #32 (tiered reachability) is not complete.

Every package's real evidence (raw C++ facts, normalized facts, sidecars, build config, every
scanner's raw output, cross-language linkage evidence) is preserved via evidence_bundle.py
BEFORE work_root is deleted, gzip-compressed, atomically written, hash-verified.

CLI (per direct instruction):
  python3 run_diagnostic_100.py --sample overnight_sample_100.tsv \
    --output overnight_diagnostic_working.jsonl --bundle-dir evidence_bundles_100 \
    --workers 2 --resume --diagnostic-only
"""
import argparse
import hashlib
import json
import os
import resource
import shutil
import sys
import time
import traceback
import concurrent.futures
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
NPM_CORPUS = os.path.dirname(HERE)
SCANNER_V2 = os.path.dirname(NPM_CORPUS)
TOOLS_DIR = "/home/user/bug_tracker/tchecker-research-complete/portable-engine-full-review-package/tools"

sys.path.insert(0, NPM_CORPUS)
sys.path.insert(0, SCANNER_V2)
sys.path.insert(0, TOOLS_DIR)

# RESOURCE SETTINGS (section 7): P (run_pipeline_one.py) computes its own STAGE_TIMEOUT (governs
# c2cpg/jssrc2cpg/cpp_export/js_export) and NORMALIZE_TIMEOUT (governs cpp_normalize/js_normalize)
# ONCE at import time from NPM_CORPUS_TIMEOUT_MULTIPLIER (default base 180s each) -- set the
# multiplier BEFORE importing P so both land on the requested 900s ceiling (180*5=900). P's own
# LINK_TIMEOUT/SCAN_TIMEOUT scale to 450s as a side effect of the same multiplier; SCAN_TIMEOUT
# (governs r04/r05) is overridden directly to exactly 300s right after import, matching "each
# scanner: 300 seconds" precisely -- LINK_TIMEOUT (polyglot linking, not itself a "scanner") is
# left at the scaled 450s, a reasonable, disclosed choice given no explicit ceiling was named
# for it.
os.environ.setdefault("NPM_CORPUS_TIMEOUT_MULTIPLIER", "5")

import run_pipeline_one as P            # noqa: E402 -- real, proven pipeline stages, reused as-is
P.SCAN_TIMEOUT = 300                    # noqa: E402 -- exact 300s ceiling per scanner, not 450s
import evidence_bundle                  # noqa: E402
import provenance                       # noqa: E402
import oob_write_verdict                # noqa: E402
import oob_index_write_verdict          # noqa: E402
import oob_read_verdict                 # noqa: E402
import oob_compare_verdict              # noqa: E402

RESOURCE_LABELS = {
    "resource_guard": "PRECISION_FIX_NOT_INTEGRATED",   # #41 not merged -- r04/r05 lineage only
    "oob_compare": "UNVALIDATED_PROPERTY",               # #33 -- no positive-path evidence yet
    "param_cap_r01": "DEVELOPMENT_ONLY",                 # #44 -- not validated (2 of 3 real sinks)
    "reachability": "REACHABILITY_UNRESOLVED",           # #32 not complete; promote_via_js_linkage unused
}

# -------------------------- resource ceilings (section 7) --------------------------
SCANNER_TIMEOUT = 300  # lock_balance/protected_field subprocess ceiling; oob_* scanners run
                        # in-process (no subprocess boundary to time out) -- see run_scanner_json.
MIN_FREE_DISK_GB = 5
MAX_WORKERS_CEILING = 2


def _free_disk_gb(path="/"):
    st = shutil.disk_usage(path)
    return st.free / (1024 ** 3)


def run_scanner_json(module, prefix, out_path):
    """Runs one of the four cpp_facts.json-based OOB scanners in-process (they expose
    emit_candidates() directly -- avoids four extra subprocess spawns per package) and writes
    its raw output to out_path in the same {"candidates": [...]} shape the CLI form writes,
    for evidence-bundle consistency."""
    cands = module.emit_candidates(prefix)
    with open(out_path, "w") as f:
        json.dump({"candidates": cands}, f)
    return cands


def enforce_diagnostic_only(record):
    """DIAGNOSTIC-ONLY MODE: forces reportable=False on every finding/candidate across all six
    properties' own keys, regardless of what provenance.py's own formula computed -- preserves
    scanner_candidate, raw verdict, all evidence, applicability_status, adjudication_status
    untouched. This is an ADDITIVE override applied AFTER provenance.enrich_record(), never a
    replacement for it -- the per-finding formula still runs and its result is still visible via
    every OTHER field; only reportable itself is forced. Also attaches the diagnostic labels."""
    all_keys = ("r04_findings", "r05_findings", "lock_balance_findings",
                "protected_field_findings", "oob_write_candidates",
                "oob_index_write_candidates", "oob_read_candidates", "oob_compare_candidates")
    for key in all_keys:
        for f in record.get(key) or []:
            if f.get("reportable"):
                f["reportable"] = False
                f["diagnostic_override"] = "FORCED_NON_REPORTABLE_diagnostic_only_run"
            elif "reportable" in f:
                f.setdefault("diagnostic_override", "ALREADY_NON_REPORTABLE")
            f["reachability_status"] = RESOURCE_LABELS["reachability"]

    for key in ("r04_findings", "r05_findings"):
        for f in record.get(key) or []:
            f["resource_guard_status"] = RESOURCE_LABELS["resource_guard"]

    for f in record.get("oob_compare_candidates") or []:
        f["property_status"] = RESOURCE_LABELS["oob_compare"]

    for f in record.get("oob_index_write_candidates") or []:
        src = ((f.get("derivation") or {}).get("capacity_source"))
        if src == "PARAM_LENGTH_PAIR":
            f["property_status"] = RESOURCE_LABELS["param_cap_r01"]

    return record


def preflight_assert_non_reportable(record):
    """Aborts the run (raises) if ANY finding in this record has reportable=True. Defense in
    depth: enforce_diagnostic_only() should already guarantee this, but this is the literal,
    independent preflight assertion required by direct instruction -- checked again, separately,
    right before every record is written to the output JSONL."""
    all_keys = ("r04_findings", "r05_findings", "lock_balance_findings",
                "protected_field_findings", "oob_write_candidates",
                "oob_index_write_candidates", "oob_read_candidates", "oob_compare_candidates")
    for key in all_keys:
        for f in record.get(key) or []:
            if f.get("reportable") is True:
                raise RuntimeError(
                    f"PREFLIGHT FAILURE: {record.get('package_name')}@{record.get('version')} "
                    f"has reportable=True in {key} -- diagnostic_only invariant violated, "
                    f"aborting run")


def run_one_diagnostic(pkg_name, version, tarball_url, source_tree_sha256_expected,
                        exception_config, work_root, bundle_dir):
    """Runs the real pipeline (P.run_one's own stages, reused) through provenance + r04/r05,
    THEN additively runs the five newly-wired scanners, enriches them too, enforces
    diagnostic-only, preflight-asserts, writes the evidence bundle, and returns the final
    record. Never modifies run_pipeline_one.py itself."""
    record = P.run_one(pkg_name, version, tarball_url, exception_config, work_root)
    record["diagnostic_only"] = True

    work = os.path.join(work_root, "work")
    cpp_raw = os.path.join(work, "cpp_raw")
    cpp_facts = os.path.join(work, "cpp_facts.json")

    if record.get("status") == "ANALYZED" and os.path.isdir(cpp_raw) and os.path.isfile(cpp_facts):
        # PROV-R01 fail-closed precondition already held for r04/r05 (via P.run_one); rebuild
        # the same manifest reference here for the five new scanners' own enrichment pass --
        # cheap (files still on disk, not re-hashed from network).
        try:
            prov_manifest = provenance.build_source_manifest(
                os.path.join(work_root, "pkg"),
                b"", pkg_name, version)  # tarball bytes already hashed once in P.run_one;
            # re-deriving purely for source_tree_sha256 continuity check below (cheap: files
            # already on disk). tarball_sha256 from THIS call is not used -- record["provenance_summary"]
            # already holds the real one P.run_one computed from the real tarball bytes.
        except Exception:
            prov_manifest = None

        pkg_dir = os.path.join(work_root, "pkg")
        new_scanner_stages = {}

        def _timed(name, fn):
            t0 = time.time()
            try:
                result = fn()
                new_scanner_stages[name] = {"seconds": time.time() - t0, "rc": 0}
                return result
            except Exception as e:
                new_scanner_stages[name] = {"seconds": time.time() - t0,
                                             "error": f"{type(e).__name__}: {e}"}
                return None

        # LOCK_BALANCE / PROTECTED_FIELD -- raw TSV dir input, CLI subprocess (matches r04/r05's
        # own convention exactly).
        import subprocess
        lb_out = os.path.join(work, "lock_balance_out.json")
        pf_out = os.path.join(work, "protected_field_out.json")

        def _run_lb():
            subprocess.run([sys.executable, f"{SCANNER_V2}/lock_balance_verdict.py",
                             cpp_raw, lb_out], check=True, timeout=SCANNER_TIMEOUT,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            with open(lb_out) as f:
                doc = json.load(f)
            record["lock_balance_classification"] = doc.get("classification", {})
            record["lock_balance_findings"] = doc.get("findings", [])

        def _run_pf():
            subprocess.run([sys.executable, f"{SCANNER_V2}/protected_field_verdict.py",
                             cpp_raw, pf_out], check=True, timeout=SCANNER_TIMEOUT,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            with open(pf_out) as f:
                doc = json.load(f)
            record["protected_field_classification"] = doc.get("classification", {})
            record["protected_field_findings"] = doc.get("findings", [])

        def _run_ow():
            cands = run_scanner_json(oob_write_verdict, cpp_facts,
                                      os.path.join(work, "oob_write_out.json"))
            record["oob_write_candidates"] = cands

        def _run_oiw():
            cands = run_scanner_json(oob_index_write_verdict, cpp_facts,
                                      os.path.join(work, "oob_index_write_out.json"))
            record["oob_index_write_candidates"] = cands

        def _run_or():
            cands = run_scanner_json(oob_read_verdict, cpp_facts,
                                      os.path.join(work, "oob_read_out.json"))
            record["oob_read_candidates"] = cands

        def _run_oc():
            cands = run_scanner_json(oob_compare_verdict, cpp_facts,
                                      os.path.join(work, "oob_compare_out.json"))
            record["oob_compare_candidates"] = cands

        _timed("lock_balance_scan", _run_lb)
        _timed("protected_field_scan", _run_pf)
        _timed("oob_write_scan", _run_ow)
        _timed("oob_index_write_scan", _run_oiw)
        _timed("oob_read_scan", _run_or)
        _timed("oob_compare_scan", _run_oc)
        record["stages"].update(new_scanner_stages)

        # PROV-R01 enrichment for the five newly-wired properties' own keys -- r04/r05 were
        # already enriched inside P.run_one(); enrich_record() silently skips whichever keys
        # aren't present, so calling it again here is safe and only adds the new keys' provenance.
        if prov_manifest is not None:
            # use the SAME manifest hashes P.run_one already recorded (real, from the real
            # tarball) rather than the placeholder computed above -- only files/paths matter for
            # per-finding enrichment; tree-level hashes come from record["provenance_summary"].
            prov_manifest["tarball_sha256"] = record.get("provenance_summary", {}).get("tarball_sha256")
            prov_manifest["source_tree_sha256"] = record.get("provenance_summary", {}).get("source_tree_sha256")
            provenance.enrich_record(record, cpp_raw, prov_manifest, pkg_dir)

    enforce_diagnostic_only(record)
    preflight_assert_non_reportable(record)

    # evidence bundle -- BEFORE work_root is deleted by the caller.
    bundle_path, manifest = evidence_bundle.write_evidence_bundle(
        work_root, bundle_dir, pkg_name, version,
        tarball_sha256=record.get("provenance_summary", {}).get("tarball_sha256"),
        pipeline_status=record.get("status"))
    record["evidence_bundle"] = {
        "path": bundle_path, "completeness_status": manifest.get("completeness_status"),
        "compressed_bytes": manifest.get("compressed_bytes"),
    }
    return record


# -------------------------- checkpointing (section 8) --------------------------

def load_completed_keys(output_path):
    """Resume key: (package_name, pinned_version, source_tree_sha256). Reads the existing
    working JSONL (if any), tolerating a trailing partial/corrupt line (the crash-recovery
    case) by dropping it rather than failing the whole load."""
    completed = {}
    if not os.path.isfile(output_path):
        return completed
    with open(output_path) as f:
        lines = f.readlines()
    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            if i == len(lines) - 1:
                print(f"[resume] last line of {output_path} is partial/corrupt -- dropped, "
                      f"not counted as completed", file=sys.stderr)
                continue
            raise RuntimeError(f"[resume] output JSONL has a corrupt line at {i+1} that is NOT "
                                f"the last line -- refusing to resume blindly") from None
        key = (rec.get("package_name"), rec.get("version"),
               rec.get("provenance_summary", {}).get("source_tree_sha256"))
        completed[key] = rec.get("status")
    return completed


def write_checkpoint(checkpoint_dir, n_done, rows_seen, status_counts, last_key):
    os.makedirs(checkpoint_dir, exist_ok=True)
    path = os.path.join(checkpoint_dir, f"checkpoint_{n_done:04d}.json")
    tmp = path + ".tmp"
    payload = {
        "n_done": n_done, "row_count": rows_seen,
        "status_distribution": dict(status_counts),
        "last_package_key": list(last_key) if last_key else None,
        "timestamp": time.time(),
    }
    payload["checksum"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode()).hexdigest()
    with open(tmp, "w") as f:
        json.dump(payload, f, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    return path


def load_sample(sample_path):
    rows = []
    with open(sample_path) as f:
        header = next(f).rstrip("\n").split("\t")
        idx = {n: i for i, n in enumerate(header)}
        for line in f:
            parts = line.rstrip("\n").split("\t")
            rows.append({name: (parts[i] if i < len(parts) else "") for name, i in idx.items()})
    return rows


def load_exception_configs():
    m = {}
    path = os.path.join(NPM_CORPUS, "npm_build_configuration.tsv")
    with open(path) as f:
        header = next(f).rstrip("\n").split("\t")
        idx = {n: i for i, n in enumerate(header)}
        for line in f:
            parts = line.rstrip("\n").split("\t")
            m[(parts[idx["package_name"]], parts[idx["version"]])] = \
                parts[idx["exception_configuration"]]
    return m


STOP_REASONS = []
_stop_lock = threading.Lock()

# In-flight (pkg_name, version, work_root, bundle_dir) tuples, updated by process_one --
# consulted by the SIGTERM/SIGINT handler below so a forced interruption still preserves
# whatever real evidence exists for the package(s) currently being processed, as a PARTIAL
# bundle, rather than losing it silently. "Preserve the current package's partial bundle and
# checkpoint before stopping" (section 10) -- a signal handler is the only way to run cleanup
# code at all once an external SIGTERM/SIGINT has been sent (a SIGKILL cannot be caught by
# anything, ever -- that limit is disclosed, not silently assumed away).
_in_flight = {}
_in_flight_lock = threading.Lock()


def request_stop(reason):
    with _stop_lock:
        STOP_REASONS.append(reason)
        print(f"[STOP CONDITION] {reason}", file=sys.stderr)


def _emergency_partial_bundle_handler(signum, frame):
    print(f"[SIGNAL {signum}] forced interruption -- writing emergency partial bundles for "
          f"in-flight work before exiting", file=sys.stderr)
    with _in_flight_lock:
        items = list(_in_flight.items())
    for (pkg, version), (work_root, bundle_dir) in items:
        try:
            bundle_path, manifest = evidence_bundle.write_evidence_bundle(
                work_root, bundle_dir, pkg, version, pipeline_status="INTERRUPTED")
            if bundle_path is None:
                print(f"  {pkg}@{version}: interrupted before any real evidence existed yet "
                      f"(no c2cpg/export output reached disk) -- nothing to bundle, no file "
                      f"written (correct, not an error)", file=sys.stderr)
            else:
                print(f"  {pkg}@{version}: emergency bundle written, "
                      f"completeness_status={manifest.get('completeness_status')}", file=sys.stderr)
        except Exception as e:
            print(f"  {pkg}@{version}: emergency bundle FAILED: {type(e).__name__}: {e}",
                  file=sys.stderr)
    sys.exit(143 if signum == 15 else 130)


def install_signal_handlers():
    import signal
    signal.signal(signal.SIGTERM, _emergency_partial_bundle_handler)
    signal.signal(signal.SIGINT, _emergency_partial_bundle_handler)


def main():
    install_signal_handlers()
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--bundle-dir", required=True)
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--diagnostic-only", action="store_true", required=True,
                     help="Required flag, always must be set -- this runner has no other mode.")
    ap.add_argument("--checkpoint-dir", default=None)
    ap.add_argument("--limit", type=int, default=None, help="For smoke testing: cap the number of packages run.")
    args = ap.parse_args()

    if not args.diagnostic_only:
        print("REFUSING to run without --diagnostic-only", file=sys.stderr)
        sys.exit(2)
    workers = min(args.workers, MAX_WORKERS_CEILING)
    checkpoint_dir = args.checkpoint_dir or (args.output + ".checkpoints")

    rows = load_sample(args.sample)
    if args.limit:
        rows = rows[: args.limit]
    exc_configs = load_exception_configs()

    completed = load_completed_keys(args.output) if args.resume else {}
    if completed:
        print(f"[resume] {len(completed)} packages already completed, skipping", file=sys.stderr)

    status_counts = {}
    for st in completed.values():
        status_counts[st] = status_counts.get(st, 0) + 1

    out_mode = "a" if (args.resume and os.path.isfile(args.output)) else "w"
    n_done_total = len(completed)
    last_key = None
    consecutive_same_stage_failures = 0
    last_failed_stage = None

    # written_keys tracks every key that will end up in the output file (pre-existing completed
    # ones, plus every one written this session) -- the single source of truth "refuse duplicate
    # completed package keys" checks against, so a duplicate is caught even if it were somehow
    # scheduled twice within the SAME session, not only against pre-existing resume state.
    written_keys = set(completed.keys())

    todo = []
    for row in rows:
        rkey = (row["package_name"], row["version"], row.get("source_tree_sha256"))
        if rkey in written_keys:
            if args.resume:
                continue  # already completed in a prior session -- skip, not an error
            raise RuntimeError(f"REFUSED: duplicate completed package key {rkey} -- rerun with "
                                f"--resume if this is intentional, or start from a clean output")
        todo.append(row)

    print(f"[plan] {len(todo)} package(s) to run this session ({n_done_total} already done)",
          file=sys.stderr)

    with open(args.output, out_mode) as out:
        def process_one(row, idx):
            nonlocal consecutive_same_stage_failures, last_failed_stage
            pkg = row["package_name"]
            version = row["version"]
            tarball_url = row["tarball_url"]
            expected_hash = row.get("source_tree_sha256")
            exc_config = exc_configs.get((pkg, version))
            work_root = f"/tmp/overnight100_work/{pkg.replace('/', '__')}@{version}"
            shutil.rmtree(work_root, ignore_errors=True)
            os.makedirs(work_root, exist_ok=True)

            free_gb = _free_disk_gb()
            if free_gb < MIN_FREE_DISK_GB:
                request_stop(f"free disk {free_gb:.1f}GB < {MIN_FREE_DISK_GB}GB before starting "
                              f"{pkg}@{version}")
                return None

            with _in_flight_lock:
                _in_flight[(pkg, version)] = (work_root, args.__dict__["bundle_dir"])
            t0 = time.time()
            try:
                rec = run_one_diagnostic(pkg, version, tarball_url, expected_hash, exc_config,
                                          work_root, args.__dict__["bundle_dir"])
            except Exception as e:
                rec = {"package_name": pkg, "version": version, "status": "RUNNER_ERROR",
                       "detail": f"{type(e).__name__}: {e}",
                       "traceback": traceback.format_exc(), "diagnostic_only": True}
            finally:
                with _in_flight_lock:
                    _in_flight.pop((pkg, version), None)
            rec["total_seconds"] = time.time() - t0
            shutil.rmtree(work_root, ignore_errors=True)
            return rec

        def results_stream():
            """Yields each package's record AS SOON AS IT COMPLETES (not batched), so every
            downstream step -- flush/fsync, checkpointing, stop-condition checks -- happens
            incrementally during the run, exactly as required, regardless of worker count."""
            if workers <= 1:
                for i, row in enumerate(todo):
                    with _stop_lock:
                        if STOP_REASONS:
                            return
                    yield process_one(row, i)
                return
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                futures = {}
                todo_iter = iter(enumerate(todo))
                # bounded submission window (== workers) so a stop request doesn't leave a
                # large backlog of already-submitted, hard-to-cancel work in flight.
                for _ in range(workers):
                    try:
                        i, row = next(todo_iter)
                    except StopIteration:
                        break
                    futures[ex.submit(process_one, row, i)] = (i, row)
                while futures:
                    done, _ = concurrent.futures.wait(
                        futures, return_when=concurrent.futures.FIRST_COMPLETED)
                    for fut in done:
                        futures.pop(fut)
                        yield fut.result()
                    with _stop_lock:
                        if STOP_REASONS:
                            continue  # drain in-flight futures, submit no more
                    try:
                        i, row = next(todo_iter)
                        futures[ex.submit(process_one, row, i)] = (i, row)
                    except StopIteration:
                        pass

        for rec in results_stream():
            if rec is None:
                break
            preflight_assert_non_reportable(rec)  # re-check post any concurrent path too

            this_key = (rec.get("package_name"), rec.get("version"),
                        rec.get("provenance_summary", {}).get("source_tree_sha256"))
            if this_key in written_keys:
                raise RuntimeError(f"REFUSED: duplicate completed package key {this_key} -- "
                                    f"already written earlier this session")
            written_keys.add(this_key)

            out.write(json.dumps(rec) + "\n")
            out.flush()
            os.fsync(out.fileno())

            n_done_total += 1
            status_counts[rec.get("status")] = status_counts.get(rec.get("status"), 0) + 1
            last_key = this_key

            stage_failed = None
            if rec.get("status") not in ("ANALYZED",):
                # best-effort: name the failing stage from the detail text / stages dict
                stages = rec.get("stages", {})
                for sname, sinfo in reversed(list(stages.items())):
                    if isinstance(sinfo, dict) and (sinfo.get("rc") not in (0, None) or "error" in sinfo):
                        stage_failed = sname
                        break
                stage_failed = stage_failed or rec.get("status")
            if stage_failed and stage_failed == last_failed_stage:
                consecutive_same_stage_failures += 1
            else:
                consecutive_same_stage_failures = 1 if stage_failed else 0
            last_failed_stage = stage_failed

            print(f"[{n_done_total}] {rec.get('package_name')}@{rec.get('version')}: "
                  f"{rec.get('status')} ({rec.get('total_seconds', 0):.1f}s)", file=sys.stderr)

            if n_done_total % 10 == 0:
                write_checkpoint(checkpoint_dir, n_done_total, n_done_total, status_counts, last_key)

            if consecutive_same_stage_failures > 3:
                request_stop(f"more than 3 consecutive packages failed at the same stage "
                              f"({last_failed_stage})")
            if _free_disk_gb() < MIN_FREE_DISK_GB:
                request_stop(f"free disk below {MIN_FREE_DISK_GB}GB after {rec.get('package_name')}")

            with _stop_lock:
                if STOP_REASONS:
                    print(f"[STOPPING] {STOP_REASONS[-1]}", file=sys.stderr)
                    write_checkpoint(checkpoint_dir, n_done_total, n_done_total, status_counts, last_key)
                    return

    write_checkpoint(checkpoint_dir, n_done_total, n_done_total, status_counts, last_key)
    print(f"[done] {n_done_total} package(s) recorded. status_distribution={status_counts}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
