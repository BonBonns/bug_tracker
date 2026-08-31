#!/usr/bin/env python3
"""NAN-PREVALENCE-STUDY step 1: corpus-wide textual prevalence census of Buffer-allocation
contract families, across all 494 eligible packages (the same population R05/R06 already
established has real native C++ source -- see eligible_packages.tsv).

This is READ-ONLY against the scanner: it does not touch resource_guard_verdict_r05.py,
resource_guard_verdict_r06.py, promote_via_js_linkage.py, any contract table, exporter, or
normalizer, and it does not write into full_scan_r05_working.jsonl or any live-scan artifact.
It re-downloads each package's own pinned tarball (same tarball_url/shasum eligible_packages.tsv
already recorded from the live scan) into a throwaway temp dir, greps the real extracted source,
and deletes the extraction immediately -- bounded disk, same discipline as run_pipeline_one.py's
own per-package cleanup.

Disclosed method limitation (stated up front, not discovered later): this is a TEXTUAL regex
census, not a CPG-verified one. R05 itself resolves call identity via Joern's type system, not
text matching. A regex over raw source can:
  - false-positive on a call name that appears inside a comment, a string literal, or disabled
    `#if 0` code (this script does NOT strip comments/strings -- explicitly disclosed, not
    silently ignored)
  - false-negative on a call written across an unusual line break the regex doesn't anticipate,
    or reached only through a macro/typedef alias
This script's output is therefore a PREVALENCE SIGNAL for deciding which capability to build
next, not a claim of exact real call-site counts. Every site that ends up cited in the study's
writeup as evidence for a specific package is separately confirmed by direct source reading
(the same discipline as R05_INTERIM_NEAR_MISS_AUDIT.md), using the context this script captures.

Families (all "New"/"Copy"-shaped Buffer-allocation entry points, matching the exact scope the
user asked this census to cover -- NOT a general native-call census):
  NAPI_BUFFER_NEW   -- Napi::Buffer<T>::New(...)              (node-addon-api; R05's own family)
  NAN_NEWBUFFER     -- Nan::NewBuffer(...)
  NAN_COPYBUFFER    -- Nan::CopyBuffer(...)
  RAW_NAPI_BUFFER   -- napi_create_buffer / napi_create_buffer_copy / napi_create_external_buffer
  V8_NODE_BUFFER    -- node::Buffer::New(...) / v8::ArrayBuffer::New(...)
  BARE_BUFFER_NEW   -- unqualified Buffer::New(...) / Buffer::Copy(...) (catches `using namespace
                       Napi;` / `using v8::Buffer;` call sites the qualified regexes above miss --
                       recorded separately since namespace is NOT resolved from text alone)

Output: nan_prevalence_hits.tsv (one row per real regex match, with a stored context window for
later manual origin-classification reading) and nan_prevalence_failures.tsv (download/extract
failures, so package-count denominators stay honest).
"""
import csv
import io
import os
import re
import shutil
import sys
import tarfile
import time
import urllib.error
import urllib.request

CORPUS_DIR = "/home/user/bug_tracker/semantic-bucket-pilot/scanner-v2/npm_corpus"
ELIGIBLE_TSV = os.path.join(CORPUS_DIR, "eligible_packages.tsv")
WORK_ROOT = "/tmp/prevalence_work"
OUT_DIR = os.path.dirname(os.path.abspath(__file__))
HITS_TSV = os.path.join(OUT_DIR, "nan_prevalence_hits.tsv")
FAILURES_TSV = os.path.join(OUT_DIR, "nan_prevalence_failures.tsv")

CPP_EXTS = (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx")
CONTEXT_LINES = 12

# Real, confirmed-by-inspection issue found while smoke-testing this script on node-addon-api
# itself: that package's own tarball vendors napi-inl.h, whose `template <typename T> inline
# Buffer<T> Buffer<T>::New(...)` is the DEFINITION of the contract, not a consumer's CALL site.
# Every other family has the same shape risk if a package happens to vendor nan's own headers
# directly instead of resolving `#include <nan.h>` from node_modules (the pipeline's own
# HDR-FIX comment confirms this is NOT the corpus norm, but a small number of old packages do
# vendor a private copy). Filtering these exact, well-known library-interface filenames is a
# precise, disclosed heuristic -- NOT a general comment/string stripper (see module docstring) --
# so a hit inside one of these basenames is excluded as "library definition", not "consumer call".
EXCLUDED_LIBRARY_HEADER_BASENAMES = {
    # node-addon-api (napi.h itself has no Buffer::New body, but exclude both for safety)
    "napi.h", "napi-inl.h", "napi-inl.deprecated.h",
    # nan (v2.x real header layout)
    "nan.h", "nan_callbacks.h", "nan_callbacks_12_inl.h", "nan_converters.h",
    "nan_converters_43_inl.h", "nan_define_own_property_helper.h", "nan_implementation_12_inl.h",
    "nan_json.h", "nan_maybe_43_inl.h", "nan_new.h", "nan_object_wrap.h",
    "nan_persistent_12_inl.h", "nan_private.h", "nan_string_bytes.h",
    "nan_typedarray_contents.h", "nan_weak.h",
}

FAMILY_PATTERNS = [
    ("NAPI_BUFFER_NEW", re.compile(r"Napi::Buffer\s*<[^>;{}]*>\s*::\s*New\s*\(")),
    ("NAN_NEWBUFFER", re.compile(r"Nan::NewBuffer\s*\(")),
    ("NAN_COPYBUFFER", re.compile(r"Nan::CopyBuffer\s*\(")),
    ("RAW_NAPI_BUFFER", re.compile(r"\bnapi_create_(external_)?buffer(_copy)?\s*\(")),
    ("V8_NODE_BUFFER", re.compile(r"\b(node::Buffer::New|v8::ArrayBuffer::New)\s*\(")),
    ("BARE_BUFFER_NEW", re.compile(r"(?<!Napi::)(?<!Nan::)(?<!::)\bBuffer\s*(<[^>;{}]*>)?\s*::\s*(New|Copy)\s*\(")),
]


def fetch_bytes(url, timeout=60, retries=3):
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "resource-guard-corpus-mining/0.1"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read(), None
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < retries - 1:
                time.sleep(2 ** attempt * 2)
                continue
            return None, f"HTTPError {e.code}: {e}"
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(1)
                continue
            return None, f"{type(e).__name__}: {e}"
    return None, "exhausted retries"


def scan_package(pkg_name, version, tarball_url, pkg_dir):
    tb, err = fetch_bytes(tarball_url)
    if err:
        return None, f"download failed: {err}"
    try:
        tf = tarfile.open(fileobj=io.BytesIO(tb), mode="r:gz")
        tf.extractall(pkg_dir, filter="data")
        tf.close()
    except Exception as e:
        return None, f"extract failed: {type(e).__name__}: {e}"

    hits = []
    for root, _dirs, files in os.walk(pkg_dir):
        for fn in files:
            if not fn.endswith(CPP_EXTS):
                continue
            if fn in EXCLUDED_LIBRARY_HEADER_BASENAMES:
                continue
            fpath = os.path.join(root, fn)
            rel = os.path.relpath(fpath, pkg_dir)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except Exception:
                continue
            lines = text.split("\n")
            # precompute line-start offsets for match->line-number mapping
            offsets = [0]
            for ln in lines:
                offsets.append(offsets[-1] + len(ln) + 1)
            for family, pattern in FAMILY_PATTERNS:
                for m in pattern.finditer(text):
                    # line number via bisect over offsets
                    lo, hi = 0, len(offsets) - 1
                    pos = m.start()
                    while lo < hi:
                        mid = (lo + hi) // 2
                        if offsets[mid + 1] <= pos:
                            lo = mid + 1
                        else:
                            hi = mid
                    line_no = lo + 1
                    ctx_start = max(0, line_no - 1 - CONTEXT_LINES)
                    ctx_end = min(len(lines), line_no + CONTEXT_LINES)
                    context = "\n".join(lines[ctx_start:ctx_end])
                    hits.append({
                        "package_name": pkg_name, "version": version, "family": family,
                        "file": rel, "line": line_no,
                        "matched_text": m.group(0),
                        "context": context,
                    })
    return hits, None


def main():
    with open(ELIGIBLE_TSV, newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        packages = [(row["package_name"], row["version"], row["tarball_url"])
                    for row in reader]

    print(f"loaded {len(packages)} eligible packages", file=sys.stderr)

    os.makedirs(WORK_ROOT, exist_ok=True)
    hit_rows = []
    failure_rows = []

    resume_from = 0
    if os.path.exists(HITS_TSV) and os.path.exists(os.path.join(OUT_DIR, "PROGRESS.txt")):
        with open(os.path.join(OUT_DIR, "PROGRESS.txt")) as f:
            resume_from = int(f.read().strip())
        print(f"resuming from index {resume_from}", file=sys.stderr)

    hits_mode = "a" if resume_from else "w"
    fail_mode = "a" if resume_from else "w"
    hits_f = open(HITS_TSV, hits_mode, newline="")
    fail_f = open(FAILURES_TSV, fail_mode, newline="")
    hit_writer = csv.DictWriter(hits_f, fieldnames=[
        "package_name", "version", "family", "file", "line", "matched_text", "context"],
        delimiter="\t")
    fail_writer = csv.DictWriter(fail_f, fieldnames=["package_name", "version", "reason"],
                                  delimiter="\t")
    if not resume_from:
        hit_writer.writeheader()
        fail_writer.writeheader()

    t_start = time.time()
    for i, (pkg_name, version, tarball_url) in enumerate(packages):
        if i < resume_from:
            continue
        pkg_dir = os.path.join(WORK_ROOT, "pkg")
        if os.path.exists(pkg_dir):
            shutil.rmtree(pkg_dir, ignore_errors=True)
        os.makedirs(pkg_dir, exist_ok=True)
        hits, err = scan_package(pkg_name, version, tarball_url, pkg_dir)
        if err:
            fail_writer.writerow({"package_name": pkg_name, "version": version, "reason": err})
            fail_f.flush()
        else:
            for h in hits:
                hit_writer.writerow(h)
            hits_f.flush()
        shutil.rmtree(pkg_dir, ignore_errors=True)
        with open(os.path.join(OUT_DIR, "PROGRESS.txt"), "w") as f:
            f.write(str(i + 1))
        if (i + 1) % 25 == 0 or i == len(packages) - 1:
            elapsed = time.time() - t_start
            print(f"[{i+1}/{len(packages)}] elapsed={elapsed:.0f}s", file=sys.stderr)

    hits_f.close()
    fail_f.close()
    print("done", file=sys.stderr)


if __name__ == "__main__":
    main()
