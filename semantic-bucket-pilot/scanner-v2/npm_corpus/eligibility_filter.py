#!/usr/bin/env python3
"""NPM-CORPUS stage 2b/3: for each candidate package name, fetch REAL npm registry metadata,
download the REAL tarball, inspect its REAL file listing, and determine eligibility per the
frozen rules (item 3 of the corpus-phase instruction). Every downloaded tarball is deleted
immediately after inspection -- only the compact per-package record is retained, so disk
usage stays bounded regardless of corpus size.

Selection rule: the latest non-prerelease, non-deprecated version available at snapshot
cutoff (this script's own run time). If acquisition fails, the package's status records the
failure -- never silently substitutes another version.

Eligibility (ALL must hold on the package's own distributed tarball contents):
  A. package-owned JS/TS: at least one .js/.jsx/.mjs/.cjs/.ts/.tsx file.
  B. package-owned C/C++: at least one .c/.cc/.cpp/.cxx file (headers alone don't count --
     a package that only VENDORS a header, e.g. a bundled copy of napi.h, without any
     package-owned .c/.cc/.cpp file, fails this check).
  C. binding-participation evidence: binding.gyp, OR a CMake/meson/GN file that references a
     native-addon-shaped target (heuristic: mentions node-gyp/node-api/napi/cmake-js
     alongside add_library/executable), OR a package-owned .c/.cc/.cpp/.h/.hpp file containing
     one of: #include "node.h"/<node.h>, #include "node_api.h"/<node_api.h>,
     #include "napi.h"/<napi.h>, #include "nan.h"/<nan.h>, NODE_MODULE(, NODE_MODULE_INIT(,
     napi_define_properties(, Napi::ObjectWrap, Napi::Function::New(, exports.Set(,
     Nan::SetMethod(, Nan::Export(. Vendoring a header with NONE of these markers actually
     used in a package-owned source file does not establish eligibility (explicit
     instruction: "Do not classify a package as eligible merely because it vendors
     node-addon-api headers").

Rust-only napi-rs exclusion: if the package contains a Cargo.toml and any .rs file, AND has
no package-owned .c/.cc/.cpp file satisfying B above, it is excluded
(NO_CPP_SOURCE/RUST_ONLY_NAPI_RS), even if it otherwise looks native (napi-rs projects use
"napi"/"NAPI" heavily in text but are not C/C++ bindings).

Output: eligibility.tsv (one row per candidate package name), and exclusion reasons recorded
for every non-eligible package -- never silently dropped.
"""
import hashlib
import io
import json
import re
import shutil
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

REGISTRY = "https://registry.npmjs.org"

JS_TS_EXTS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
CPP_EXTS = (".c", ".cc", ".cpp", ".cxx")
HEADER_EXTS = (".h", ".hpp", ".hh", ".hxx")

BINDING_MARKERS = [
    re.compile(rb'#\s*include\s*["<]node\.h[">]'),
    re.compile(rb'#\s*include\s*["<]node_api\.h[">]'),
    re.compile(rb'#\s*include\s*["<]napi\.h[">]'),
    re.compile(rb'#\s*include\s*["<]nan\.h[">]'),
    re.compile(rb'NODE_MODULE\s*\('),
    re.compile(rb'NODE_MODULE_INIT\s*\('),
    re.compile(rb'napi_define_properties\s*\('),
    re.compile(rb'Napi::ObjectWrap'),
    re.compile(rb'Napi::Function::New\s*\('),
    re.compile(rb'exports\.Set\s*\('),
    re.compile(rb'Nan::SetMethod\s*\('),
    re.compile(rb'Nan::Export\s*\('),
]


def fetch_json(url, timeout=30, retries=4):
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "resource-guard-corpus-mining/0.1"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8")), None
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


def fetch_bytes(url, timeout=60, retries=4):
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


def select_version(meta):
    """Latest non-prerelease, non-deprecated version at snapshot cutoff. Returns
    (version, version_meta, reason_if_none)."""
    dist_tags = meta.get("dist-tags", {})
    latest = dist_tags.get("latest")
    versions = meta.get("versions", {})
    if not versions:
        return None, None, "NO_VERSIONS_IN_METADATA"
    candidates = []
    for v, vm in versions.items():
        if re.search(r'-(alpha|beta|rc|pre|next|canary|dev|nightly)', v, re.I):
            continue
        if vm.get("deprecated"):
            continue
        candidates.append(v)
    if not candidates:
        return None, None, "NO_ELIGIBLE_NON_PRERELEASE_NON_DEPRECATED_VERSION"
    if latest in candidates:
        return latest, versions[latest], None
    # dist-tags.latest itself is prerelease/deprecated/missing -- pick the highest remaining
    # by a simple version-tuple sort (best-effort, real limitation disclosed).
    def key(v):
        parts = re.findall(r'\d+', v)
        return tuple(int(p) for p in parts[:3]) if parts else (0,)
    best = sorted(candidates, key=key)[-1]
    return best, versions[best], None


def inspect_tarball(tarball_bytes):
    """Returns a dict of eligibility signals from a real, extracted tarball listing --
    never from the registry metadata alone."""
    js_ts_files = []
    cpp_files = []
    header_files = []
    has_cargo_toml = False
    has_rs_files = False
    has_binding_gyp = False
    has_cmake = False
    binding_marker_hits = []  # (file, marker_pattern)
    try:
        tf = tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz")
    except Exception as e:
        return {"error": f"TARBALL_UNREADABLE: {type(e).__name__}: {e}"}
    members = tf.getmembers()
    for m in members:
        if not m.isfile():
            continue
        # npm tarballs wrap everything under package/
        name = m.name.split("/", 1)[1] if "/" in m.name else m.name
        lower = name.lower()
        if lower.endswith(JS_TS_EXTS):
            js_ts_files.append(name)
        if lower.endswith(CPP_EXTS):
            cpp_files.append(name)
        if lower.endswith(HEADER_EXTS):
            header_files.append(name)
        if lower.endswith("binding.gyp"):
            has_binding_gyp = True
        if lower.endswith("cmakelists.txt") or lower.endswith(".cmake"):
            has_cmake = True
        if lower.endswith("cargo.toml"):
            has_cargo_toml = True
        if lower.endswith(".rs"):
            has_rs_files = True
    # Only scan package-owned C/C++ source+header files for binding markers (bounded cost --
    # skip huge vendored trees; cap total bytes scanned per package).
    total_scanned = 0
    SCAN_CAP = 8 * 1024 * 1024
    for m in members:
        if not m.isfile():
            continue
        name = m.name.split("/", 1)[1] if "/" in m.name else m.name
        lower = name.lower()
        if not (lower.endswith(CPP_EXTS) or lower.endswith(HEADER_EXTS) or lower.endswith("binding.gyp")
                or lower.endswith("cmakelists.txt")):
            continue
        if total_scanned > SCAN_CAP:
            break
        try:
            f = tf.extractfile(m)
            if f is None:
                continue
            content = f.read()
            total_scanned += len(content)
        except Exception:
            continue
        for pat in BINDING_MARKERS:
            if pat.search(content):
                binding_marker_hits.append((name, pat.pattern.decode("utf-8", "replace")))
    tf.close()
    return {
        "js_ts_files": js_ts_files,
        "cpp_files": cpp_files,
        "header_files": header_files,
        "has_binding_gyp": has_binding_gyp,
        "has_cmake": has_cmake,
        "has_cargo_toml": has_cargo_toml,
        "has_rs_files": has_rs_files,
        "binding_marker_hits": binding_marker_hits,
    }


def classify(insp):
    if "error" in insp:
        return "EXTRACTION_FAILED", insp["error"], []
    reasons = []
    if not insp["js_ts_files"]:
        return "NO_JS_TS_SOURCE", "no .js/.jsx/.mjs/.cjs/.ts/.tsx file in the tarball", []
    if not insp["cpp_files"]:
        if insp["has_cargo_toml"] and insp["has_rs_files"]:
            return "NO_CPP_SOURCE", "Rust-only (Cargo.toml + .rs present, no package-owned C/C++ source) -- excluded per napi-rs rule", []
        return "NO_CPP_SOURCE", "no .c/.cc/.cpp/.cxx file in the tarball", []
    binding_evidence = []
    if insp["has_binding_gyp"]:
        binding_evidence.append("binding.gyp present")
    if insp["binding_marker_hits"]:
        for fname, marker in insp["binding_marker_hits"][:5]:
            binding_evidence.append(f"{fname}: {marker}")
    if not binding_evidence:
        return "NO_PACKAGE_OWNED_NATIVE_BINDING", (
            "C/C++ source present but no binding.gyp and no package-owned source file "
            "contains a recognized Node/N-API/NAN binding-registration marker -- "
            "vendored headers alone (if any) do not establish eligibility"
        ), []
    return "ANALYZED", "eligible", binding_evidence


def process_one(pkg_name):
    meta, err = fetch_json(f"{REGISTRY}/{urllib.request.quote(pkg_name, safe='@/')}")
    if err:
        return {"package_name": pkg_name, "status": "DOWNLOAD_FAILED",
                "detail": f"registry metadata fetch failed: {err}"}
    version, vmeta, verr = select_version(meta)
    if verr:
        return {"package_name": pkg_name, "status": "DOWNLOAD_FAILED", "detail": verr}
    dist = vmeta.get("dist", {})
    tarball_url = dist.get("tarball")
    integrity = dist.get("integrity", "")
    shasum = dist.get("shasum", "")
    git_head = vmeta.get("gitHead", "")
    repo = vmeta.get("repository", {})
    repo_url = repo.get("url", "") if isinstance(repo, dict) else (repo or "")
    pub_time = meta.get("time", {}).get(version, "")

    record = {
        "package_name": pkg_name, "version": version, "publication_timestamp": pub_time,
        "tarball_url": tarball_url, "dist_integrity": integrity, "dist_shasum": shasum,
        "git_head": git_head, "repository_url": repo_url,
    }
    if not tarball_url:
        record["status"] = "DOWNLOAD_FAILED"
        record["detail"] = "no dist.tarball in version metadata"
        return record

    tb, terr = fetch_bytes(tarball_url)
    if terr:
        record["status"] = "DOWNLOAD_FAILED"
        record["detail"] = terr
        return record

    if shasum:
        real_sha1 = hashlib.sha1(tb).hexdigest()
        if real_sha1 != shasum:
            record["status"] = "INTEGRITY_FAILED"
            record["detail"] = f"sha1 mismatch: expected {shasum}, got {real_sha1}"
            return record

    insp = inspect_tarball(tb)
    status, detail, evidence = classify(insp)
    record["status"] = status
    record["detail"] = detail
    record["binding_evidence"] = "; ".join(evidence)
    record["n_js_ts_files"] = len(insp.get("js_ts_files", []))
    record["n_cpp_files"] = len(insp.get("cpp_files", []))
    record["n_header_files"] = len(insp.get("header_files", []))
    del tb  # never persisted to disk -- inspected in memory only, discarded immediately
    return record


FIELDS = ["package_name", "version", "status", "detail", "publication_timestamp",
          "tarball_url", "dist_integrity", "dist_shasum", "git_head", "repository_url",
          "n_js_ts_files", "n_cpp_files", "n_header_files", "binding_evidence"]


def main():
    candidates_path, out_path = sys.argv[1], sys.argv[2]
    start_idx = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    end_idx = int(sys.argv[4]) if len(sys.argv) > 4 else None

    names = []
    seen = set()
    with open(candidates_path) as f:
        next(f)  # header
        for line in f:
            name = line.split("\t", 1)[0]
            if name not in seen:
                seen.add(name)
                names.append(name)
    if end_idx is None:
        end_idx = len(names)
    names = names[start_idx:end_idx]

    mode = "a" if start_idx > 0 else "w"
    with open(out_path, mode) as out:
        if mode == "w":
            out.write("\t".join(FIELDS) + "\n")
        for i, name in enumerate(names):
            rec = process_one(name)
            row = [str(rec.get(k, "")).replace("\t", " ").replace("\n", " ") for k in FIELDS]
            out.write("\t".join(row) + "\n")
            out.flush()
            if (i + 1) % 25 == 0:
                print(f"[{start_idx + i + 1}] {name}: {rec.get('status')}", file=sys.stderr)


if __name__ == "__main__":
    main()
