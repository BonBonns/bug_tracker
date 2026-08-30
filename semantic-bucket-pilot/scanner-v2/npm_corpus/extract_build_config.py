#!/usr/bin/env python3
"""NPM-CORPUS stage 5: automatic build-configuration evidence extraction (item 5). For each
eligible package, re-fetches the real tarball and inspects real binding.gyp, CMakeLists.txt/
*.cmake, meson.build, GN (*.gn/*.gni) files, and package.json (scripts/gypfile/binary fields)
for real, textual exception-configuration evidence.

Classification (never inferred from the absence of try/catch in source -- that signal has no
bearing on the actual compiled build configuration, confirmed by R02/R03's own
r02c10_exceptions_enabled_try_catch control):

  disabled  -- NAPI_DISABLE_CPP_EXCEPTIONS and/or -fno-exceptions found, no enabling
               counter-evidence.
  enabled   -- NAPI_CPP_EXCEPTIONS (not the DISABLE_ variant) and/or an explicit -fexceptions
               flag found, no disabling counter-evidence.
  conflict  -- both disabling and enabling evidence found in the same package's build config.
  unresolved -- no direct textual evidence either way. This is the SAFE DEFAULT: an automatic,
               bulk, per-package scan does not attempt the kind of one-off, manually-verified
               default-resolution reasoning RESOURCE_GUARD_R04.md applied to jpeg-turbo
               (checking node-addon-api's own napi.h default-resolution logic AND the absence
               of any compiler-level exception-disabling flag) -- that was deliberate, disclosed,
               manual investigative work on ONE real site, not a rule this automatic stage
               applies to hundreds of packages without individual verification.

Output: npm_build_configuration.tsv -- one row per eligible package: exception_configuration,
the real evidence strings found (file + matched pattern, bounded to the first 5), and which
config file family supplied the evidence (binding.gyp / cmake / meson / gn / package.json /
none).
"""
import io
import re
import sys
import tarfile
import time
import urllib.error
import urllib.request

DISABLE_PATTERNS = [
    (re.compile(rb'NAPI_DISABLE_CPP_EXCEPTIONS'), "NAPI_DISABLE_CPP_EXCEPTIONS"),
    (re.compile(rb'-fno-exceptions'), "-fno-exceptions"),
]
ENABLE_PATTERNS = [
    (re.compile(rb'(?<!DISABLE_)NAPI_CPP_EXCEPTIONS'), "NAPI_CPP_EXCEPTIONS"),
    (re.compile(rb'(?<!-fno)-fexceptions'), "-fexceptions"),
]

CONFIG_FILE_SUFFIXES = {
    "binding.gyp": "binding.gyp",
    "cmakelists.txt": "cmake",
    ".cmake": "cmake",
    "meson.build": "meson",
    ".gn": "gn",
    ".gni": "gn",
    "package.json": "package.json",
}


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


def classify_from_tarball(tarball_bytes):
    try:
        tf = tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz")
    except Exception as e:
        return {"error": f"TARBALL_UNREADABLE: {type(e).__name__}: {e}"}

    disable_evidence = []
    enable_evidence = []
    families = set()
    for m in tf.getmembers():
        if not m.isfile():
            continue
        name = m.name.split("/", 1)[1] if "/" in m.name else m.name
        lower = name.lower()
        family = None
        for suffix, fam in CONFIG_FILE_SUFFIXES.items():
            if lower.endswith(suffix):
                family = fam
                break
        if family is None:
            continue
        f = tf.extractfile(m)
        if f is None:
            continue
        try:
            content = f.read()
        except Exception:
            continue
        families.add(family)
        for pat, label in DISABLE_PATTERNS:
            if pat.search(content):
                disable_evidence.append(f"{name}: {label}")
        for pat, label in ENABLE_PATTERNS:
            if pat.search(content):
                enable_evidence.append(f"{name}: {label}")
    tf.close()

    if disable_evidence and enable_evidence:
        exc_config = "conflict"
    elif disable_evidence:
        exc_config = "disabled"
    elif enable_evidence:
        exc_config = "enabled"
    else:
        exc_config = "unresolved"

    return {
        "exception_configuration": exc_config,
        "disable_evidence": "; ".join(disable_evidence[:5]),
        "enable_evidence": "; ".join(enable_evidence[:5]),
        "config_file_families": ";".join(sorted(families)),
    }


def main():
    eligible_path = sys.argv[1] if len(sys.argv) > 1 else "eligible_packages.tsv"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "npm_build_configuration.tsv"

    rows = []
    with open(eligible_path) as f:
        header = next(f).rstrip("\n").split("\t")
        idx = {name: i for i, name in enumerate(header)}
        for line in f:
            parts = line.rstrip("\n").split("\t")
            rows.append(parts)

    fields = ["package_name", "version", "exception_configuration", "disable_evidence",
              "enable_evidence", "config_file_families", "status", "detail"]
    with open(out_path, "w") as out:
        out.write("\t".join(fields) + "\n")
        for i, parts in enumerate(rows):
            pkg = parts[idx["package_name"]]
            version = parts[idx["version"]]
            tarball_url = parts[idx["tarball_url"]]
            tb, err = fetch_bytes(tarball_url)
            if err:
                out.write("\t".join([pkg, version, "unresolved", "", "", "", "REFETCH_FAILED", err]) + "\n")
                out.flush()
                continue
            r = classify_from_tarball(tb)
            if "error" in r:
                out.write("\t".join([pkg, version, "unresolved", "", "", "", "EXTRACTION_FAILED", r["error"]]) + "\n")
                out.flush()
                continue
            row = [pkg, version, r["exception_configuration"], r["disable_evidence"],
                   r["enable_evidence"], r["config_file_families"], "OK", ""]
            out.write("\t".join(row) + "\n")
            out.flush()
            if (i + 1) % 25 == 0:
                print(f"[{i + 1}/{len(rows)}] {pkg}@{version}: {r['exception_configuration']}",
                      file=sys.stderr)


if __name__ == "__main__":
    main()
