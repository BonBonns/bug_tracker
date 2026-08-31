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
  enabled   -- NAPI_CPP_EXCEPTIONS (not the DISABLE_ variant), an explicit -fexceptions flag,
               or a real `node_addon_api_except`/`node_addon_api_except_all` gyp target
               dependency found, no disabling counter-evidence.
  conflict  -- both disabling and enabling evidence found in the same package's build config.

REGRESSION FIX (node-libcurl@5.1.2 -- see study/resource_guard_r05/
NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md for the full real account): two real, corpus-wide
defects found and fixed here, both confirmed via direct manual verification against the
real published tarball, not assumed:

1. A flat text search cannot see gyp's own `<key>!` list-REMOVAL convention (e.g.
   `'cflags!': ['-fno-exceptions']`, node-addon-api's own canonical `except.gypi` idiom,
   copied inline by node-libcurl's own binding.gyp) -- a `-fno-exceptions` match INSIDE
   such a removal list means the flag is being STRIPPED, i.e. exceptions ARE allowed, the
   OPPOSITE of ordinary disable evidence. `_gyp_removal_spans()`/`_in_any_span()` detect
   this and invert polarity only for matches genuinely inside a `<key>!` list body.
2. A package can enable exceptions purely via node-addon-api's own gyp target-name
   convention (depending on `node_addon_api_except`/`node_addon_api_except_all`) without
   the literal text "NAPI_CPP_EXCEPTIONS" ever appearing in the package's OWN binding.gyp
   at all -- added as a new, high-confidence enable pattern.
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
    # REGRESSION FIX (node-libcurl@5.1.2, see study/resource_guard_r05/
    # NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md for the full real account): the real,
    # documented node-addon-api gyp target-name convention
    # (https://github.com/nodejs/node-addon-api/blob/main/doc/setup.md) -- depending on
    # the `node_addon_api_except`/`node_addon_api_except_all` target is real,
    # high-confidence enable evidence even when the literal text "NAPI_CPP_EXCEPTIONS"
    # never appears anywhere in the PACKAGE's own binding.gyp. Confirmed real by
    # directly reading node-addon-api 8.5.0's own `node_addon_api.gyp`: both targets
    # `includes: ['except.gypi']`, which itself `'defines': ['NAPI_CPP_EXCEPTIONS']` --
    # a real, multi-hop, externally-verified chain, not assumed. Matched as a real gyp
    # `dependencies` entry, e.g. `"<!(node -p \"require('node-addon-api').targets\"):
    # node_addon_api_except"` -- node-libcurl's own real, exact usage.
    (re.compile(rb'node_addon_api_except'), "node_addon_api_except (gyp target dependency)"),
]

# REGRESSION FIX (node-libcurl@5.1.2): gyp's own `<key>!` list convention REMOVES
# entries from an inherited list rather than adding to it. Confirmed real and NOT a
# one-off: this is node-addon-api's own canonical `except.gypi` idiom --
# `'cflags!': ['-fno-exceptions']`, `'cflags_cc!': ['-fno-exceptions']` -- which
# node-libcurl's own binding.gyp copies inline, verbatim, with its own comment
# "# Allow C++ exceptions" directly above it. A flat text search cannot see this: it
# found the substring "-fno-exceptions" and classified node-libcurl "disabled", the
# OPPOSITE of the source's own explicit, commented intent -- confirmed as a real
# regression by manual verification (fetching the real published tarball, tracing
# `Easy::ReadFunction`'s real registration/callers, and reading node-addon-api 8.5.0's
# own real source; see study/resource_guard_r05/NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md).
# `_gyp_removal_spans()` finds the real byte ranges of every `'<key>!': [...]` /
# `"<key>!": [...]` list body in a binding.gyp file, so a flag matched INSIDE one can be
# classified with INVERTED polarity instead of the file's own naive, flat-search
# polarity. Deliberately bounded, disclosed scope: only flat string lists (cflags,
# cflags_cc, defines) are matched -- `[^\]]*` stops at the first `]`, so a list
# containing a nested `[...]`/`{...}` would not be captured correctly; real cflags/
# cflags_cc/defines lists in practice are always flat string lists, confirmed on every
# real binding.gyp read during this fix's own verification. Only meaningful for
# binding.gyp files -- gyp's `!`-suffix list-removal convention does not exist in
# CMake/meson/GN/package.json, so it is never applied to those families.
GYP_REMOVAL_LIST_RE = re.compile(rb'''["'][A-Za-z_]+!["']\s*:\s*\[([^\]]*)\]''')


def _gyp_removal_spans(content):
    """Real byte-offset spans of gyp `<key>!` (list-removal) bodies in `content` -- see
    `GYP_REMOVAL_LIST_RE`'s own module-level comment."""
    return [m.span(1) for m in GYP_REMOVAL_LIST_RE.finditer(content)]


def _in_any_span(pos, spans):
    return any(start <= pos < end for start, end in spans)

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
        removal_spans = _gyp_removal_spans(content) if family == "binding.gyp" else []
        for pat, label in DISABLE_PATTERNS:
            matches = list(pat.finditer(content))
            if not matches:
                continue
            if any(not _in_any_span(m.start(), removal_spans) for m in matches):
                disable_evidence.append(f"{name}: {label}")
            if any(_in_any_span(m.start(), removal_spans) for m in matches):
                enable_evidence.append(
                    f"{name}: {label} (found inside a gyp `!`-list removal -- real enable evidence)")
        for pat, label in ENABLE_PATTERNS:
            matches = list(pat.finditer(content))
            if not matches:
                continue
            if any(not _in_any_span(m.start(), removal_spans) for m in matches):
                enable_evidence.append(f"{name}: {label}")
            if any(_in_any_span(m.start(), removal_spans) for m in matches):
                disable_evidence.append(
                    f"{name}: {label} (found inside a gyp `!`-list removal -- real disable evidence)")
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
