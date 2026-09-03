#!/usr/bin/env python3
"""ESCAPE-PARITY-BOUNDARY-R01 -- deterministic, source-only package prefilter.

A CHEAP TEXT PREFILTER, USED ONLY TO SELECT PACKAGES FOR ANALYSIS.
A prefilter match is NEVER a finding. Nothing this file computes is a
classification; it exists solely to decide which packages are worth compiling.
Every classification comes from the frozen analyzer running over a real CPG.

The filter is deterministic (no randomness, no network, no ordering dependence
beyond the frozen corpus order) and operates only on a package's own JS/TS source
files. It requires evidence in all four required dimensions:

  A. quoted-string parsing        -- a quote character used in a parsing position
  B. escape/decode/encode/replace -- escape handling or a replacement operation
  C. delayed-processing context   -- archive, dump, import, restore, migration or
                                     database-processing code
  D. structured-text consumer     -- a call that hands text to a structured-data
                                     interpreter or database import routine

Score = number of dimensions met (0-4). Only packages meeting ALL FOUR are eligible
for selection. Ties are broken by frozen corpus order, never by score magnitude
alone and never by anything package-specific.
"""
import json
import re
import sys
import tarfile
from pathlib import Path

SRC_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts")
SKIP_DIR_PARTS = ("/node_modules/", "/test/", "/tests/", "/__tests__/", "/spec/",
                  "/fixtures/", "/fixture/", "/example/", "/examples/", "/docs/",
                  "/coverage/", "/.git/")

# A. a quote character appearing in a parsing position: inside a regex-looking
#    literal, or compared against an indexed character.
A_PATTERNS = (
    re.compile(r"""/[^/\n]*\\?['"][^/\n]*/[dgimsuvy]*"""),      # quote inside a regex literal
    re.compile(r"""\[\s*\w+\s*(?:[-+]\s*\d+\s*)?\]\s*[!=]==?\s*['"]"""),  # s[i] === "'"
    re.compile(r"""charAt\s*\([^)]*\)\s*[!=]==?\s*['"]"""),
    re.compile(r"""new\s+RegExp\s*\("""),
)
# B. escape handling / decode / encode / replacement
B_PATTERNS = (
    re.compile(r"""\\\\\\\\"""),                                  # an escaped backslash
    re.compile(r"""\.replace(?:All)?\s*\("""),
    re.compile(r"""Buffer\.from\s*\(|\.toString\s*\(\s*['"](?:base64|hex|utf-?8)"""),
    re.compile(r"""\b(?:atob|btoa|decodeURIComponent|encodeURIComponent|unescape)\s*\("""),
    re.compile(r"""\bzlib\b|\bgunzip|\binflate"""),
)
# C. delayed-processing context
C_PATTERNS = (
    re.compile(r"""\b(?:readFile|readFileSync|createReadStream)\s*\("""),
    re.compile(r"""\brequire\s*\(\s*['"](?:fs|node:fs|fs/promises|yauzl|unzipper|adm-zip|tar|tar-stream|node-stream-zip|jszip|archiver|zlib|node:zlib)['"]"""),
    re.compile(r"""\bfrom\s+['"](?:fs|node:fs|fs/promises|yauzl|unzipper|adm-zip|tar|tar-stream|node-stream-zip|jszip|archiver|zlib|node:zlib)['"]"""),
    re.compile(r"""\b(?:dump|backup|restore|migrat|archive|import)\w*\s*[=(:]""", re.I),
)
# D. structured-text consumer
D_PATTERNS = (
    re.compile(r"""\bJSON\.parse\s*\("""),
    re.compile(r"""\.(?:query|execute)\s*\("""),
    re.compile(r"""\b(?:yaml|jsyaml|js_yaml)\s*\.\s*(?:parse|load|safeLoad)\s*\("""),
    re.compile(r"""\bunserialize\s*\("""),
    re.compile(r"""\bquerystring\s*\.\s*parse\s*\("""),
)
DIMENSIONS = (("A_quoted_string_parsing", A_PATTERNS),
              ("B_escape_decode_encode_replace", B_PATTERNS),
              ("C_delayed_processing_context", C_PATTERNS),
              ("D_structured_text_consumer", D_PATTERNS))


def source_members(tf):
    for m in tf.getmembers():
        if not m.isfile():
            continue
        name = "/" + m.name
        if not name.endswith(SRC_SUFFIXES):
            continue
        if any(part in name for part in SKIP_DIR_PARTS):
            continue
        if m.size > 4 * 1024 * 1024:      # skip pathological single files
            continue
        yield m


def scan_tarball(path):
    """Return (score, per-dimension hit counts, n_source_files, n_bytes)."""
    hits = {d: 0 for d, _ in DIMENSIONS}
    nfiles, nbytes = 0, 0
    try:
        with tarfile.open(path, "r:gz") as tf:
            for m in source_members(tf):
                try:
                    data = tf.extractfile(m).read()
                except Exception:
                    continue
                nfiles += 1
                nbytes += len(data)
                try:
                    text = data.decode("utf-8", errors="replace")
                except Exception:
                    continue
                for dim, pats in DIMENSIONS:
                    if any(p.search(text) for p in pats):
                        hits[dim] += 1
    except Exception as e:
        return None, {"error": "%s: %s" % (type(e).__name__, e)}, 0, 0
    score = sum(1 for d in hits if hits[d] > 0)
    return score, hits, nfiles, nbytes


if __name__ == "__main__":
    out = []
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        name, version, tarball = line.split("\t")
        score, hits, nfiles, nbytes = scan_tarball(tarball)
        out.append({"package": name, "version": version, "score": score,
                    "dimension_hits": hits, "n_source_files": nfiles,
                    "n_source_bytes": nbytes})
    json.dump(out, sys.stdout, indent=1)
