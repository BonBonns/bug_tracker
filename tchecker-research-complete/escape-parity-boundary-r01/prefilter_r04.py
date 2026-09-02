#!/usr/bin/env python3
"""ESCAPE-PARITY-BOUNDARY -- deterministic, source-only prefilter for BOTH languages.

A CHEAP TEXT PREFILTER, USED ONLY TO SELECT PACKAGES FOR ANALYSIS.
A prefilter match is NEVER a finding. Every classification comes from the frozen
analyzers running over a real CPG.

It scores each package independently for each target language on the four required
dimensions:

  A  quoted-string parsing        a quote used in a parsing position
  B  escape / decode / encode     escape handling or a replacement operation
  C  delayed-processing context   archive, dump, import, restore, migration, database
  D  structured-text consumer     a call handing text to a structured interpreter or
                                  a database import routine

A package is ELIGIBLE for a language when that language meets all four. Deterministic:
no randomness, no network, no ordering dependence beyond the frozen corpus order.
"""
import json
import re
import sys
import tarfile
from pathlib import Path

JS_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts")
CPP_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx")
SKIP = ("/node_modules/", "/test/", "/tests/", "/__tests__/", "/spec/", "/fixtures/",
        "/fixture/", "/example/", "/examples/", "/docs/", "/coverage/", "/.git/")

JS = {
 "A": (re.compile(r"""/[^/\n]*\\?['"][^/\n]*/[dgimsuvy]*"""),
       re.compile(r"""\[\s*\w+\s*(?:[-+]\s*\d+\s*)?\]\s*[!=]==?\s*['"]"""),
       re.compile(r"""charAt\s*\([^)]*\)\s*[!=]==?\s*['"]"""),
       re.compile(r"""new\s+RegExp\s*\(""")),
 "B": (re.compile(r"""\\\\\\\\"""), re.compile(r"""\.replace(?:All)?\s*\("""),
       re.compile(r"""Buffer\.from\s*\(|\.toString\s*\(\s*['"](?:base64|hex|utf-?8)"""),
       re.compile(r"""\b(?:atob|btoa|decodeURIComponent|encodeURIComponent|unescape)\s*\(""")),
 "C": (re.compile(r"""\b(?:readFile|readFileSync|createReadStream)\s*\("""),
       re.compile(r"""\brequire\s*\(\s*['"](?:fs|node:fs|fs/promises|yauzl|unzipper|adm-zip|tar|tar-stream|node-stream-zip|jszip|archiver|zlib|node:zlib)['"]"""),
       re.compile(r"""\bfrom\s+['"](?:fs|node:fs|fs/promises|yauzl|unzipper|adm-zip|tar|zlib)['"]"""),
       re.compile(r"""\b(?:dump|backup|restore|migrat|archive|import)\w*\s*[=(:]""", re.I)),
 "D": (re.compile(r"""\bJSON\.parse\s*\("""), re.compile(r"""\.(?:query|execute)\s*\("""),
       re.compile(r"""\b(?:yaml|jsyaml)\s*\.\s*(?:parse|load|safeLoad)\s*\("""),
       re.compile(r"""\bunserialize\s*\("""), re.compile(r"""\bquerystring\s*\.\s*parse\s*\(""")),
}
# C/C++ dimensions. The A patterns look for a character compared against a quote literal,
# which is how a hand-written scanner is written in C/C++.
CPP = {
 "A": (re.compile(r"""\[\s*\w+\s*(?:[-+]\s*\d+\s*)?\]\s*[!=]=\s*'"""),
       re.compile(r"""\*\s*\(?\s*\w+\s*(?:[-+]\s*\d+\s*)?\)?\s*[!=]=\s*'"""),
       re.compile(r"""\.at\s*\([^)]*\)\s*[!=]=\s*'"""),
       re.compile(r"""(?:std::)?regex\s*[\w:]*\s*\(\s*"[^"]*['"]"""),
       re.compile(r"""[!=]=\s*'\\?["']'""")),
 "B": (re.compile(r"""'\\\\\\\\'"""), re.compile(r"""[!=]=\s*'\\\\\\\\'"""),
       re.compile(r"""\b(?:base64_(?:de|en)code|EVP_(?:De|En)codeBlock|uncompress|compress|inflate|deflate)\s*\("""),
       re.compile(r"""(?:std::)?regex_replace\s*\(""")),
 "C": (re.compile(r"""\b(?:fopen|fread|fgets|getline|mmap|pread)\s*\("""),
       re.compile(r"""\b(?:zip_fread|unzReadCurrentFile|archive_read_data|gzread|BZ2_bzRead)\s*\("""),
       re.compile(r"""\b(?:sqlite3_column_(?:text|blob)|mysql_fetch_row|PQgetvalue)\s*\("""),
       re.compile(r"""\b(?:dump|backup|restore|migrat|archive|import)\w*\s*[({]""", re.I)),
 "D": (re.compile(r"""\b(?:sqlite3_exec|sqlite3_prepare(?:_v2)?|mysql_query|mysql_real_query|PQexec\w*)\s*\("""),
       re.compile(r"""\b(?:json_tokener_parse|cJSON_Parse|yaml_parser_load|xmlReadMemory|xmlParseMemory)\s*\("""),
       re.compile(r"""\bjson\s*::\s*parse\s*\(""")),
}
LANGS = {"JAVASCRIPT": (JS_SUFFIXES, JS), "C_CPP": (CPP_SUFFIXES, CPP)}


def scan_tarball(path):
    out = {L: {"hits": {d: 0 for d in "ABCD"}, "files": 0, "bytes": 0} for L in LANGS}
    try:
        with tarfile.open(path, "r:gz") as tf:
            for m in tf.getmembers():
                if not m.isfile() or m.size > 4 * 1024 * 1024:
                    continue
                name = "/" + m.name
                if any(p in name for p in SKIP):
                    continue
                lang = next((L for L, (sfx, _) in LANGS.items() if name.endswith(sfx)), None)
                if lang is None:
                    continue
                try:
                    text = tf.extractfile(m).read().decode("utf-8", errors="replace")
                except Exception:
                    continue
                rec = out[lang]
                rec["files"] += 1
                rec["bytes"] += len(text)
                for dim, pats in LANGS[lang][1].items():
                    if any(p.search(text) for p in pats):
                        rec["hits"][dim] += 1
    except Exception as e:
        return None, "%s: %s" % (type(e).__name__, e)
    for L in out:
        out[L]["score"] = sum(1 for d in out[L]["hits"] if out[L]["hits"][d] > 0)
        out[L]["eligible"] = out[L]["score"] == 4
    return out, ""


if __name__ == "__main__":
    res = []
    for line in sys.stdin:
        if not line.strip():
            continue
        name, version, tarball = line.strip().split("\t")
        o, err = scan_tarball(tarball)
        res.append({"package": name, "version": version, "languages": o, "error": err})
    json.dump(res, sys.stdout, indent=1)
