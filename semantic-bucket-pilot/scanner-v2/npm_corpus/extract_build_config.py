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
  unresolved -- no direct textual evidence either way. This is the SAFE DEFAULT: an automatic,
               bulk, per-package scan does not attempt the kind of one-off, manually-verified
               default-resolution reasoning RESOURCE_GUARD_R04.md applied to jpeg-turbo
               (checking node-addon-api's own napi.h default-resolution logic AND the absence
               of any compiler-level exception-disabling flag) -- that was deliberate, disclosed,
               manual investigative work on ONE real site, not a rule this automatic stage
               applies to hundreds of packages without individual verification.

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

R06 TARGET-SCOPING FIX (this revision -- see study/resource_guard_r05/
NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md's own addendum): the whole-package
`classify_from_tarball()` above -- including both fixes just described -- was itself
found to have a real, undisclosed scope problem: a real binding.gyp can define MULTIPLE
gyp targets, each with its OWN, independently-resolved exception configuration (via
per-target cflags/cflags_cc/defines, OS-`conditions` branches, or per-target
dependencies) -- package-wide flat text matching can silently MERGE two genuinely
different targets' evidence into one misleading verdict (a real `conflict` where one
target is actually cleanly `enabled` and an unrelated target is cleanly `disabled`, or
worse, evidence from a target that does not even compile the file in question). Fixed by
`parse_gyp_targets()` (real, quote-aware brace-matching -- not another flat regex -- so
nested `conditions`/`dependencies` structures inside a target block do not corrupt
scoping) and `classify_target_aware()`, which associates each real gyp target with the
real source files it compiles (`sources`) and classifies each target independently.
`resolve_build_config_for_file()` looks up the SPECIFIC target that compiles a given
finding's own source file -- exactly one match uses that target's own verdict; zero or
conflicting matches yield `BUILD_CONFIGURATION_UNRESOLVED`/`conflict`, NEVER a
package-wide guess. Five real, adversarial fixtures (two targets with different real
configs; `cflags!` in an unrelated target; a real OS-`conditions` branch; removal
immediately followed by a target-level re-add; `node_addon_api_except` vs. bare
`node_addon_api`) all verified through this real parser -- see
`study/resource_guard_r05/NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md`.

Output: npm_build_configuration.tsv -- one row per eligible package: exception_configuration,
the real evidence strings found (file + matched pattern, bounded to the first 5), and which
config file family supplied the evidence (binding.gyp / cmake / meson / gn / package.json /
none). The per-target functions below are a real, tested, reusable library layer, not yet
wired into a new corpus-wide output schema -- deliberately deferred (see
NODE_LIBCURL_FALSE_POSITIVE_REVIEW.md) until after the currently-running R05 494-package
scan finishes, so the two expensive jobs never compete for the same container.
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


def _classify_span(content, start, end):
    """Real disable/enable evidence classification restricted to `content[start:end]`
    only -- the SAME patterns and gyp `!`-list-removal polarity check as the
    whole-package `classify_from_tarball()`, just scoped to one real byte range (a
    single gyp target's own block, or `target_defaults`). Returns
    (disable_evidence: [str], enable_evidence: [str])."""
    region = content[start:end]
    removal_spans = _gyp_removal_spans(region)
    disable_evidence, enable_evidence = [], []
    for pat, label in DISABLE_PATTERNS:
        matches = list(pat.finditer(region))
        if not matches:
            continue
        if any(not _in_any_span(m.start(), removal_spans) for m in matches):
            disable_evidence.append(label)
        if any(_in_any_span(m.start(), removal_spans) for m in matches):
            enable_evidence.append(f"{label} (found inside a gyp `!`-list removal -- real enable evidence)")
    for pat, label in ENABLE_PATTERNS:
        matches = list(pat.finditer(region))
        if not matches:
            continue
        if any(not _in_any_span(m.start(), removal_spans) for m in matches):
            enable_evidence.append(label)
        if any(_in_any_span(m.start(), removal_spans) for m in matches):
            disable_evidence.append(f"{label} (found inside a gyp `!`-list removal -- real disable evidence)")
    return disable_evidence, enable_evidence


def _classification_from_evidence(disable_evidence, enable_evidence):
    if disable_evidence and enable_evidence:
        return "conflict"
    if disable_evidence:
        return "disabled"
    if enable_evidence:
        return "enabled"
    return "unresolved"


def _skip_gyp_string(content, i):
    """If `content[i]` opens a quoted string, return the index just past its real
    matching closing quote (respecting `\\`-escaped characters), else return `i`
    unchanged. Used by the bracket matcher below so a literal `{`/`}`/`[`/`]` character
    INSIDE a quoted string value (e.g. a shell command string in a `dependencies` entry)
    never miscounts as real gyp structure."""
    if i >= len(content) or content[i:i + 1] not in (b'"', b"'"):
        return i
    quote = content[i:i + 1]
    j = i + 1
    n = len(content)
    while j < n:
        c = content[j:j + 1]
        if c == b'\\':
            j += 2
            continue
        if c == quote:
            return j + 1
        j += 1
    return j  # unterminated string (truncated/malformed content) -- stop at EOF


def _skip_gyp_comment(content, i):
    """If `content[i]` starts a real gyp/Python-style `#`-to-end-of-line comment,
    return the index of the newline that ends it (or EOF), else return `i` unchanged.
    REQUIRED, not cosmetic: confirmed real via a genuine parse failure on
    node-libcurl's own real binding.gyp -- a comment reading "...because it doesn't
    start with a -..." contains a single, real, UNBALANCED apostrophe. Without skipping
    comments first, `_skip_gyp_string` treats that apostrophe as opening a real string
    and scans forward for the next quote character to close it, silently consuming real
    gyp structure (including the actual closing bracket) along the way. Comments are
    skipped BEFORE string detection in every scanning loop below for exactly this
    reason."""
    if i >= len(content) or content[i:i + 1] != b'#':
        return i
    j = content.find(b'\n', i)
    return len(content) if j == -1 else j


def _find_matching_bracket(content, open_pos, open_ch, close_ch):
    """Real, quote-and-comment-aware bracket matcher: returns the index of the
    `close_ch` that matches the `open_ch` at `open_pos` (which must itself be
    `open_ch`), skipping over quoted string contents via `_skip_gyp_string` and real
    `#`-comments via `_skip_gyp_comment` (comments checked FIRST -- see its own
    docstring for why) so a real target block's own `dependencies`/`conditions`
    sub-structures, and any real comment text within it, never corrupt the match.
    Returns None on unmatched/truncated content -- callers treat that as "cannot
    establish", never a guess (matches this project's own established fail-closed
    discipline)."""
    n = len(content)
    if open_pos >= n or content[open_pos:open_pos + 1] != open_ch:
        return None
    depth = 0
    i = open_pos
    while i < n:
        c = content[i:i + 1]
        if c == b'#':
            i = _skip_gyp_comment(content, i)
            continue
        if c in (b'"', b"'"):
            i = _skip_gyp_string(content, i)
            continue
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


TARGETS_KEY_RE = re.compile(rb'''["']targets["']\s*:\s*\[''')
TARGET_DEFAULTS_KEY_RE = re.compile(rb'''["']target_defaults["']\s*:\s*\{''')
TARGET_NAME_RE = re.compile(rb'''["']target_name["']\s*:\s*["']([^"']+)["']''')
SOURCES_LIST_RE = re.compile(rb'''["']sources["']\s*:\s*\[([^\]]*)\]''')
SOURCE_FILE_RE = re.compile(rb'''["']([^"']+\.(?:cc|cpp|cxx|c|mm))["']''', re.IGNORECASE)


def parse_gyp_targets(content):
    """R06 TARGET-SCOPING FIX -- see module docstring for the full real account. Real,
    quote-aware, bracket-matching parse of a binding.gyp file's own `"targets": [...]`
    array into one dict per real target: `{"target_name": str|None, "start": int,
    "end": int, "sources": [str, ...]}` (byte-offset span of the target's own `{...}`
    block, and the real source-file paths its own `"sources"` list names). Also returns
    the real byte-offset span of a `"target_defaults": {...}` block if present (gyp's
    own standard mechanism for settings shared by every target in the file), or None.

    Deliberately bounded, disclosed scope, same discipline as `GYP_REMOVAL_LIST_RE`
    above: does not evaluate gyp variable substitution (`<(var)`), does not evaluate
    which branch of a `"conditions"` array actually applies (both branches are scanned
    for evidence -- see module docstring), does not resolve gyp `"includes"` (external
    file inclusion), and `SOURCES_LIST_RE` assumes a flat, non-nested source-file list
    (true of every real binding.gyp read during this fix's own verification). A real
    target whose own config depends on something this parser cannot resolve is exactly
    the case that must report UNRESOLVED/CONFLICT downstream, never a guess."""
    targets = []
    tm = TARGETS_KEY_RE.search(content)
    if tm is None:
        return targets, None
    list_open = tm.end() - 1
    list_close = _find_matching_bracket(content, list_open, b'[', b']')
    if list_close is None:
        return targets, None
    i = list_open + 1
    n = len(content)
    while i < list_close:
        c = content[i:i + 1]
        if c == b'#':
            i = _skip_gyp_comment(content, i)
            continue
        if c in (b'"', b"'"):
            i = _skip_gyp_string(content, i)
            continue
        if c == b'{':
            block_close = _find_matching_bracket(content, i, b'{', b'}')
            if block_close is None:
                break  # malformed/truncated -- stop rather than guess past it
            block = content[i:block_close + 1]
            name_m = TARGET_NAME_RE.search(block)
            target_name = name_m.group(1).decode('utf-8', 'replace') if name_m else None
            sources = []
            src_m = SOURCES_LIST_RE.search(block)
            if src_m:
                sources = [s.decode('utf-8', 'replace') for s in SOURCE_FILE_RE.findall(src_m.group(1))]
            targets.append({"target_name": target_name, "start": i, "end": block_close + 1,
                             "sources": sources})
            i = block_close + 1
            continue
        i += 1

    defaults_span = None
    dm = TARGET_DEFAULTS_KEY_RE.search(content)
    if dm is not None:
        d_open = dm.end() - 1
        d_close = _find_matching_bracket(content, d_open, b'{', b'}')
        if d_close is not None:
            defaults_span = (d_open, d_close + 1)
    return targets, defaults_span


def classify_target_aware(content):
    """R06 TARGET-SCOPING FIX -- real, per-target exception-configuration
    classification for one binding.gyp file's own real `content` bytes. Returns a list
    of dicts, one per real gyp target: `{"target_name", "sources",
    "exception_configuration", "disable_evidence", "enable_evidence"}`. Each target's
    own evidence is gathered from ONLY its own real `{...}` block span, UNION any real
    `target_defaults` block (gyp's own standard shared-settings mechanism, applies to
    every target) -- never from another, unrelated target's own scope, and never from
    bare top-level keys outside both (a real binding.gyp CAN contain such keys, e.g. as
    dead/unused text sibling to `"targets"`, which is not standard gyp inheritance and
    is therefore never treated as applying to any specific target here). Returns []
    if no real `"targets"` array could be parsed at all (caller falls back to the
    whole-file, non-target-aware classification)."""
    targets, defaults_span = parse_gyp_targets(content)
    if not targets:
        return []
    default_dis, default_en = ([], [])
    if defaults_span is not None:
        default_dis, default_en = _classify_span(content, *defaults_span)
    results = []
    for t in targets:
        own_dis, own_en = _classify_span(content, t["start"], t["end"])
        disable_evidence = own_dis + default_dis
        enable_evidence = own_en + default_en
        results.append({
            "target_name": t["target_name"],
            "sources": t["sources"],
            "exception_configuration": _classification_from_evidence(disable_evidence, enable_evidence),
            "disable_evidence": disable_evidence,
            "enable_evidence": enable_evidence,
        })
    return results


def _source_file_matches(target_source, finding_source):
    """Real, tolerant match between a gyp target's own recorded source path (e.g.
    `"./src/Easy.cc"`, `"src/Easy.cc"`) and a finding's own source-file path -- compares
    normalized (leading `./` stripped) suffixes, since a gyp `sources` entry and a real
    finding's own recorded file path are not guaranteed to share the same relative-path
    prefix convention. A real, disclosed, exact-suffix requirement -- never a substring
    or basename-only match, which could conflate two different files that merely share
    a filename in different directories."""
    def norm(p):
        p = p.replace('\\', '/')
        while p.startswith('./'):
            p = p[2:]
        return p.lstrip('/')
    a, b = norm(target_source), norm(finding_source)
    return a == b or a.endswith('/' + b) or b.endswith('/' + a)


def resolve_build_config_for_targets(per_target, finding_source_file):
    """R06 TARGET-SCOPING FIX -- the real, required entry point for associating a
    SPECIFIC finding's own source file with the SPECIFIC gyp target that compiles it,
    rather than a package-wide flattened verdict. Takes an ALREADY-PARSED per-target
    list (`classify_target_aware()`'s own return shape) rather than raw file content,
    so a caller holding many findings for the same package (e.g. the R06 scanner) can
    parse the real binding.gyp ONCE and resolve every finding's own source file against
    the same real per-target data, instead of re-parsing per finding.

    Returns a dict: `{"exception_configuration", "resolved_target_name"|None,
    "matching_targets": [...], "reason"}` where `exception_configuration` is one of
    `"enabled"`, `"disabled"`, `"conflict"`, `"unresolved"`, or
    `"BUILD_CONFIGURATION_UNRESOLVED"` -- the last one used specifically when target
    identity itself could not be established (zero or more-than-one real target names
    the file, per `_source_file_matches`), matching the same naming convention as
    `BUILD_CONFIGURATION_UNRESOLVED`/`_CONFLICT` used elsewhere in this project's own
    R04/R05 applicability gates. NEVER falls back to a package-wide guess: if target
    identity cannot be resolved, the returned `exception_configuration` is always
    `BUILD_CONFIGURATION_UNRESOLVED` or `"conflict"`, never a same-named single
    target's own `enabled`/`disabled` value applied package-wide -- this is the FAIL-
    CLOSED behavior required whenever source-to-target resolution is unavailable."""
    if not per_target:
        return {"exception_configuration": "BUILD_CONFIGURATION_UNRESOLVED",
                "resolved_target_name": None, "matching_targets": [],
                "reason": "no real gyp targets array could be parsed"}
    matching = [t for t in per_target
                for src in t["sources"] if _source_file_matches(src, finding_source_file)]
    if not matching:
        return {"exception_configuration": "BUILD_CONFIGURATION_UNRESOLVED",
                "resolved_target_name": None, "matching_targets": [],
                "reason": f"no real gyp target's own sources list names {finding_source_file!r}"}
    configs = {t["exception_configuration"] for t in matching}
    if len(matching) == 1:
        return {"exception_configuration": matching[0]["exception_configuration"],
                "resolved_target_name": matching[0]["target_name"],
                "matching_targets": matching, "reason": "single real target compiles this file"}
    if len(configs) == 1:
        return {"exception_configuration": matching[0]["exception_configuration"],
                "resolved_target_name": None, "matching_targets": matching,
                "reason": "multiple real targets compile this file, but all agree"}
    return {"exception_configuration": "conflict", "resolved_target_name": None,
            "matching_targets": matching,
            "reason": "multiple real targets compile this file with DIFFERING exception configuration"}


def resolve_build_config_for_file(content, finding_source_file):
    """Convenience wrapper over `resolve_build_config_for_targets` for a caller
    (tests, one-off CLI use) that only has raw gyp file content, not an already-parsed
    per-target list -- parses ONCE per call. See `resolve_build_config_for_targets`
    for the real matching semantics; kept as a separate, stable entry point since
    `tests/test_target_scoping.py` already calls it by this name."""
    return resolve_build_config_for_targets(classify_target_aware(content), finding_source_file)


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
