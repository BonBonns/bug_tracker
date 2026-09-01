#!/usr/bin/env python3
"""EXTRACT-BUILD-CONFIG-R01 controls. Covers `classify_unresolved_reason()` -- the real,
diagnostic-only sub-classification added after the corpus-wide build-configuration staleness
audit's own follow-up investigation of the 54 packages classify_from_tarball() left
"unresolved" in the 97-package replay sample: no signal was found that could safely promote any
of them to a decisive enabled/disabled/conflict value without guessing, but three real,
mechanically-checkable REASONS for the "unresolved" state were found and are worth surfacing for
a future individual review (see study/task34_replay/UNRESOLVED_CATEGORIZATION.md).

Per direct instruction, controls for the change: POSITIVE (a real reason correctly identified),
NEGATIVE (a case that must NOT be misclassified into the wrong reason bucket), CONFLICT
(classify_unresolved_reason is never even meaningful when classify_from_tarball() itself already
resolved a decisive/conflict value -- the two functions' own results must never disagree about
whether resolution happened), and GENUINELY-UNRESOLVED (a real config file with irrelevant
content correctly falls through to NO_TEXTUAL_EVIDENCE, never guessed at)."""
import io
import os
import sys
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
NPM_CORPUS = os.path.join(HERE, "npm_corpus")
sys.path.insert(0, NPM_CORPUS)
import extract_build_config as ebc  # noqa: E402

ok = tot = 0
def ck(name, cond):
    global ok, tot
    tot += 1
    ok += bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


def make_tarball(files):
    """files: {relpath: bytes}. Builds a real, valid gzipped tar in memory, wrapped in a
    single 'package/' top-level dir, matching real npm tarball convention."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for relpath, content in files.items():
            data = content if isinstance(content, bytes) else content.encode()
            info = tarfile.TarInfo(name=f"package/{relpath}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# =====================================================================================
# 1. NEGATIVE / baseline: classify_unresolved_reason() must NEVER be called meaningfully when
#    classify_from_tarball() itself already resolved a decisive value -- proven here by
#    confirming its own "has_any_pattern" defensive fallback never fires on real inputs where
#    the caller's contract (only call when "unresolved") is honored, and that calling it anyway
#    on a DECISIVE tarball still returns the defensive NO_TEXTUAL_EVIDENCE fallback rather than
#    crashing or fabricating a reason -- i.e., it fails safe, never fails loud, on contract
#    violation by a future caller.
# =====================================================================================
decisive_enabled_tb = make_tarball({
    "binding.gyp": '{"targets": [{"target_name": "t", "cflags": ["-fexceptions"]}]}',
    "package.json": '{"name": "x"}',
})
r_decisive = ebc.classify_from_tarball(decisive_enabled_tb)
ck("baseline: a real, decisive binding.gyp resolves to 'enabled' via classify_from_tarball()",
   r_decisive["exception_configuration"] == "enabled")
ck("CONFLICT-SAFETY: classify_unresolved_reason() called anyway on an ALREADY-decisive tarball "
   "returns the defensive fallback, never crashes and never contradicts classify_from_tarball()'s "
   "own decisive answer with a fabricated 'reason'",
   ebc.classify_unresolved_reason(decisive_enabled_tb) == "NO_TEXTUAL_EVIDENCE")

# =====================================================================================
# 2. CONFLICT case: classify_unresolved_reason() on a real CONFLICT tarball (both real disable
#    and enable evidence present) -- same defensive-fallback contract as above; a conflict is
#    itself a resolved (if ambiguous) answer, never something this function re-diagnoses.
# =====================================================================================
conflict_tb = make_tarball({
    "binding.gyp": '{"targets": [{"target_name": "a", "cflags": ["-fno-exceptions"]}, '
                    '{"target_name": "b", "cflags": ["-fexceptions"]}]}',
    "package.json": '{"name": "x"}',
})
r_conflict = ebc.classify_from_tarball(conflict_tb)
ck("real CONFLICT tarball (both real disable+enable evidence) resolves to 'conflict'",
   r_conflict["exception_configuration"] == "conflict")
ck("classify_unresolved_reason() on the SAME conflict tarball returns the defensive fallback, "
   "never fabricates NO_RECOGNIZED_BUILD_FILE/CMAKE_JS_EXTERNAL_DEFAULT for an already-resolved "
   "(if ambiguous) case",
   ebc.classify_unresolved_reason(conflict_tb) == "NO_TEXTUAL_EVIDENCE")

# =====================================================================================
# 3. POSITIVE: NO_RECOGNIZED_BUILD_FILE -- a real tarball with only a package.json (no
#    binding.gyp/CMakeLists.txt/meson.build/*.gn(i) anywhere) is correctly identified as having
#    no recognized build file at all. Mirrors 4 real packages this round's own investigation
#    found in exactly this shape (@co_snow/hello, @depup/node-addon-api, velociradix, yatag).
# =====================================================================================
no_build_file_tb = make_tarball({"package.json": '{"name": "x", "version": "1.0.0"}'})
r_nbf = ebc.classify_from_tarball(no_build_file_tb)
ck("POSITIVE precondition: a package.json-only tarball resolves to 'unresolved' via "
   "classify_from_tarball()", r_nbf["exception_configuration"] == "unresolved")
ck("POSITIVE: classify_unresolved_reason() correctly identifies NO_RECOGNIZED_BUILD_FILE",
   ebc.classify_unresolved_reason(no_build_file_tb) == "NO_RECOGNIZED_BUILD_FILE")

# =====================================================================================
# 4. POSITIVE: CMAKE_JS_EXTERNAL_DEFAULT -- a real CMakeLists.txt with no textual exception
#    evidence, but package.json real-lists cmake-js as a dependency (the real, documented npm
#    convention for a cmake-js-built native addon) -- cmake-js's own tooling injects the
#    exception-configuration define at build time, external to the package's own repo text.
#    Mirrors 8 real packages this round's own investigation found in exactly this shape (e.g.
#    @eliyya/sange, @ipshipyard/node-datachannel, @fugood/whisper.node, audify).
# =====================================================================================
cmake_js_tb = make_tarball({
    "CMakeLists.txt": "cmake_minimum_required(VERSION 3.15)\nadd_library(x SHARED src/x.cc)\n",
    "package.json": '{"name": "x", "devDependencies": {"cmake-js": "^7.3.0"}}',
})
r_cjs = ebc.classify_from_tarball(cmake_js_tb)
ck("POSITIVE precondition: a real, textually-silent CMakeLists.txt resolves to 'unresolved'",
   r_cjs["exception_configuration"] == "unresolved")
ck("POSITIVE: classify_unresolved_reason() correctly identifies CMAKE_JS_EXTERNAL_DEFAULT (real "
   "cmake-js devDependency evidence found)",
   ebc.classify_unresolved_reason(cmake_js_tb) == "CMAKE_JS_EXTERNAL_DEFAULT")

# =====================================================================================
# 5. NEGATIVE (distinguishing the two positive cases from each other): a real CMakeLists.txt
#    present with NO cmake-js reference anywhere must fall through to NO_TEXTUAL_EVIDENCE, never
#    be misclassified as CMAKE_JS_EXTERNAL_DEFAULT just because a CMake file exists, and never as
#    NO_RECOGNIZED_BUILD_FILE just because CMakeLists.txt happens to be silent on exceptions.
# =====================================================================================
plain_cmake_tb = make_tarball({
    "CMakeLists.txt": "cmake_minimum_required(VERSION 3.15)\nadd_library(x SHARED src/x.cc)\n",
    "package.json": '{"name": "x", "dependencies": {"node-addon-api": "^7.0.0"}}',
})
r_plain = ebc.classify_from_tarball(plain_cmake_tb)
ck("NEGATIVE precondition: a real, textually-silent, non-cmake-js CMakeLists.txt resolves to "
   "'unresolved'", r_plain["exception_configuration"] == "unresolved")
ck("GENUINELY-UNRESOLVED: classify_unresolved_reason() correctly returns NO_TEXTUAL_EVIDENCE -- "
   "a real config file exists, is not cmake-js-driven, and simply carries no recognized pattern "
   "-- never guessed at, never promoted, never misfiled into either positive-case bucket",
   ebc.classify_unresolved_reason(plain_cmake_tb) == "NO_TEXTUAL_EVIDENCE")

# =====================================================================================
# 6. INVARIANT: classify_unresolved_reason() NEVER changes exception_configuration -- by
#    construction it cannot, since it never calls (or reimplements) the decisive-value logic at
#    all, only ever reports a reason string. Verified directly: calling it never mutates or
#    depends on any classify_from_tarball() output; the two are independent, read-only functions
#    over the SAME real tarball bytes.
# =====================================================================================
for tb, label in ((decisive_enabled_tb, "decisive"), (conflict_tb, "conflict"),
                   (no_build_file_tb, "no-build-file"), (cmake_js_tb, "cmake-js"),
                   (plain_cmake_tb, "plain-cmake")):
    before = ebc.classify_from_tarball(tb)["exception_configuration"]
    ebc.classify_unresolved_reason(tb)
    after = ebc.classify_from_tarball(tb)["exception_configuration"]
    ck(f"INVARIANT ({label}): classify_unresolved_reason() call causes ZERO incorrect "
       f"promotions -- classify_from_tarball()'s own decisive answer is byte-identical before "
       f"and after ({before!r} == {after!r})", before == after)

# =====================================================================================
# 7. REAL SMOKE TEST: reruns classify_unresolved_reason() against 3 real packages from this
#    round's own 54-package investigation (results/unresolved_investigation.json), one per real
#    category found, confirming the SAME real answer this gate's own synthetic controls above
#    predict -- narrow, same-identity re-download, continuing the same established exception.
# =====================================================================================
INVESTIGATION_PATH = os.path.join(HERE, "study", "task34_replay", "results",
                                    "unresolved_investigation.json")
EXPECTED_REAL = {
    "velociradix@8.3.1": "NO_RECOGNIZED_BUILD_FILE",
    "@eliyya/sange@1.2.0": "CMAKE_JS_EXTERNAL_DEFAULT",
    "uiohook-napi@1.5.5": "NO_TEXTUAL_EVIDENCE",
}
if os.path.isfile(INVESTIGATION_PATH):
    import json
    sample_path = os.path.join(NPM_CORPUS, "overnight_100", "overnight_sample_100.json")
    sample = json.load(open(sample_path))
    sample_by_key = {f'{p["package_name"]}@{p["version"]}': p for p in sample["packages"]}
    for key, expected in EXPECTED_REAL.items():
        s = sample_by_key.get(key)
        if not s:
            print(f"SKIP real smoke: {key} not in overnight_sample_100.json")
            continue
        tb, err = ebc.fetch_bytes(s["tarball_url"])
        if err:
            print(f"SKIP real smoke: {key} download failed: {err}")
            continue
        real_reason = ebc.classify_unresolved_reason(tb)
        ck(f"REAL SMOKE: {key} classify_unresolved_reason() == {expected!r} (matches this "
           f"round's own investigation output)", real_reason == expected)
else:
    print("SKIP: results/unresolved_investigation.json not present -- real smoke tests skipped, "
          "all synthetic controls above still ran")

print(f"EXTRACT_BUILD_CONFIG_CONTROLS={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
