#!/usr/bin/env python3
"""JS-SOURCE-R01 pure-engine control. Uses CACHED facts (no live frontend) so it
runs inside GUARD-R01 without Joern. Asserts: readers tagged FILE_INPUT, non-reader
not, unbound abstains, and eval(readFileSync(x)) sink carries the origin."""
import json, os, subprocess, sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "gates" / "guard-r01" / "jssrc_fixture"
BUILD = ROOT / "tests" / "gates" / "jsts-r05" / "build"
if not (FIX / "js.json").exists():
    print("JS_SOURCE_R01_CONTROLS: fixture absent (skipped)"); sys.exit(0)
S = json.load(open(FIX / "js.json.source.json"))
G = json.load(open(FIX / "js.json"))
loc = {l["id"]: l["name"] for l in G["locals"]}
names = {loc.get(o["target_local_id"]) for o in S["source_origins"]}
ok = tot = 0
def ck(n, c):
    global ok, tot; tot += 1; ok += bool(c); print(("PASS " if c else "FAIL ") + n)
ck("readFileSync-bound local tagged FILE_INPUT", "data" in names)
ck("non-reader result NOT tagged", "other" not in names)
ck("origin count matches bound reads only (2)", len(S["source_origins"]) == 2)
args = [str(FIX / f) for f in ("js.json", "js_state.json", "js_identity.json",
        "js_capture.json", "js.json.expression.json", "js.json.source.json")]
out = subprocess.run(["java", "-cp", str(BUILD), "EndToEndRunner", *args],
    env={**os.environ, "SINKS": "eval:1"}, capture_output=True, text=True).stdout
ck("eval(readFileSync(x)) sink carries FILE_INPUT origin", "FILE_INPUT@readFileSync" in out)
print(f"JS_SOURCE_R01_CONTROLS={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
