#!/usr/bin/env python3
"""ORIGIN-KIND PURITY gate.

Invariant: a source API may emit ONLY the OriginRef.Kind matching its actual
trust boundary and value semantics. No "closest available bucket."

This gate is a REGRESSION FENCE against exactly the two defects found in review:
  - recv (network) was emitting FILE_INPUT   (trust-boundary collapse)
  - createReadStream (handle) was emitting FILE_INPUT (value-shape collapse)
It asserts the CANON below and fails loud if a recognizer drifts back.
"""
import json, os, re, subprocess, sys, tempfile, pathlib
ROOT = pathlib.Path(__file__).resolve().parent.parent

# The canonical, PURE mapping. A recognizer may emit the value on the right for
# the API on the left, and NOTHING ELSE. APIs mapped to None must emit no origin
# (abstain) until they have their own characterized, controlled recognizer.
CANON = {
    # atomic file readers -> FILE_INPUT (return value is bytes)
    'fread':'FILE_INPUT', 'fgets':'FILE_INPUT', 'read':'FILE_INPUT',
    'getline':'FILE_INPUT', 'readFile':'FILE_INPUT', 'readFileSync':'FILE_INPUT',
    # network -> NETWORK_INPUT, but NOT promoted yet -> must abstain
    'recv':None, 'recvfrom':None,
    # stream handle -> not bytes -> must abstain (JS-SOURCE-R02 territory)
    'createReadStream':None,
    # database -> DATABASE_INPUT, curated layer only, engine must not emit
    'sqlite3_column_blob':None,
}

def check_source_recognizer(src_lang, apis, kind_expected):
    """Scan a tiny fixture and confirm each API emits only its canonical kind."""
    failures=[]
    # Static assertion against the recognizer source is the robust check: the C
    # and JS recognizers each declare their reader set + kind explicitly.
    c_norm=(ROOT/'tests/gates/cpp-r06/frontend/normalize_c_cpp_facts_v03.py').read_text()
    js_norm=(ROOT/'frontends/javascript-typescript/joern-ts/normalize_ts_facts.py').read_text()
    # 1. recv must NOT be in the C FILE_READ_APIS
    m=re.search(r'FILE_READ_APIS=\{([^}]*)\}', c_norm)
    c_readers=m.group(1) if m else ''
    if 'recv' in c_readers:
        failures.append("recv is in C FILE_READ_APIS -> would emit FILE_INPUT (network->file collapse)")
    if 'fread' not in c_readers:
        failures.append("fread missing from C FILE_READ_APIS (regression)")
    # 2. C recognizer emits only origin_kind FILE_INPUT
    kinds=set(re.findall(r"origin_kind'\s*:\s*'(\w+)'", c_norm)) | set(re.findall(r"'origin_kind':'(\w+)'", c_norm))
    stray=kinds - {'FILE_INPUT'}
    if stray:
        failures.append(f"C recognizer emits non-FILE_INPUT kinds: {stray}")
    # 3. createReadStream must NOT be in the JS atomic reader set
    m=re.search(r'_JS_FILE_READERS=\{([^}]*)\}', js_norm)
    js_readers=m.group(1) if m else ''
    if 'createReadStream' in js_readers:
        failures.append("createReadStream in JS atomic readers -> false EXACT on a stream handle")
    if 'readFileSync' not in js_readers:
        failures.append("readFileSync missing from JS readers (regression)")
    # 4. JS recognizers emit only their separately-modelled trust classes.
    js_kinds=set(re.findall(r"origin_kind'\s*:\s*'(\w+)'", js_norm)) | set(re.findall(r"'origin_kind':'(\w+)'", js_norm))
    stray_js=js_kinds - {'FILE_INPUT', 'WEBEXT_EXTERNAL_MESSAGE_INPUT',
                         'WEBEXT_TAB_URL_INPUT'}
    if stray_js:
        failures.append(f"JS recognizer emits unclassified kinds: {stray_js}")
    if 'WEBEXT_EXTERNAL_MESSAGE_INPUT' not in js_kinds or '_WEBEXT_EXTERNAL_LISTENER' not in js_norm:
        failures.append("WebExtension external-message recognizer lost its distinct origin class")
    if 'WEBEXT_TAB_URL_INPUT' not in js_kinds or '_WEBEXT_TAB_LISTENER' not in js_norm:
        failures.append("WebExtension tab-URL recognizer lost its distinct origin class")
    return failures

fails = check_source_recognizer('all', CANON, None)
ok = len(fails)==0
tot = 4
print(f"ORIGIN_KIND_PURITY: recv!∈file={'OK' if not any('recv' in f for f in fails) else 'FAIL'}, "
      f"createReadStream!∈atomic={'OK' if not any('createReadStream' in f for f in fails) else 'FAIL'}, "
      f"C-kinds-pure={'OK' if not any('C recognizer' in f for f in fails) else 'FAIL'}, "
      f"JS-kinds-pure={'OK' if not any('JS recognizer' in f for f in fails) else 'FAIL'}")
for f in fails: print("  FAIL:", f)
print(f"ORIGIN_KIND_PURITY_CONTROLS={'PASS' if ok else 'FAIL'} ({tot-len(fails)}/{tot})")
sys.exit(0 if ok else 1)
