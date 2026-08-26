#!/usr/bin/env python3
"""Scanner presentation controls for sidecars and out-of-band origins."""
import importlib.util
import pathlib
import subprocess
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("provenance_scan", HERE / "provenance_scan.py")
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)

with tempfile.TemporaryDirectory() as td:
    work = pathlib.Path(td)
    names = [p.name for p in scan.SIDECARS["js"](work)]
    assert "js.json.source.json" in names
    output = "\n".join([
        "SINK handler fetch#1 resolution=AMBIGUOUS proven=[] may=[0] unknown=false "
        "origins=[] mayOrigins=[WEBEXT_EXTERNAL_MESSAGE_INPUT@runtime.onMessageExternal]",
        "SINK clean fetch#1 resolution=EXACT proven=[] may=[] unknown=false origins=[] mayOrigins=[]",
    ]) + "\n"
    original = scan.run
    scan.run = lambda *a, **kw: subprocess.CompletedProcess([], 0, output, "")
    try:
        rows = scan.engine("js", work, "fetch:1")
    finally:
        scan.run = original
    assert len(rows) == 2
    assert rows[0]["may_origins"] == [
        "WEBEXT_EXTERNAL_MESSAGE_INPUT@runtime.onMessageExternal"]
    assert scan.classify(rows[0]) == "MAY_ORIGIN"
    assert scan.classify(rows[1]) == "PROVEN_SOURCE_FREE"

print("PROVENANCE_SCAN_CONTROLS=4/4")
