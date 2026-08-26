#!/usr/bin/env python3
"""OOB-ADJ-R03: attestation binds to the exact candidate (candidate-field fingerprint), ambiguous
duplicates never suppress, declared-fact mismatch rejected, fault-after-success leaves no stale."""
import sys, json, importlib.util, pathlib, tempfile
H = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("adjudicate_oob", H/"adjudicate_oob.py")
A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)
SC = {"WinWebAuthnManager.cpp": "65cbd51f84bf131d0ab7d024417a78f0ebbd3a1aabd98093dc8d05979b643f97"}
ok = tot = 0
def ck(n, c):
    global ok, tot; tot += 1; ok += bool(c); print(("PASS " if c else "FAIL ") + n)
def adj(out, tru=None, sc=SC):
    return A.adjudicate(H/"row3_vuln.program.json", out, trusted_attestations=tru or {}, scanned_content=sc)
with tempfile.TemporaryDirectory() as td:
    td = pathlib.Path(td)
    r = adj(td/"b"); fp = json.loads((td/"b"/"evidence_v0.json").read_text())["candidates"][0]["candidate_fingerprint"]
    ck("baseline 1 candidate", r["candidates"] == 1)
    ck("matching fingerprint suppresses", adj(td/"m", tru={fp:{"proposed_value":"SAFE","confidence":"HIGH"}})["packets"] == 0)
    ck("declared-fact mismatch -> rejected (packet emitted)",
       adj(td/"mm", tru={fp:{"proposed_value":"SAFE","confidence":"HIGH","declared_facts":{"array":"WRONG"}}})["packets"] == 1)
    disp, use, _ = A.disposition(fp, {"file":"x"}, True, {}, {fp:{"proposed_value":"SAFE","confidence":"HIGH"}}, {fp})
    ck("ambiguous duplicate fingerprint -> never suppress", use == "AMBIGUOUS_FINGERPRINT_NO_SUPPRESS")
    d = td/"stale"; adj(d); had = len(list(d.glob("llm_input_*.json")))
    orig = A._load_producer
    class _Boom:
        def emit_candidates(self, p): raise RuntimeError("fault")
    A._load_producer = lambda: _Boom(); raised = False
    try: A.adjudicate(H/"row3_vuln.program.json", d, scanned_content=SC)
    except Exception: raised = True
    A._load_producer = orig
    ck("fault after success -> raises & no stale packet", had == 1 and raised and len(list(d.glob("llm_input_*.json"))) == 0)
print(f"OOB_ADJ_R03={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
