#!/usr/bin/env python3
"""OOB-ADJ-R04: identity/content binding is DERIVED by trusted runtime, not caller labels.
Content identity = full sha256 of the ACTUAL scanned bytes (dirty worktree covered); analyzer
identity = full sha256 of component files on disk; full 64-hex used; fail-closed on unverified
content; no caller field selects identity; suppression recomputes the fingerprint from facts."""
import sys, json, importlib.util, pathlib, tempfile, hashlib
H = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("adjudicate_oob", H/"adjudicate_oob.py")
A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)
ok = tot = 0
def ck(n, c):
    global ok, tot; tot += 1; ok += bool(c); print(("PASS " if c else "FAIL ") + n)

CONTENT_A = hashlib.sha256(b"file bytes v1").hexdigest()
CONTENT_B = hashlib.sha256(b"file bytes v2 (surrounding code changed)").hexdigest()
FILE = "WinWebAuthnManager.cpp"
def adj(out, sc, adv=None, tru=None):
    return A.adjudicate(H/"row3_vuln.program.json", out, advisory_hints=adv or {},
                        trusted_attestations=tru or {}, scanned_content=sc)

# analyzer identity: full 64-hex, deterministic, and tracks file content
aid1, comps = A.analyzer_identity()
ck("analyzer_identity is full 64-hex sha256", len(aid1) == 64 and all(ch in "0123456789abcdef" for ch in aid1))
ck("analyzer_identity deterministic", A.analyzer_identity()[0] == aid1)
cfgp = A._config_path(); orig = cfgp.read_bytes()
try:
    cfgp.write_bytes(orig + b"\n// analyzer rule/config change\n")
    ck("changing a component file changes analyzer_identity", A.analyzer_identity()[0] != aid1)
finally:
    cfgp.write_bytes(orig)

# fingerprint is full 64-hex and binds every identity/context field
rec = A.fingerprint_record({"class":"OOB_WRITE","subclass":"INDEX_STORE","array":"rg","elem_count":1,
        "index_expr":"c","file":FILE,"line":298,"function":"F","function_line":1,"function_line_end":9}, CONTENT_A, aid1)
fp = A.fingerprint(rec)
ck("fingerprint is full 64-hex sha256", len(fp) == 64)
for k, v in [("content_sha256", CONTENT_B), ("analyzer_identity", "deadbeef"), ("function", "G"),
             ("function_span", [2,9]), ("line", 299), ("array", "rg2"), ("elem_count", 2), ("index_expr","d")]:
    r2 = dict(rec); r2[k] = v
    ck(f"fingerprint binds {k} (change re-fingerprints)", A.fingerprint(r2) != fp)

with tempfile.TemporaryDirectory() as td:
    td = pathlib.Path(td)
    # real candidate fingerprint at content A
    scA = {FILE: CONTENT_A}
    r = adj(td/"a", scA); fpA = json.loads((td/"a"/"evidence_v0.json").read_text())["candidates"][0]["candidate_fingerprint"]
    ck("baseline 1 candidate, content verified", r["candidates"] == 1)
    # matching attestation suppresses
    ck("matching-fingerprint trusted attestation suppresses", adj(td/"s", scA, tru={fpA:{"proposed_value":"SAFE","confidence":"HIGH"}})["packets"] == 0)
    # DIRTY WORKTREE / surrounding-code change: candidate fields identical, only content bytes differ
    scB = {FILE: CONTENT_B}
    rB = adj(td/"b", scB, tru={fpA:{"proposed_value":"SAFE","confidence":"HIGH"}})
    fpB = json.loads((td/"b"/"evidence_v0.json").read_text())["candidates"][0]["candidate_fingerprint"]
    ck("content change (same candidate fields) re-fingerprints", fpB != fpA)
    ck("stale attestation does NOT suppress changed-content code", rB["packets"] == 1)
    # FAIL CLOSED: content not verified (file absent from scanned_content) -> never suppress
    rN = adj(td/"n", {}, tru={fpA:{"proposed_value":"SAFE","confidence":"HIGH"}})
    evN = json.loads((td/"n"/"evidence_v0.json").read_text())["candidates"][0]
    ck("unverified content -> FAIL CLOSED (packet emitted)", rN["packets"] == 1 and evN["disposition"] == "CANDIDATE_OPEN")
    ck("unverified content -> flagged UNVERIFIED_CONTENT_FAIL_CLOSED", evN["adjudication_use"] == "UNVERIFIED_CONTENT_FAIL_CLOSED")
    # NO CALLER FIELD SELECTS IDENTITY: a trusted-channel entry declaring analyzer_identity/content/
    # candidate_fingerprint has them stripped; only the fp KEY (recomputed) matters.
    forged = A._norm({"proposed_value":"SAFE","confidence":"HIGH","analyzer_identity":"x","content_sha256":"y","candidate_fingerprint":"z"}, "CURATED_ATTESTATION_CHANNEL")
    ck("caller-declared identity fields are stripped", not any(k in forged for k in ("analyzer_identity","content_sha256","candidate_fingerprint")))
    # a trusted attestation keyed by a FABRICATED fp (not recomputed) does NOT suppress
    ck("fabricated-fingerprint attestation does NOT suppress (recompute-not-echo)",
       adj(td/"fab", scA, tru={"f"*64:{"proposed_value":"SAFE","confidence":"HIGH"}})["packets"] == 1)

print(f"OOB_ADJ_R04={ok}/{tot}")
sys.exit(0 if ok == tot else 1)
