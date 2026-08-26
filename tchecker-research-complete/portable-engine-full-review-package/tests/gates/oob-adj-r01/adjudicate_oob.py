#!/usr/bin/env python3
"""OOB-ADJ (R01/R02/R03/R04) — stage OOB index-store CANDIDATEs into the shared
tchecker-llm-packet/1.0 review pipeline, preserving CANDIDATE (never VULNERABLE).

Trust model:
 R02 trust is a property of the INGESTION CHANNEL, never of a field inside a hint.
 R03 a trusted attestation binds to a canonical evidence fingerprint (applies to ONE candidate).
 R04 the identity fields IN that fingerprint are DERIVED by trusted runtime code, never accepted as
     caller labels:
       - content identity = full SHA-256 of the ACTUAL scanned file bytes (covers uncommitted /
         untracked / dirty-worktree edits; a commit id does NOT). Supplied by the trusted scanner
         from the exact bytes it fed the frontend; if absent for a candidate's file we FAIL CLOSED
         (never suppress).
       - analyzer identity = full SHA-256 over the analyzer component files on disk (producer +
         this adapter + rule/config + frontend normalizer/export when locatable). A manual version
         string is never used.
     The FULL sha-256 is used (64 hex). Serialization is explicit canonical JSON (fixed field names,
     sorted keys, compact separators, ascii). Suppression is decided ONLY on a fingerprint recomputed
     here from producer facts + trusted digests — never from any fingerprint echoed in a packet/hint.
"""
import argparse, json, hashlib, importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent

def _find(rel):
    for base in (HERE, HERE.parent, HERE.parent.parent, HERE.parent.parent.parent):
        p = base / rel
        if p.exists():
            return p
    return None

def _load_producer():
    spec = importlib.util.spec_from_file_location("oiw", _find("oob_index_write_verdict.py"))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m

def _config_path():
    return _find("property_configs/oob_index_write.json")

def _config():
    return json.loads(_config_path().read_text())

# ---- explicit canonical serialization (fixed field names + types) ----
def _canon(rec):
    return json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

def _sha256_file(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

# ---- R04 analyzer identity: full hash over analyzer component files on disk ----
_ANALYZER_COMPONENT_RELS = (
    "oob_index_write_verdict.py",                                   # producer (rules)
    "adjudicate_oob.py",                                            # this adapter
    "property_configs/oob_index_write.json",                       # config
    "tests/gates/cpp-r06/frontend/normalize_c_cpp_facts_v03.py",   # frontend normalizer (fact rules)
    "tests/gates/cpp-r06/frontend/export_c_cpp_facts_v03.sc",      # frontend exporter
    "portable-engine-full-review-package/tests/gates/cpp-r06/frontend/normalize_c_cpp_facts_v03.py",
    "portable-engine-full-review-package/tests/gates/cpp-r06/frontend/export_c_cpp_facts_v03.sc",
)
def analyzer_identity():
    comps = {}
    for rel in _ANALYZER_COMPONENT_RELS:
        p = _find(rel)
        if p is not None and p.is_file():
            comps[Path(rel).name] = _sha256_file(p)
    payload = _canon({"components": comps})               # sorted, deterministic
    return hashlib.sha256(payload.encode()).hexdigest(), sorted(comps.keys())

# ---- R04 canonical fingerprint record (fixed names + types) ----
def fingerprint_record(cand, content_sha256, analyzer_id):
    return {
        "analyzer_identity": str(analyzer_id),
        "content_sha256": str(content_sha256),          # full sha-256 of the ACTUAL scanned file bytes
        "file": str(cand.get("file") or ""),
        "candidate_class": str(cand.get("class") or ""),
        "subclass": str(cand.get("subclass") or "INDEX_STORE"),
        "array": str(cand.get("array") or ""),
        "elem_count": int(cand.get("elem_count")) if cand.get("elem_count") is not None else -1,
        "index_expr": str(cand.get("index_expr") or ""),
        "function": str(cand.get("function") or ""),
        "line": int(cand.get("line")) if cand.get("line") is not None else -1,
        "function_span": [int(cand.get("function_line") or -1), int(cand.get("function_line_end") or -1)],
    }

def fingerprint(rec):
    return hashlib.sha256(_canon(rec).encode()).hexdigest()      # FULL 64-hex sha-256

def property_id(fp):
    return f"oob-index:{fp}.index_within_capacity"

# ---- R02 channel-assigned trust; strip ALL caller-declared identity/trust claims ----
_STRIP = ("source", "trust", "trusted", "_channel_trust", "_trust", "provenance",
          "candidate_fingerprint", "analyzer_identity", "content_sha256", "repo_rev")

def _norm(h, channel_source):
    base = {k: v for k, v in h.items() if k not in _STRIP}
    base["source"] = channel_source
    return base

def load_channels(advisory_path=None, trusted_path=None):
    def _load(p):
        p = Path(p) if p else None
        return json.loads(p.read_text()) if (p and p.exists()) else {}
    advisory = {k: _norm(v, "UNTRUSTED_CHANNEL") for k, v in _load(advisory_path).items()}
    trusted  = {k: _norm(v, "CURATED_ATTESTATION_CHANNEL") for k, v in _load(trusted_path).items()}
    return advisory, trusted

def _facts_match(declared, rec):
    if not declared:
        return True
    for k in ("file", "array", "elem_count", "index_expr", "line", "candidate_class", "function"):
        if k in declared and declared[k] != rec.get(k):
            return False
    return True

def disposition(fp, rec, content_verified, advisory, trusted, ambiguous):
    if not content_verified:
        return "CANDIDATE_OPEN", "UNVERIFIED_CONTENT_FAIL_CLOSED", None   # cannot bind -> never suppress
    if fp in ambiguous:
        return "CANDIDATE_OPEN", "AMBIGUOUS_FINGERPRINT_NO_SUPPRESS", None
    t = trusted.get(fp)                     # keyed by RECOMPUTED fingerprint; packet echoes never consulted
    if t is not None:
        if not _facts_match(t.get("declared_facts"), rec):
            return "CANDIDATE_OPEN", "REJECTED_FACT_MISMATCH", t
        if t.get("confidence") == "HIGH" and t.get("proposed_value") == "SAFE":
            return "RESOLVED_SAFE_BY_ACCEPTED_HINT", "ACCEPTED_HINT", t
        if t.get("confidence") == "HIGH" and t.get("proposed_value") == "UNSAFE":
            return "RESOLVED_CANDIDATE_BY_ACCEPTED_HINT", "ACCEPTED_HINT", t
        return "CANDIDATE_OPEN", "NEEDS_MORE_REVIEW", t
    u = advisory.get(fp)
    if u is not None:
        return "CANDIDATE_OPEN", "ADVISORY_ONLY_UNTRUSTED_CHANNEL", u
    return "CANDIDATE_OPEN", None, None

def packet(fp, rec, cand, cfg, prior, analyzer_components):
    arr, idx, n = cand["array"], cand["index_expr"], cand["elem_count"]
    q = cfg["focused_question_template"].format(array=arr, index_expr=idx, elem_count=n)
    return {
        "schema": "tchecker-llm-packet/1.0", "round": 1,
        "finding_id": f"oob-index-write:{rec['file']}#L{rec['line']}:{arr}",
        "property_id": property_id(fp), "candidate_fingerprint": fp,
        "candidate_evidence_bound": rec, "analyzer_components": analyzer_components,
        "candidate_class": cand["class"], "deterministic_status": "UNKNOWN",
        "candidate_evidence": {
            "established_shape": "INDEXED_STORE_INTO_FIXED_CAPACITY_ARRAY",
            "capacity_status": "EXACT_SYNTACTIC_ELEM_COUNT", "capacity_elem_count": n,
            "index_bound_status": "UNESTABLISHED",
            "limitation": "The array capacity is known; no bound index<capacity is established on all "
                          "paths. No vulnerability/triggerability/attacker control is established.",
        },
        "PRIOR_SEMANTIC_HINTS_ADVISORY": list(prior),
        "unresolved_subject": {"deterministic_status": "UNKNOWN", "node_kind": "INDEX_EXPRESSION", "index_expr": idx},
        "QUESTION": q,
        "answer_contract": {
            "source_must_be": "LLM", "proposed_value": "SAFE | UNSAFE | UNKNOWN",
            "confidence": "LOW | MEDIUM | HIGH", "rationale": "string",
            "must_echo_candidate_fingerprint": fp,
            "note": "Advisory HINT over a heuristic candidate; cannot change the deterministic verdict. "
                    "The fingerprint echoed here is NOT trusted for suppression; the scanner recomputes it.",
            "value_meanings": {
                "SAFE": "the index is guaranteed within [0, capacity-1] on all supplied paths",
                "UNSAFE": "the index can reach or exceed the capacity on some supplied path",
                "UNKNOWN": "the supplied evidence is insufficient",
            },
        },
    }

def adjudicate(program_json, out_dir, advisory_hints=None, trusted_attestations=None,
               scanned_content=None):
    """scanned_content: {file_path: full_sha256_hex} from the TRUSTED scanner (actual scanned bytes).
    Identity is derived here; no caller label selects analyzer/content identity."""
    out_dir = Path(out_dir)
    if out_dir.exists():
        for old in list(out_dir.glob("llm_input_*.json")) + list(out_dir.glob("evidence_v0.json")):
            old.unlink()
    out_dir.mkdir(parents=True, exist_ok=True)
    cfg = _config()
    analyzer_id, analyzer_components = analyzer_identity()      # derived from disk, not passed
    scanned_content = scanned_content or {}
    cands = _load_producer().emit_candidates(str(program_json))   # may raise -> fail loud
    # recompute per-candidate fingerprint from producer facts + trusted digests
    recs = []
    for cand in cands:
        f = cand.get("file")
        content = scanned_content.get(f)
        verified = content is not None
        rec = fingerprint_record(cand, content if verified else "UNVERIFIED", analyzer_id)
        recs.append((fingerprint(rec), rec, verified, cand))
    counts = {}
    for fp, _, _, _ in recs:
        counts[fp] = counts.get(fp, 0) + 1
    ambiguous = {fp for fp, c in counts.items() if c > 1}
    advisory = advisory_hints or {}; trusted = trusted_attestations or {}
    evidence, prior, packets = [], [], 0
    for fp, rec, verified, cand in recs:
        disp, use, hint = disposition(fp, rec, verified, advisory, trusted, ambiguous)
        evidence.append({"finding_id": f"oob-index-write:{rec['file']}#{fp}", "property_id": property_id(fp),
                         "candidate_fingerprint": fp, "content_verified": verified,
                         "candidate_class": cand["class"], "deterministic_status": "UNKNOWN",
                         "semantic_hint": hint, "adjudication_use": use, "disposition": disp})
        if use != "ACCEPTED_HINT":
            pk = packet(fp, rec, cand, cfg, prior, analyzer_components)
            assert "VULNERABLE" not in json.dumps(pk), "invariant: packet must not assert VULNERABLE"
            (out_dir / f"llm_input_{fp}.json").write_text(json.dumps(pk, indent=2) + "\n")
            packets += 1
        if hint:
            prior.append({"property_id": property_id(fp), **hint, "status": "advisory"})
    (out_dir / "evidence_v0.json").write_text(json.dumps(
        {"schema": "oob-index-candidate-evidence/1.2", "analyzer_identity": analyzer_id,
         "analyzer_components": analyzer_components, "candidate_count": len(evidence),
         "candidates": evidence}, indent=2) + "\n")
    return {"candidates": len(evidence), "packets": packets, "out_dir": str(out_dir),
            "analyzer_identity": analyzer_id}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("program_json", type=Path)
    ap.add_argument("out_dir", type=Path)
    ap.add_argument("--advisory-hints", type=Path)
    ap.add_argument("--trusted-attestations", type=Path)
    ap.add_argument("--scanned-content", type=Path, help="JSON {file: full_sha256} from the trusted scanner")
    a = ap.parse_args()
    advisory, trusted = load_channels(a.advisory_hints, a.trusted_attestations)
    sc = json.loads(a.scanned_content.read_text()) if a.scanned_content and a.scanned_content.exists() else {}
    r = adjudicate(a.program_json, a.out_dir, advisory_hints=advisory, trusted_attestations=trusted,
                   scanned_content=sc)
    print(f"OOB_INDEX_ADJUDICATION={r['candidates']} candidates; packets={r['packets']}; analyzer={r['analyzer_identity'][:12]}..")

if __name__ == "__main__":
    main()
