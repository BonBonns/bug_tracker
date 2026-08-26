#!/usr/bin/env python3
"""Global-mutation -> CanonicalEvidenceSet (shared-state / aliasing semantics).

Fifth semantic shape. The security relationship: a control-weakening write to a
security member lands on an object OTHER CONSUMERS SHARE (a module singleton /
process-global), so the weakened control is observable process-wide -- as opposed
to a write confined to a local or per-call object.

The property is NOT "assignment to an imported member". It is:
    aliasing_scope(base) is SHARED  AND  control_effect(write) WEAKENS  AND observable
Kinds/flags are only evidence. Closure requires establishing BOTH aliasing scope and
control effect; if either is unresolved -> SEMANTICALLY_OPEN.

Value-flow fields NOT_APPLICABLE (a state/aliasing mechanism, not a value path).
"""
import collections, sys
from pathlib import Path

RAW = Path(sys.argv[1] if len(sys.argv) > 1 else "gm-out/raw")
NA = {"status": "NOT_APPLICABLE", "reason": "global-mutation is a shared-state/aliasing question; "
      "an attacker value path is not required to characterise the mechanism"}


def rows(name, n):
    p = RAW / name
    seen, out = set(), []
    for ln in (p.read_text().splitlines() if p.exists() else []):
        f = ln.split("\t")
        if len(f) == n and ln not in seen:
            seen.add(ln); out.append(f)
    return out


binding = {}   # (file, short_method, name) -> kind
for r in rows("base_bindings.tsv", 4):
    file_, method, name, kind = r
    binding[(file_.split("/")[-1], method.split(":")[-1], name.strip())] = kind

percall = collections.defaultdict(list)
for r in rows("percall_overrides.tsv", 5):
    percall[(r[0].split("/")[-1], r[1].split(":")[-1])].append(r[4])

writes = collections.defaultdict(list)
for r in rows("singleton_writes.tsv", 8):
    file_, method, line, base, member, is_import, rhs_identity, rhs_code = r
    writes[(file_.split("/")[-1], method.split(":")[-1])].append({
        "line": line, "base": base.strip(), "member": member, "is_import": is_import == "true",
        "rhs_identity": rhs_identity == "true", "rhs_code": rhs_code})


def aliasing_scope(file_, method, w):
    if w["is_import"]:
        return "SHARED_SINGLETON", "base is an imported module singleton"
    kind = binding.get((file_, method, w["base"]), "UNKNOWN")
    if kind in ("IMPORT", "IMPORT_ALIAS"):
        return "SHARED_SINGLETON", "base aliases an imported singleton (%s)" % kind
    if kind == "LOCAL_OBJECT":
        return "LOCAL", "base is a local object literal"
    if w["base"].startswith("_tmp"):
        return "LOCAL", "base is a compiler temp for object-literal construction (never a shared import)"
    if kind == "PARAM":
        return "UNKNOWN", "base is a parameter; the caller may pass a shared object"
    return "UNKNOWN", "base binding unresolved"


def control_effect(w):
    if w["rhs_identity"]:
        return "WEAKENS", "rhs is an identity/no-op, disabling the control"
    return "UNKNOWN", "rhs semantics unresolved; cannot establish the write weakens the control"


def classify(scope, effect):
    # closure: need BOTH shared-scope AND weakening established.
    if scope == "LOCAL":
        return "SAFE_LOCAL_OBJECT_MUTATION", "SEMANTICALLY_CLOSED", None
    if scope == "SHARED_SINGLETON" and effect == "WEAKENS":
        return "CANDIDATE_GLOBAL_SECURITY_OVERRIDE", "SEMANTICALLY_CLOSED", None
    if scope == "SHARED_SINGLETON" and effect == "UNKNOWN":
        return "NEEDS_SEMANTIC_REVIEW", "SEMANTICALLY_OPEN", \
            "The write targets a shared singleton but the replacement's semantics are unresolved. "\
            "Does it weaken the security control, or replace it with an equivalent/stronger one?"
    # scope UNKNOWN
    return "NEEDS_SEMANTIC_REVIEW", "SEMANTICALLY_OPEN", \
        "The base's aliasing scope is unresolved (parameter/unknown). Is it a shared object other "\
        "consumers observe, or confined to this call?"


def build(file_, method):
    ws = writes[(file_, method)]
    alternatives = []
    for w in ws:
        scope, sreason = aliasing_scope(file_, method, w)
        effect, ereason = control_effect(w)
        verdict, coverage, q = classify(scope, effect)
        alternatives.append({"base": w["base"], "member": w["member"], "aliasing_scope": scope,
                             "control_effect": effect, "observability": ("SHARED" if scope == "SHARED_SINGLETON"
                             else "ISOLATED" if scope == "LOCAL" else "UNKNOWN"),
                             "verdict": verdict, "coverage": coverage, "question": q})
    has_percall = (file_, method) in percall
    if not alternatives:
        if has_percall:
            return {"file": file_, "method": method, "alternatives": [],
                    "verdict": "SAFE_PERCALL_OVERRIDE", "coverage": "SEMANTICALLY_CLOSED"}
        return None
    verds = [a["verdict"] for a in alternatives]
    if "CANDIDATE_GLOBAL_SECURITY_OVERRIDE" in verds:
        mv, mc = "CANDIDATE_GLOBAL_SECURITY_OVERRIDE", "SEMANTICALLY_CLOSED"
    elif "NEEDS_SEMANTIC_REVIEW" in verds:
        mv, mc = "NEEDS_SEMANTIC_REVIEW", "SEMANTICALLY_OPEN"
    elif has_percall:
        mv, mc = "SAFE_PERCALL_OVERRIDE", "SEMANTICALLY_CLOSED"
    else:
        mv, mc = "SAFE_LOCAL_OBJECT_MUTATION", "SEMANTICALLY_CLOSED"
    return {"file": file_, "method": method, "alternatives": alternatives, "verdict": mv, "coverage": mc}


if __name__ == "__main__":
    keys = set(writes) | {k for k in percall}
    for (file_, method) in sorted(keys):
        if method == "program":
            continue
        ev = build(file_, method)
        if ev is None:
            continue
        print(f"[{ev['file']}::{ev['method']}] verdict={ev['verdict']}  coverage={ev['coverage']}")
        for a in ev["alternatives"]:
            print(f"     base={a['base']}.{a['member']} scope={a['aliasing_scope']} "
                  f"effect={a['control_effect']} obs={a['observability']} -> {a['verdict']}  "
                  f"[value-flow: {NA['status']}]")
            if a["question"]:
                print(f"        Q: {a['question']}")
