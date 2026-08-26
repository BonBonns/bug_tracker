#!/usr/bin/env python3
"""LLM-input vulnerability verdict — OWASP LLM Top-10 shapes in JS/TS.

  LLM02 Insecure Output Handling: model output flows into a code/command/HTML/
        SQL sink without validation -> RCE / injection / XSS.
  LLM01 Prompt Injection: untrusted request data flows into the SYSTEM
        instruction position -> instruction override.

VERDICTS (CANDIDATE, never "VULNERABLE")
  CANDIDATE_INSECURE_LLM_OUTPUT   LLM output reaches a dangerous sink (eval/exec/
     sql/html/redirect) not inside a try/catch or validation.
  CANDIDATE_PROMPT_INJECTION      request data reaches the system-role content.
  SUSPICIOUS_LLM_OUTPUT_HTML      LLM output reaches an HTML response sink (XSS
     risk, but lower-severity than code/command execution).
  SAFE_LLM_OUTPUT_VALIDATED       the output sink is inside try/catch (e.g.
     JSON.parse-and-validate) or the sink is not model-fed.
  SAFE_STATIC_SYSTEM_PROMPT       no request taint into the system role.

CEILINGS
  * output->sink and request->role linkage is intra-method lexical taint; a
    value laundered through a helper is under-approximated (missed, not
    false-alarmed).
  * LLM call-site recognition is by SDK/endpoint pattern (OpenAI, Anthropic,
    Vercel AI SDK, LangChain, provider fetch); a bespoke HTTP wrapper is missed.
  * prompt-injection flags ONLY the system-role position (instruction override);
    user-role injection is not flagged, since sending user input in the user
    role is the intended, normal use of an LLM.
"""
import json, sys
from pathlib import Path


def _rows(p, n):
    p = Path(p)
    if not p.exists():
        raise FileNotFoundError(f"required LLM fact file missing: {p}")
    out, seen = [], set()
    for ln in p.read_text().splitlines():
        if ln.strip() and len(ln.split("\t")) == n:
            xs = ln.split("\t")
            if tuple(xs) not in seen:
                seen.add(tuple(xs)); out.append(xs)
    return out


def _pkg(path):
    parts = Path(path).parts
    return parts[0] if parts else path


def derive(raw):
    raw = Path(raw)
    sinks = _rows(raw / "llm_output_sinks.tsv", 6)
    inject = _rows(raw / "prompt_injection.tsv", 5)

    findings = []

    # LLM02 — insecure output handling
    for f_, meth, line, kind, fed, in_try in sinks:
        if fed != "true":
            continue                       # sink not fed by model output
        pkg = _pkg(f_)
        in_trycatch = in_try == "true"
        # NOTE: try/catch is NOT a mitigation for eval/exec/sql — the dangerous
        # operation still executes; catching the thrown error afterward does
        # nothing. Only output validation/allowlisting before the sink helps,
        # which is not reliably detectable statically (stated ceiling). So model
        # output reaching a code/command/SQL sink is a candidate regardless.
        if kind in ("EVAL", "EXEC", "SQL"):
            verdict = "CANDIDATE_INSECURE_LLM_OUTPUT"
        elif kind in ("HTML_RESPONSE", "REDIRECT"):
            verdict = "SUSPICIOUS_LLM_OUTPUT_HTML"
        else:
            verdict = "SUSPICIOUS_LLM_OUTPUT_HTML"
        findings.append({"file": f_, "package": pkg, "line": line,
                         "shape": "insecure_output_handling", "sink_kind": kind,
                         "fed_by_llm": True, "in_try_catch": in_trycatch,
                         "verdict": verdict})

    # LLM01 — prompt injection into the system role
    seen_inj = set()
    for f_, meth, line, role, tainted in inject:
        if role != "system" or tainted != "true":
            continue
        key = (f_, line)
        if key in seen_inj:
            continue
        seen_inj.add(key)
        findings.append({"file": f_, "package": _pkg(f_), "line": line,
                         "shape": "prompt_injection", "role": role,
                         "request_tainted": True,
                         "verdict": "CANDIDATE_PROMPT_INJECTION"})

    return {
        "schema": "llm-input-verdict/0.1",
        "note": ("CANDIDATE, never VULNERABLE. Flags model output flowing into a "
                 "code/command/HTML/SQL sink (LLM02 insecure output handling) and "
                 "request data flowing into the system instruction position "
                 "(LLM01 prompt injection). Validation (try/catch) or a static "
                 "system prompt de-escalates."),
        "findings": findings,
    }


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1] if len(sys.argv) > 1 else "llm-out/raw"), indent=2))
