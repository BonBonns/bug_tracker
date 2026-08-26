#!/usr/bin/env python3
"""Global shared-singleton security-control mutation verdict — the JS/TS shape
of the Unleash CWE-116 bug (GHSA-w4mq-xh27-6xpx).

PATTERN
-------
Assigning to a security-sensitive member of an IMPORTED shared module singleton
(`Mustache.escape = (t) => t`) disables that control for every consumer in the
process, because Node's module cache shares one object instance. The safe fix
passes the override PER CALL (`render(a, c, undefined, { escape })`) and never
mutates the shared object.

DISCRIMINATOR (fully static)
  base_is_import (the assignment target is a require()/import binding, i.e. a
  process-shared singleton) is the load-bearing signal. Weakening the control to
  an identity function raises confidence (escaping becomes a literal no-op).
  These break the pattern (all present as negative controls):
    * base is a LOCAL object you own (not imported)   -> safe
    * the override is passed PER CALL in an options obj -> safe
    * the member is only READ/called, never assigned   -> safe

VERDICTS (CANDIDATE, never "VULNERABLE")
  CANDIDATE_GLOBAL_SECURITY_OVERRIDE   assignment to an imported module's
     security member. Confidence HIGH when the rhs is an identity function.
  SAFE_PERCALL_OVERRIDE                the override is passed per-call.
  SAFE_LOCAL_OBJECT_MUTATION           base is a local object, not imported.
  SAFE_NO_SINGLETON_WRITE              no security-member assignment present.

CEILINGS
  * import detection uses require()/import bindings; a singleton obtained through
    an indirection (`const M = getMustache()`) is under-approximated.
  * per-call recognition keys on an options-object override reaching a render
    call in the same method; an override threaded through a helper is missed
    (would fall back to inspecting the singleton write, which is absent here).
  * identity-function detection covers arrow/function bodies returning the sole
    parameter; a semantically-weakening-but-not-identity escape (e.g. one that
    strips only some entities) is reported as a write without the identity flag.
"""
import json, sys
from pathlib import Path


def _rows(p, n):
    p = Path(p)
    if not p.exists():
        raise FileNotFoundError(f"required global-mutation fact file missing: {p}")
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
    writes = _rows(raw / "singleton_writes.tsv", 8)
    overrides = _rows(raw / "percall_overrides.tsv", 5)
    reads = _rows(raw / "security_member_reads.tsv", 3)

    # group by package (top-level dir), which is how the fixture is organized;
    # for a real repo the natural unit is the file, so also key by file.
    override_files = {r[0] for r in overrides}

    # per file: is there an imported-base security write? a local write? any?
    by_file = {}
    for f_, meth, line, base, member, is_import, is_ident, rhs in writes:
        rec = by_file.setdefault(f_, {"import_writes": [], "local_writes": []})
        entry = {"line": line, "base": base, "member": member,
                 "identity": is_ident == "true", "rhs": rhs}
        if is_import == "true":
            rec["import_writes"].append(entry)
        else:
            rec["local_writes"].append(entry)

    findings = []
    # every file that has ANY security-member activity gets a verdict
    all_files = set(by_file) | override_files | {r[0] for r in reads}
    for f_ in sorted(all_files):
        rec = by_file.get(f_, {"import_writes": [], "local_writes": []})
        has_percall = f_ in override_files

        if rec["import_writes"]:
            iw = rec["import_writes"][0]
            verdict = "CANDIDATE_GLOBAL_SECURITY_OVERRIDE"
            confidence = "HIGH" if any(w["identity"] for w in rec["import_writes"]) else "MEDIUM"
            findings.append({"file": f_, "package": _pkg(f_), "verdict": verdict,
                             "confidence": confidence,
                             "base": iw["base"], "member": iw["member"],
                             "identity_function": any(w["identity"] for w in rec["import_writes"]),
                             "line": iw["line"]})
        elif has_percall and not rec["import_writes"]:
            findings.append({"file": f_, "package": _pkg(f_),
                             "verdict": "SAFE_PERCALL_OVERRIDE"})
        elif rec["local_writes"]:
            findings.append({"file": f_, "package": _pkg(f_),
                             "verdict": "SAFE_LOCAL_OBJECT_MUTATION",
                             "base": rec["local_writes"][0]["base"]})
        else:
            findings.append({"file": f_, "package": _pkg(f_),
                             "verdict": "SAFE_NO_SINGLETON_WRITE"})

    return {
        "schema": "global-singleton-mutation-verdict/0.1",
        "note": ("CANDIDATE, never VULNERABLE. Flags assignment to a security-"
                 "sensitive member (escape/sanitize/encode/...) of an IMPORTED "
                 "shared module singleton -- the JS/TS shape of the Unleash "
                 "Mustache.escape global-override bug (CWE-116). A per-call "
                 "override or a local-object mutation is safe and cleared."),
        "findings": findings,
    }


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1] if len(sys.argv) > 1 else "gmut-out/raw"), indent=2))
