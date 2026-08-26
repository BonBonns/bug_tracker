#!/usr/bin/env python3
"""JS-PROV-R09 — FrameworkRegistrationFact recognition.

Consumes JS-PROV-R08's ObservedParameterTypeFact to recognize framework route
registrations whose receiver is a parameter typed ANY in the CPG.

WHY THIS ORDERING MATTERS (JS-PROV-R07)
---------------------------------------
R07 measured that when a receiver is ANY:
  - methodFullName may be POPULATED BUT WRONG (5/14 Corpus-B `get` sites
    resolved to `ctx:cookies:...:get`), and
  - the resolved callee AGREES with that wrong value, so the two are NOT
    independent signals -- agreement is correlated error, not corroboration.

Therefore this module NEVER uses methodFullName or resolved-callee identity to
establish framework ownership. Framework identity comes exclusively from
RECEIVER-DOMAIN EVIDENCE (R08). The call's own name only SELECTS which HTTP
verb is being registered once the receiver is already established -- Level 1
alone is never sufficient, exactly as R07 required.

FRAMEWORK PROFILE
-----------------
EXPLICIT, EXTERNAL, CURATED -- policy, not inference, in the same spirit as
security_sink_profile.py. Framework identity is matched against observed
receiver types by EXACT string equality against this closed table. An
unrecognized module yields UNKNOWN, never "not a framework".

WHAT THIS DOES NOT ESTABLISH
----------------------------
Where a handler came from is not where the values inside it came from.
`ctx.validatedData.*` remains a separate middleware-provenance problem
(JS-PROV-R03), untouched here.
"""
import json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from observed_parameter_types import derive as derive_observed  # noqa: E402

# EXPLICIT framework profile. Replace/extend per deployment. Keys are exact
# observed receiver type strings; values are (framework_family, verbs).
_FRAMEWORK_RECEIVERS = {
    "@koa/router": ("KOA_ROUTER", {"get", "post", "put", "delete", "patch", "all"}),
    # `koa-router` is the pre-fork package name; both are in use. Listed
    # EXPLICITLY as separate profile entries -- never matched by normalising or
    # fuzzy-matching specifier strings.
    "koa-router":  ("KOA_ROUTER", {"get", "post", "put", "delete", "patch", "all"}),
    "koa":         ("KOA_APP",    {"use"}),
    "express":     ("EXPRESS",    {"get", "post", "put", "delete", "patch", "use", "all"}),
}


def _rows(p, n):
    p = Path(p)
    if not p.exists():
        return []
    out = []
    for ln in p.read_text().splitlines():
        if not ln.strip():
            continue
        xs = ln.split("\t")
        if len(xs) == n:
            out.append(xs)
    return out


def derive(raw):
    observed = derive_observed(raw)

    # (callee_method_fullname, param_index) -> observed fact
    obs_by_param = {
        (f["callee_full_name"], f["parameter_index"]): f
        for f in observed["facts"]
    }

    registrations, abstentions = [], []

    for r in _rows(Path(raw) / "registrations.tsv", 9):
        (call_id, name, mfn, in_method, recv_name, recv_type,
         param_method, param_index, nargs) = r
        if not param_method:
            # JS-PROV-R29: DIRECT (non-parameter) receiver. Its type comes from
            # its own initializer (`const router = new Router()`), NOT from
            # Joern's interprocedural propagation -- which is the mechanism that
            # produced the wrong parameter types noted below. Measured support:
            #   R07 fixture   `direct` -> @koa/router  (real, correct)
            #                 `fr`     -> FakeRouter   (fake, correct)
            #   Corpus D      `router` -> koa-router   (15/15, correct)
            # The framework profile is unchanged: only a receiver whose OWN type
            # is in that closed table qualifies. ANY, or any non-profiled type,
            # yields nothing -- no guessing, and no fallback to names.
            hit = _FRAMEWORK_RECEIVERS.get(recv_type)
            if hit is None:
                continue                   # not a profiled framework receiver
            family, verbs = hit
            if name not in verbs:
                abstentions.append({"call_id": int(call_id), "call_name": name,
                                    "receiver_param": f"<direct>{recv_name}",
                                    "reason": "CALL_NAME_NOT_A_REGISTRATION_VERB",
                                    "detail": {"framework": family, "name": name}})
                continue
            registrations.append({
                "registration_call_id": int(call_id),
                "verb": name,
                "framework_family": family,
                "framework_identity": recv_type,
                "identity_evidence": "DIRECT_RECEIVER_TYPE",
                "receiver_parameter": None,
                "receiver_local": recv_name,
                "receiver_evidence_calls": [],
                "declaring_method": in_method,
                "argument_count": int(nargs),
                "cpg_receiver_type": recv_type,
                "cpg_receiver_type_disagrees": False,
                "resolution": "ESTABLISHED",
            })
            continue
        # NOTE (JS-PROV-R09 measurement): the receiver's own typeFullName is
        # NOT trusted, even when it is concrete. On the R08 fixture jssrc2cpg
        # assigned `t:ts::program:FakeRouter` (note the malformed ':ts::'
        # separator, the R04/R05 defect) to EVERY router parameter -- including
        # the one that genuinely receives an @koa/router. Joern's own type
        # recovery performs a form of propagation and got it wrong. Trusting
        # recv_type here would have mis-registered the real router as a fake.
        # R08 receiver-domain evidence is used instead, and any disagreement is
        # recorded rather than silently resolved.

        key = (param_method, int(param_index))
        fact = obs_by_param.get(key)

        def abstain(reason, extra=None):
            abstentions.append({"call_id": int(call_id), "call_name": name,
                                "receiver_param": f"{param_method}#{param_index}",
                                "reason": reason, "detail": extra})

        if fact is None:
            abstain("NO_RECEIVER_EVIDENCE"); continue
        if not fact["domain_established"]:
            # includes the ANY-contaminated case: observing a framework type is
            # NOT enough if any callsite passed ANY (JS-STATE-R11 invariant)
            abstain("RECEIVER_DOMAIN_NOT_ESTABLISHED",
                    {"observed": fact["observed_types"],
                     "unconstrained": fact["unconstrained_callsite"]}); continue

        types = fact["observed_types"]
        hits = [t for t in types if t in _FRAMEWORK_RECEIVERS]
        if not hits:
            abstain("RECEIVER_NOT_A_PROFILED_FRAMEWORK", {"observed": types}); continue
        if len(types) > 1:
            # a receiver observed as BOTH a framework and something else is not
            # a proven framework receiver at this site
            abstain("RECEIVER_AMBIGUOUS_ACROSS_CALLSITES", {"observed": types}); continue

        family, verbs = _FRAMEWORK_RECEIVERS[hits[0]]
        if name not in verbs:
            abstain("CALL_NAME_NOT_A_REGISTRATION_VERB",
                    {"framework": family, "name": name}); continue

        registrations.append({
            "registration_call_id": int(call_id),
            "verb": name,
            "framework_family": family,
            "framework_identity": hits[0],
            "identity_evidence": "RECEIVER_DOMAIN_EVIDENCE",   # never methodFullName
            "receiver_parameter": {"method": param_method, "index": int(param_index)},
            "receiver_evidence_calls": fact["source_call_ids"],
            "declaring_method": in_method,
            "argument_count": int(nargs),
            "cpg_receiver_type": recv_type,
            "cpg_receiver_type_disagrees": (recv_type not in ("ANY", "") and recv_type != hits[0]),
            "resolution": "ESTABLISHED",
        })

    return {
        "schema": "portable-framework-registration/0.1",
        "note": ("Framework identity derived ONLY from receiver-domain evidence "
                 "(JS-PROV-R08). methodFullName and resolved-callee identity are "
                 "deliberately NOT used: JS-PROV-R07 measured them as correlated "
                 "error under an ANY receiver. Call name selects the verb only "
                 "AFTER the receiver is established."),
        "registrations": registrations,
        "abstentions": abstentions,
    }


if __name__ == "__main__":
    print(json.dumps(derive(sys.argv[1]), indent=2, default=str))
