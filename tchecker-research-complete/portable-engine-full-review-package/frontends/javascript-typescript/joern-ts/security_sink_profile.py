#!/usr/bin/env python3
"""JS-STATE-R03: an explicit, human-curated security-sensitive-sink profile.

**This module is policy, not analysis.** JS-STATE-R01 (Q5) found that the
neutral core cannot and must not decide whether a given callee is
"security-sensitive" from anything in the CPG -- there is no structural fact
that distinguishes `authenticate(id)` from `unrelatedSink(id)` other than the
name a programmer happened to choose, and the hard rule forbids trusting
programmer-chosen names as evidence.

So this table is NOT auto-derived, NOT inferred, and NOT a general JS/TS
"detect authentication code" capability. It is exactly what a real deployment
would have to supply externally: a short, explicit, reviewed list of which
particular functions/APIs in a *specific* project or framework are
authentication/authorization/session/identity/token sinks -- the same shape as
Gate 30's context/effect profiles and the C++ track's SINK-R01/SOURCE-R02
profile layer. Anyone using this module for a real codebase must replace
`EXAMPLE_SENSITIVE_SINKS` with their own project's/framework's actual sink
list; the entries below exist only to make the JS-STATE-R02 fixture's
`authenticate()` stand-in resolvable, and must not be read as a claim that
Fable can recognize authentication code in general.

Categories follow the bug-shape spec: AUTHENTICATION, AUTHORIZATION,
SESSION_CREATION, IDENTITY_ASSIGNMENT, TOKEN_ISSUANCE.

Anything NOT in this table is UNKNOWN, never a proven "not sensitive" -- the
absence of a sink-profile entry is not evidence of safety, only evidence that
nobody has classified that callee yet. This module never emits a NOT_SENSITIVE
verdict for that reason: case7/10/11/12 in the JS-STATE-R02 fixture reach
`unrelatedSink`, which is simply UNKNOWN here (not proven safe, not flagged),
exactly matching what JS-STATE-R01 documented as the honest answer.
"""

# EXAMPLE-ONLY. Replace per-project/per-framework before using this in
# anything beyond the JS-STATE-R02/R03 fixtures. Keyed on the plain callee
# name as exported by Joern (`calls.tsv` / `methods.tsv` `name` column) because
# the fixture's sinks are flat `declare function` stubs with no qualified
# import path to key on; a real profile should key on the fully-qualified
# resolved callee (module + export name) wherever the frontend can provide it,
# not on a bare unqualified name, to avoid collisions with unrelated same-named
# functions elsewhere in a real codebase.
EXAMPLE_SENSITIVE_SINKS = {
    "authenticate": "AUTHENTICATION",
}


def classify_sink(callee_name):
    """Return the sink category string, or None if not in the profile.
    None must be read as UNKNOWN, never as a proof of non-sensitivity.
    """
    return EXAMPLE_SENSITIVE_SINKS.get(callee_name)
