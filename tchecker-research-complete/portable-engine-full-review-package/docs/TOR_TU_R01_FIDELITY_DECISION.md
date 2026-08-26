# TOR-TU-R01 — translation-unit fidelity vs scope DECISION. One bounded build attempt + decide.
# Question: can a faithful TU build (or.h before onion.h) be produced HERE, and is it worth it?
# DECISION: NO to a full TU build here; ACCEPT PARTIAL RESOLUTION (option B). Recorded below.

## THE BOUNDED ATTEMPT (one, then stop)
Built a TU probe _tu_probe.c = { #include "orconfig.h"; #include "core/or/or.h";
#include "core/or/onion.h"; } with the full src/ tree as include root.
RESULT: 0 members emitted. ROOT CAUSE: orconfig.h is NOT in the source tree — it is GENERATED
by ./configure (autotools). Without it the TU cannot fully preprocess, so c2cpg emits no
struct members. A faithful TU build therefore requires running Tor's real build
(./configure && make with full autotools + dependencies) to generate orconfig.h and a
compile-command database. That is a full build environment, NOT a bounded scan step.

## PARTIAL-YIELD MEASUREMENT (best-available directory build, quantifies option B)
Of 20 distinct struct-ARRAY members in core/or:
  RESOLVED (typeFullName has [N]): 15   digest[20], histogram[100], next_state[7],
                                        circuit_build_times[1000], identity_digest[20], ...
  ABSTAIN  (typeFullName T[]):       5   payload[CELL_PAYLOAD_SIZE], onionskin[MAX_CREATE_LEN],
                                        reply[MAX_CREATED_LEN] (all need or.h's CELL_PAYLOAD_SIZE);
                                        one DIGEST_LEN case (header not in scope);
                                        payload[FLEXIBLE_ARRAY_MEMBER] (genuine flexible array)
So 75% (15/20) resolve WITHOUT any TU fidelity work; only 25% hit the header-dependency wall,
and one of those (flexible array) is correctly unsized regardless.

## DECISION: ACCEPT PARTIAL RESOLUTION (option B), do NOT pursue full-build fidelity here
Rationale:
  - A faithful TU/compile-db build needs orconfig.h from ./configure + full autotools deps —
    out of scope for this environment and a large time sink with uncertain payoff.
  - 15/20 members already resolve on the best-available build; capacity for those is derivable
    by the EXISTING _fixed_array_capacity (no new layer). The engine can produce REAL,
    non-zero capacity on properly-resolved Tor members TODAY.
  - The 5 abstaining members (onionskin/reply/payload)ABSTAIN SOUNDLY: typeFullName is T[],
    the frontend genuinely did not resolve the size in that parse scope, and the engine must
    NOT invent it (no source-text inference of 505). Abstention is the correct behavior.
  - This keeps the discipline: capacity only from frontend-resolved dimensions; unresolved ->
    abstain. It does not special-case Tor or read #defines from source.

## WHAT THIS MEANS FOR THE create_cell_init:110 THESIS SITE
onionskin remains T[] (abstains) under realistic builds -> R02b emits NO capacity for it, for
the header-dependency reason now fully characterized. This is HONEST and CORRECT: the engine
abstains because the dimension is genuinely unresolved in that parse, not because of a bug.
NOTE: even with capacity, create_cell_init:110's guard is INTERPROCEDURAL (caller
parse_create2_payload), so it would remain a TOR-B3 case, not "safe". So the specific thesis
site is doubly gated (header-dependency capacity + interprocedural guard) and is NOT the site
to demonstrate R02b. A RESOLVED member with an intraprocedural guard would be.

## REVISED R02b DISPOSITION
R02b (capacity consumes field identity) is SOUND and its teeth pass. On Tor it yields capacity
for the 15 resolved members and abstains for the 5 unresolved — a PARTIAL, HONEST, non-zero
result, NOT the "0 on Tor" artifact from the broken flat scan. To SHIP R02b still requires:
  1. the GUARD-R01 capacity-control update (assert new resolution invariant) — still owed;
  2. re-running R02b on a properly-built (directory-level, includes-resolved) Tor facts set and
     adjudicating any candidate movement on the 15 resolved members.
Neither is done here (TOR-TU-R01 is a DECISION milestone). R02b stays PARKED, but its Tor
prospects are now understood as PARTIAL-POSITIVE, not zero.

## STATUS
Decision: accept partial resolution; do NOT build full-fidelity TUs in this environment
(orconfig.h/./configure required). Best-available build resolves 15/20 core/or array members;
5 abstain soundly (header dependency / flexible array). No source-text size inference. Engine
frozen at R02a.1 (9c535347e330c483), core 7ad2880e04e84fd5, tcpdump 11, raft 8, canonical
31/31 — UNCHANGED. If R02b is later shipped: update GUARD-R01 control, replay on directory
build, adjudicate the 15-member candidate movement.
