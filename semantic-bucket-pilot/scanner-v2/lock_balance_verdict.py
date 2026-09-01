#!/usr/bin/env python3
"""LOCK-SAFE-R01: Capability 1 for the thread-safety property (THREAD_SAFETY_R01.md) --
a general evidence model for ONE representation shape, not a bug-specific alias:
missing-unlock-before-return. For a registered lock-acquire call, walks the REAL CFG
(cfg_edges.tsv, from export_c_cpp_facts_v03.sc -- the same real Joern-derived facts the
destination-capacity-write capabilities consume, not a diff-text heuristic) forward from
the lock call, treating a matching unlock call on the SAME object as a barrier that clears
the path. Any `return` reachable from the lock call WITHOUT first crossing a matching
unlock on that object is a LOCK_LEAK_CANDIDATE -- an open finding, never a certainty (does
not model exceptions/longjmp/goto out of the CFG structure Joern gives us, does not prove
the leaked lock is ever reacquired or causes a real deadlock -- states only what is
mechanically checkable: a CFG path from acquire to return crossing no matching release).

Object identity is TEXT-only (the lock/unlock call's first-argument CODE must match
exactly) -- conservative and abstain-first, same posture as this project's other
capabilities: two differently-spelled expressions are never assumed to be the same lock,
even if they alias at runtime (STRUCT-FIELD-ID-style value resolution is a possible future
refinement, not attempted here).

LOCK_FUNCS/UNLOCK_FUNCS is the SAME evidence-based registered-function list as
thread_freeze.py's LOCK/UNLOCK regex (wc_LockMutex/wc_UnLockMutex confirmed real for
wolfSSL; the rest are standard-API assumptions, flagged there, not re-litigated here). An
unregistered lock-shaped function name is invisible to this capability entirely -- verified
by a negative control (see lockcap_probe.c, negUnregisteredLockName) -- same "negative
control proves the registration table is load-bearing" pattern as PORT_Memcpy's own control.

WRAPPER-SITE-R01 (roadmap step 7, closing STEP6_PROMOTIONS_MANUAL_REVIEW.md's own "lock-
primitive wrapper recognition" gap -- a REAL, direct CFG bug, confirmed hop-by-hop against
@fugood/whisper.node's own real cpp_facts.json, not guessed): c2cpg represents a `static
inline` wrapper call (e.g. `ggml_mutex_unlock_shared(&threadpool->mutex)`, itself a one-line
call to `pthread_mutex_unlock`) as TWO real, distinct call nodes at the SAME source line with
the SAME first-argument code text -- the outer wrapper name and an inlined-duplicate inner
primitive-name node -- but only ONE of the two is actually threaded into the real CFG's own
linear flow for that specific call site; the other is a disconnected/parallel node this
capability's own forward BFS never reaches. WHICH of the two is CFG-connected is not
consistent even within one function: confirmed real on ggml_graph_compute_secondary_thread,
the INNER `pthread_mutex_lock` node is the CFG-connected one for the lock call at :3219, while
the OUTER `ggml_mutex_unlock_shared` node (not `pthread_mutex_unlock`) is the CFG-connected
one for the matching unlock at :3224 -- so a barriers set built by literal LOCK_FUNCS/
UNLOCK_FUNCS name-matching alone misses the real, CFG-connected unlock entirely (its own name,
`ggml_mutex_unlock_shared`, is not and cannot practically be a complete, closed allowlist --
every project can define its own wrapper name), producing a real false
RETURN_REACHABLE_WITHOUT_MATCHING_UNLOCK.

Fix, evidence-based rather than a growing wrapper-name allowlist: `same_site_calls()` groups
EVERY real call by (owner, line, first-argument code text) -- the SAME "text-only object
identity" discipline this module already applies to the lock/unlock OBJECT argument, now also
applied to the call SITE itself. Two calls sharing (owner, line, arg0) are, by direct
construction, real, alternate Joern representations of the SAME source statement -- confirmed,
not assumed, on the real fixture above (`ggml_mutex_lock_shared`/`pthread_mutex_lock` both at
:3219 with `arg0="&threadpool->mutex"`; `ggml_mutex_unlock_shared`/`pthread_mutex_unlock` both
at :3224 with the same arg0). Whenever ANY member of such a group is a real, recognized
LOCK_FUNCS/UNLOCK_FUNCS call, EVERY member of that group is treated as the same real
lock/unlock operation -- for barrier detection (a wrapper node reached in the CFG now correctly
clears the path even though its own bare name is unrecognized) AND, symmetrically, for lock-
site discovery (a wrapper-named lock call whose own sibling is a recognized primitive is
analyzed the same as if its own name matched directly) -- the same real mechanism, applied
uniformly rather than one-sidedly, since nothing in the real evidence says the asymmetry (lock
vs. unlock) is the only direction this can occur in real code.

Usage: lock_balance_verdict.py RAW_DIR OUT.json
"""
import base64
import json
import sys
from collections import defaultdict

LOCK_FUNCS = {"pthread_mutex_lock", "pthread_mutex_trylock", "pthread_rwlock_rdlock",
              "pthread_rwlock_wrlock", "wc_LockMutex", "k_mutex_lock",
              "spin_lock_irqsave", "spin_lock", "mutex_lock", "PR_Lock",
              "EnterCriticalSection"}
UNLOCK_FUNCS = {"pthread_mutex_unlock", "pthread_rwlock_unlock", "wc_UnLockMutex",
                "k_mutex_unlock", "spin_unlock_irqrestore", "spin_unlock",
                "mutex_unlock", "PR_Unlock", "LeaveCriticalSection"}


def dec(s):
    if not s:
        return ""
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except Exception:
        return s


def rows(path, n):
    out = []
    for ln in open(path):
        ln = ln.rstrip("\n")
        if not ln.strip():
            continue
        xs = ln.split("\t")
        if len(xs) != n:
            raise ValueError(f"{path}: expected {n} cols, got {len(xs)}: {ln!r}")
        out.append(xs)
    return out


CMP_OPS = ("<operator>.notEquals", "<operator>.equals")


def guard_success_start(method_id, lock_call_id, lock_call_code, obj_code, rets,
                        cfg_next, calls, args_by_call):
    """GUARD-R01: a lock call's own CFG successors include its FAILURE path (e.g.
    `if (wc_LockMutex(m) != 0) return err;` -- the object was never actually acquired on
    that path, so a return reached only through it is not a leak). cfg_edges.tsv carries no
    true/false branch label, so this can't be resolved from raw CFG topology alone.
    Recognizes the common, structurally-checkable idiom: an immediate CFG-successor
    comparison call (<operator>.notEquals/equals) whose own `code` textually contains the
    lock call's `code` (i.e., the lock call is the direct condition subexpression -- not a
    result stored in a variable first, a narrower but unambiguous case).

    Of that comparison's exactly-2 CFG successors, the GUARD-FAILURE branch is identified
    by object identity, not by "is this branch trivial in general" (an earlier version of
    this function tried that and got it wrong twice: (1) treating `<operator>.minus` for a
    literal `-1` as disqualifying "real work" when it's just building the return value, and
    (2) on a two-different-locks fixture, treating a failure branch that unlocks the OTHER
    (unrelated) object as non-trivial when it should count as trivial FOR THIS lock). The
    real criterion: a branch is the failure path iff EVERY forward path through it reaches
    a `return` before any LOCK/UNLOCK call on THIS SAME object (obj_code, matched by exact
    argument text) -- calls to anything else (operators, unrelated functions, locks/unlocks
    of a DIFFERENT object) don't disqualify it, since they can't represent this lock being
    used. The other successor becomes the real BFS start (first point downstream where the
    lock is provably still held). Returns None if the idiom isn't recognized, or if neither/
    both branches resolve this way -- callers fall back to the raw lock_call_id, which
    reproduces the ORIGINAL naive behavior (conservative in the sense of "doesn't crash",
    NOT in the sense of "never false-positives" for an unrecognized guard shape -- this is
    Round 1 of this capability, not a claim of completeness)."""
    def next_call_nodes(start, depth=4):
        seen = {start}; frontier = cfg_next.get((method_id, start), []); found = []
        for _ in range(depth):
            nxt = []
            for n in frontier:
                if n in seen:
                    continue
                seen.add(n)
                if n in calls:
                    found.append(n)
                    continue
                nxt.extend(cfg_next.get((method_id, n), []))
            frontier = nxt
            if not frontier:
                break
        return found

    def resolves_without_touching_object(start, depth=60):
        """True iff every forward path from `start` reaches a return (and stops there)
        before any LOCK/UNLOCK call on obj_code. False if some path touches obj_code
        first, or the depth budget is exhausted without every path resolving (abstain).
        DEPTH-R01: raised from 10 -- confirmed real, on case_a6eb1f6d's full
        wolfSSL_RAND_bytes, that the "skip this guarded block, continue into the rest of
        the function" branch can be dozens of CFG nodes from its own resolution in real
        (not fixture-sized) code, so a small bound made this abstain (falsely, via depth
        exhaustion) on exactly the guard shape it needs to resolve. Still bounded, not
        unlimited -- a genuinely pathological branch still abstains rather than loop
        forever or silently guess."""
        seen = set(); frontier = [start]
        for _ in range(depth):
            nxt = []
            for n in frontier:
                if n in seen:
                    continue
                seen.add(n)
                nc = calls.get(n)
                if nc and (nc["name"] in LOCK_FUNCS or nc["name"] in UNLOCK_FUNCS):
                    nargs = sorted(args_by_call.get(n, []))
                    if nargs and nargs[0][1].strip() == obj_code:
                        return False
                if n in rets:
                    continue  # this path is done; do not expand past a return
                nxt.extend(cfg_next.get((method_id, n), []))
            frontier = nxt
            if not frontier:
                return True
        return False  # depth exhausted without every path resolving -> abstain

    def branch_point(start, depth=5):
        """COMPOUND-GUARD-R01: the comparison isn't always the direct branch node -- a
        compound condition like `A() == 0 && LOCK(...) == 0` first feeds the comparison's
        result into a `<operator>.logicalAnd`/`logicalOr` node (which has exactly ONE CFG
        successor -- it just forwards the combined boolean onward), and THAT node's
        successors are the real 2-way branch. Confirmed real: PostCutoff-CVE
        case_a6eb1f6d's `wolfSSL_RAND_InitMutex() == 0 && wc_LockMutex(&gRandMethodMutex)
        == 0` guard -- without this walk, the comparison's own single successor fails the
        `len(succs) != 2` check below and this whole guard idiom silently falls back to
        the unguarded-lock-call BFS start, over-exploring into code the lock never
        protected. Walks forward through single-successor chains (bounded, cycle-safe)
        until a 2-successor node is found, or gives up (same fallback as an unrecognized
        idiom -- never guesses)."""
        seen = {start}; node = start
        for _ in range(depth):
            succs = cfg_next.get((method_id, node), [])
            if len(succs) != 1:
                return node
            nxt = succs[0]
            if nxt in seen:
                return node
            seen.add(nxt); node = nxt
        return node

    for s in next_call_nodes(lock_call_id):
        c = calls.get(s)
        if not c or c["name"] not in CMP_OPS:
            continue
        if lock_call_code not in (c.get("code") or ""):
            continue
        branch = branch_point(s)
        succs = cfg_next.get((method_id, branch), [])
        if len(succs) != 2:
            continue

        failure_like = [t for t in succs if resolves_without_touching_object(t)]
        other = [t for t in succs if t not in failure_like]
        if len(failure_like) == 1 and len(other) == 1:
            return other[0]
    return None


def main():
    raw, outp = sys.argv[1], sys.argv[2]

    methods = {int(r[0]): dec(r[1]) for r in rows(f"{raw}/methods.tsv", 10)}
    calls = {}
    calls_by_method = defaultdict(list)
    for r in rows(f"{raw}/calls.tsv", 11):
        cid, owner, name, code, line = int(r[0]), int(r[1]), dec(r[2]), dec(r[6]), r[8]
        calls[cid] = {"id": cid, "owner": owner, "name": name, "code": code, "line": line}
        calls_by_method[owner].append(cid)

    args_by_call = defaultdict(list)
    for r in rows(f"{raw}/arguments.tsv", 8):
        call_id, idx, code = int(r[1]), int(r[2]), dec(r[4])
        args_by_call[call_id].append((idx, code))

    def first_arg_code(cid):
        a = sorted(args_by_call.get(cid, []))
        return a[0][1].strip() if a else None

    # WRAPPER-SITE-R01: real (owner, line, first-arg-code) equivalence classes -- see module
    # docstring for the real, confirmed evidence this grouping is built from. Two calls in the
    # same group are, by direct construction, alternate Joern representations of the SAME real
    # source statement (a wrapper call and its own inlined-duplicate primitive call), never a
    # guess about two merely-similar-looking different statements.
    site_group = defaultdict(set)
    for gid, gc in calls.items():
        a0 = first_arg_code(gid)
        if a0:
            site_group[(gc["owner"], gc["line"], a0)].add(gid)

    def wrapper_group(cid, obj_code):
        gc = calls[cid]
        return site_group.get((gc["owner"], gc["line"], obj_code), {cid})

    # RETURNS-R01 (pre-existing exporter quirk, worked around here, not fixed at the
    # source): export_c_cpp_facts_v03.sc's `cpg.method.l.foreach { owner => owner.ast.
    # isReturn... }` re-emits every return under BOTH the file's <global> pseudo-method
    # (whose AST subtree transitively contains every function) AND the real owning
    # method. Building per-method sets rather than a global id->owner map sidesteps it
    # entirely: a lock analysis never queries <global>'s own return set.
    returns_by_method = defaultdict(set)
    for r in rows(f"{raw}/returns.tsv", 5):
        rid, owner = int(r[0]), int(r[1])
        returns_by_method[owner].add(rid)

    cfg_next = defaultdict(list)
    for r in rows(f"{raw}/cfg_edges.tsv", 3):
        owner, frm, to = int(r[0]), int(r[1]), int(r[2])
        cfg_next[(owner, frm)].append(to)

    findings = []
    classification = defaultdict(int)

    for method_id, call_ids in calls_by_method.items():
        rets = returns_by_method.get(method_id, set())
        for cid in call_ids:
            c = calls[cid]
            if c["name"] not in LOCK_FUNCS:
                continue
            classification["LOCK_CALL_FOUND"] += 1
            lock_args = sorted(args_by_call.get(cid, []))
            if not lock_args:
                classification["LOCK_NO_OBJECT_ARG"] += 1
                continue
            obj_code = lock_args[0][1].strip()
            if not obj_code:
                classification["LOCK_NO_OBJECT_ARG"] += 1
                continue

            # Barriers: unlock calls in the SAME method on the textually-identical object.
            # WRAPPER-SITE-R01: also include every real (owner, line, obj_code) sibling of a
            # recognized unlock call -- the call node Joern actually threads into the CFG for
            # that source statement may be the WRAPPER (unrecognized by bare name), not the
            # primitive found here; both are barriers for the SAME real release, confirmed
            # real on @fugood/whisper.node's own ggml_graph_compute_secondary_thread (module
            # docstring).
            barriers = set()
            for oc in call_ids:
                oc_info = calls[oc]
                if oc_info["name"] not in UNLOCK_FUNCS:
                    continue
                oargs = sorted(args_by_call.get(oc, []))
                if oargs and oargs[0][1].strip() == obj_code:
                    barriers.add(oc)
                    barriers.update(wrapper_group(oc, obj_code))
            if not barriers:
                classification["LOCK_NO_MATCHING_UNLOCK_IN_FUNCTION"] += 1
                # still worth flagging: EVERY return is a leak candidate if there is no
                # release of this object anywhere in the function at all.
                unsafe_returns = set(rets)
                if unsafe_returns:
                    classification["LEAK_CANDIDATE_NO_RELEASE_AT_ALL"] += 1
                    findings.append({
                        "method_id": method_id, "method_name": methods.get(method_id),
                        "lock_call_id": cid, "lock_object": obj_code,
                        "reason": "NO_RELEASE_ANYWHERE_IN_FUNCTION",
                        "unsafe_return_ids": sorted(unsafe_returns),
                    })
                continue

            # BFS forward from the lock call, pruning at barriers (a path through a
            # barrier is safe beyond that point) and at method boundaries. GUARD-R01: if
            # this call is guarded by a recognized `if (LOCK(...) != 0) return ...;`-shaped
            # check, start from the SUCCESS successor instead of the raw call -- the guard's
            # own failure-return means the lock was never acquired on that path, not a leak.
            c_code = (c.get("code") or "")
            guard_start = guard_success_start(method_id, cid, c_code, obj_code, rets,
                                              cfg_next, calls, args_by_call)
            start_node = guard_start if guard_start is not None else cid
            visited = {cid, start_node}
            frontier = list(cfg_next.get((method_id, start_node), []))
            unsafe_returns = set()
            while frontier:
                node = frontier.pop()
                if node in visited:
                    continue
                visited.add(node)
                if node in barriers:
                    continue  # cleared past this point, do not expand further
                if node in rets:
                    unsafe_returns.add(node)
                    continue  # nothing follows a return
                frontier.extend(cfg_next.get((method_id, node), []))

            if unsafe_returns:
                classification["LEAK_CANDIDATE_UNSAFE_RETURN"] += 1
                findings.append({
                    "method_id": method_id, "method_name": methods.get(method_id),
                    "lock_call_id": cid, "lock_object": obj_code,
                    "reason": "RETURN_REACHABLE_WITHOUT_MATCHING_UNLOCK",
                    "unsafe_return_ids": sorted(unsafe_returns),
                })
            else:
                classification["BALANCED_ON_ALL_PATHS"] += 1

    json.dump({"schema": "lock-balance-verdict/0.1",
               "classification": dict(classification),
               "findings": findings}, open(outp, "w"), indent=1, sort_keys=True)
    print(f"classification: {dict(classification)}")
    print(f"findings: {len(findings)}")


if __name__ == "__main__":
    main()
