#!/usr/bin/env python3
"""LOCK-SAFE-R02: Capability 2 for the thread-safety property (THREAD_SAFETY_R01.md) --
a general evidence model for the OTHER representation shape Capability 1
(lock_balance_verdict.py) explicitly could not cover: a critical section that should exist
but is entirely ABSENT, not an existing lock with an incomplete release. Recognizes exactly
one case_644b3e3c shape (Dtls13RtxRemoveCurAck touching ssl->dtls13Rtx.seenRecords with NO
lock call at all, while Dtls13RtxAddAck in the same file protects the SAME field with
ssl->dtls13Rtx.mutex) -- inferred from evidence within a single translation unit's raw
facts, not a whole-program/interprocedural points-to analysis.

Method: within ONE c2cpg raw-facts export (a single file, same scope Capability 1 already
operates in), for every function that holds a registered lock, compute the CFG node-set
genuinely inside that lock's critical section (reusing Capability 1's exact
guard-aware barrier-BFS). For every field-access call (<operator>.fieldAccess /
<operator>.indirectFieldAccess) NOT subsumed as an intermediate step of a longer chain in
the same expression, normalize away the base identifier (ssl->dtls13Rtx.seenRecords ->
.dtls13Rtx.seenRecords) and record whether that access falls inside a critical section, and
for which lock-object signature.

INFERENCE RULE (conservative, abstain-on-ambiguity): a field-path signature is "PROTECTED
by lock signature L" only if EVERY access to it across the whole corpus that occurs inside
ANY critical section is inside an L-critical-section specifically (never a DIFFERENT lock --
that would mean either lock is a false signal, and this abstains rather than guess which).
Given such an L, any access to that field-path OUTSIDE any L-critical-section (including in
a function with no lock at all) is a MISSING_LOCK_CANDIDATE -- an open finding, never a
certainty: it does not know whether the accessing function runs single-threaded, before
threads exist, or under some OTHER synchronization mechanism this corpus's lock-detection
vocabulary doesn't cover. A field-path with NO protected occurrence anywhere in the corpus
establishes no pattern and is never flagged (no evidence, no guess).

Usage: protected_field_verdict.py RAW_DIR OUT.json
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
FIELD_OPS = {"<operator>.fieldAccess", "<operator>.indirectFieldAccess"}
CMP_OPS = ("<operator>.notEquals", "<operator>.equals")


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


def normalize_path(code):
    """Strip the leading base identifier: `ssl->dtls13Rtx.seenRecords` ->
    `.dtls13Rtx.seenRecords`, `p.field` -> `.field`. Returns None for a bare identifier
    with no `.`/`->` at all (not a field-path signature), OR for a SINGLE-segment path
    (`ssl->heap` -> `.heap`, `rn->next` -> `.next`) -- MULTI-SEGMENT-R01: a pre-freeze
    sanity check against the real xfn_probe.c fixture found single-segment generic field
    names (`.next`, `.heap`, `.epoch`, `.seq`) get flagged as false MISSING_LOCK_CANDIDATEs
    purely because they were incidentally touched inside SOME lock's critical section
    (Dtls13RtxAddAck happens to walk `cur->next`/dereference `ssl->heap` while holding the
    lock, which doesn't mean those specific fields need it -- correlation, not causation).
    The one real bug (`.dtls13Rtx.seenRecords`) and the lock object itself
    (`.dtls13Rtx.mutex`) are both 2-segment paths; every false positive found was
    1-segment. A single common field name is far more likely to collide across unrelated
    struct types in a real codebase than a specific nested path, so this requires >=2
    segments as a (conservative, evidence-driven, not exhaustively proven) precondition for
    even attempting the inference -- abstain on anything less specific."""
    for sep in ("->", "."):
        i = code.find(sep)
        if i > 0:
            rest = code[i + len(sep):]
            if not any(s in rest for s in ("->", ".")):
                return None  # single-segment: too generic a name to trust
            return "." + rest
    return None


def normalize_global(code, known_globals):
    """GLOBAL-VAR-R01: the plain-global-variable counterpart to normalize_path, for a
    bug shape struct-field paths can't represent -- confirmed real and NOT recoverable by
    the field-path scheme alone: PostCutoff-CVE case_f21da596's `wolfSSL_RAND_poll()`
    reseeds `globalRNG` (a bare `static WC_RNG globalRNG;` at file scope, not a struct
    field) via `wc_RNG_DRBG_Reseed(&globalRNG, ...)` with no lock at all, while
    `wolfSSL_RAND_bytes()` protects the SAME variable with `globalRNGMutex` -- exactly
    Capability 2's target shape, but `&globalRNG` is an `<operator>.addressOf` call on a
    bare IDENTIFIER, never a `<operator>.fieldAccess`/`indirectFieldAccess`, so
    normalize_path (which only recognizes `.`/`->` chains) never sees it.
    `known_globals` is the set of names c2cpg exposes as `locals` of the file's own
    `<global>` pseudo-method -- real evidence: static/file-scope variable declarations are
    exported there (confirmed: `static WC_RNG globalRNG;` appears as a `<global>`-owned
    local with that literal declaration as its code). Returns `::<name>` (a distinct
    namespace from normalize_path's `.`-prefixed signatures, so a global can never collide
    with a same-named struct field) for `&name` or a bare `name` where `name` is a known
    global; None otherwise -- an identifier that ISN'T a known global (a true local, a
    parameter, an unrecognized macro) is never guessed at."""
    c = code.strip()
    if c.startswith("&"):
        c = c[1:].strip()
    if c in known_globals:
        return "::" + c
    return None


def guard_success_start(method_id, lock_call_id, lock_call_code, obj_code, rets,
                        cfg_next, calls, args_by_call):
    """Same as lock_balance_verdict.guard_success_start (duplicated, not imported, so this
    script stays a standalone gate script like the rest of this project's tools) -- see
    that module's docstring for the full rationale and validated design."""
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
        # DEPTH-R01 -- see lock_balance_verdict.guard_success_start's docstring.
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
                    continue
                nxt.extend(cfg_next.get((method_id, n), []))
            frontier = nxt
            if not frontier:
                return True
        return False

    def branch_point(start, depth=5):
        """COMPOUND-GUARD-R01 -- see lock_balance_verdict.guard_success_start's docstring
        for the full rationale (duplicated here, not imported, per this project's
        standalone-gate-script convention)."""
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


def critical_section_nodes(method_id, cid, c_code, obj_code, rets, cfg_next, calls, args_by_call):
    """The set of CFG nodes genuinely inside this lock call's critical section (guard-aware
    start, pruned at the matching-object barrier) -- the same region Capability 1's BFS
    walks to find leaking returns; here used to test field-access membership instead."""
    barriers = set()
    for oc, oc_info in calls.items():
        if oc_info["owner"] != method_id or oc_info["name"] not in UNLOCK_FUNCS:
            continue
        oargs = sorted(args_by_call.get(oc, []))
        if oargs and oargs[0][1].strip() == obj_code:
            barriers.add(oc)
    if not barriers:
        return set()
    guard_start = guard_success_start(method_id, cid, c_code, obj_code, rets, cfg_next, calls, args_by_call)
    start_node = guard_start if guard_start is not None else cid
    visited = {cid, start_node}
    frontier = list(cfg_next.get((method_id, start_node), []))
    region = set()
    while frontier:
        node = frontier.pop()
        if node in visited:
            continue
        visited.add(node)
        if node in barriers:
            continue
        region.add(node)
        frontier.extend(cfg_next.get((method_id, node), []))
    return region


def main():
    raw, outp = sys.argv[1], sys.argv[2]

    methods = {int(r[0]): dec(r[1]) for r in rows(f"{raw}/methods.tsv", 10)}
    calls = {}
    calls_by_method = defaultdict(list)
    for r in rows(f"{raw}/calls.tsv", 11):
        cid, owner, name, code = int(r[0]), int(r[1]), dec(r[2]), dec(r[6])
        calls[cid] = {"id": cid, "owner": owner, "name": name, "code": code}
        calls_by_method[owner].append(cid)

    args_by_call = defaultdict(list)
    for r in rows(f"{raw}/arguments.tsv", 8):
        call_id, idx, code = int(r[1]), int(r[2]), dec(r[4])
        args_by_call[call_id].append((idx, code))

    returns_by_method = defaultdict(set)
    for r in rows(f"{raw}/returns.tsv", 5):
        rid, owner = int(r[0]), int(r[1])
        returns_by_method[owner].add(rid)

    cfg_next = defaultdict(list)
    for r in rows(f"{raw}/cfg_edges.tsv", 3):
        owner, frm, to = int(r[0]), int(r[1]), int(r[2])
        cfg_next[(owner, frm)].append(to)

    # GLOBAL-VAR-R01: file-scope static/global variable declarations are exported as
    # `locals` owned by the file's own `<global>` pseudo-method (confirmed real:
    # `static WC_RNG globalRNG;` -> a local owned by the `<global>` method literally named
    # "<global>", code `static WC_RNG globalRNG`). Collect their names as the known-global
    # vocabulary normalize_global checks identifiers against -- never guessed beyond this.
    global_method_ids = {mid for mid, name in methods.items() if name == "<global>"}
    known_globals = set()
    for r in rows(f"{raw}/locals.tsv", 6):
        lid, owner, name = int(r[0]), int(r[1]), dec(r[2])
        if owner in global_method_ids:
            known_globals.add(name)

    def normalize_any(code):
        sig = normalize_path(code)
        return sig if sig is not None else normalize_global(code, known_globals)

    # Field-path signature extraction, subsumption-filtered per method: a field-access
    # call whose code is a strict `sep`-joined prefix of a sibling's code in the same
    # method is just an intermediate step of that longer chain -- drop it, keep only the
    # most complete access at each expression site.
    field_calls_by_method = defaultdict(list)
    for cid, c in calls.items():
        if c["name"] in FIELD_OPS and normalize_path(c["code"]) is not None:
            field_calls_by_method[c["owner"]].append(cid)

    # Global-variable touch extraction: an <operator>.addressOf call on a bare identifier
    # matching a known global (the `&globalRNG` shape). No subsumption issue here -- unlike
    # a struct-field chain, a global reference has no shorter intermediate "prefix" step to
    # collide with.
    global_touches_by_method = defaultdict(list)
    for cid, c in calls.items():
        if c["name"] != "<operator>.addressOf":
            continue
        sig = normalize_global(c["code"], known_globals)
        if sig is not None:
            global_touches_by_method[c["owner"]].append((cid, sig))

    # LOCK-OBJECT-EXCLUSION-R01: a field-path OR global that is ITSELF ever passed as a
    # lock/unlock call's object argument anywhere in the corpus is the LOCK, not
    # protectable data -- dereferencing a mutex to pass it to wc_LockMutex/wc_UnLockMutex
    # is part of the locking mechanism, never a race on data. Without this, the mutex's own
    # access sometimes falls inside vs. outside its critical section (its OWN acquire
    # call's argument is evaluated before the lock is held; its release calls' argument
    # accesses are inside), producing a nonsensical "protected by itself"
    # MISSING_LOCK_CANDIDATE -- confirmed real against xfn_probe.c (field form) and
    # extended here to the global form (globalRNGMutex/gRandMethodMutex are themselves
    # plain globals in case_f21da596/case_a6eb1f6d) on the same reasoning, not
    # independently re-confirmed against a dedicated global-lock-object fixture.
    known_lock_sigs = set()
    for c in calls.values():
        if c["name"] in LOCK_FUNCS or c["name"] in UNLOCK_FUNCS:
            largs = sorted(args_by_call.get(c["id"], []))
            if largs:
                sig = normalize_any(largs[0][1].strip())
                if sig:
                    known_lock_sigs.add(sig)

    kept_field_accesses = []  # (call_id, method_id, path_sig)
    for method_id, touches in global_touches_by_method.items():
        for cid, sig in touches:
            if sig in known_lock_sigs:
                continue
            kept_field_accesses.append((cid, method_id, sig))
    for method_id, cids in field_calls_by_method.items():
        codes = {cid: calls[cid]["code"] for cid in cids}
        subsumed = set()
        for a in cids:
            for b in cids:
                if a == b:
                    continue
                if codes[b].startswith(codes[a]) and len(codes[b]) > len(codes[a]) and \
                   codes[b][len(codes[a]):len(codes[a]) + 1] in (".", "-"):
                    subsumed.add(a)
        for cid in cids:
            if cid in subsumed:
                continue
            sig = normalize_path(codes[cid])
            if sig in known_lock_sigs:
                continue
            kept_field_accesses.append((cid, method_id, sig))

    # For every registered lock call, compute its critical-section node set once.
    crit_regions = []  # (method_id, obj_code, node_set)
    for method_id, cids in calls_by_method.items():
        rets = returns_by_method.get(method_id, set())
        for cid in cids:
            c = calls[cid]
            if c["name"] not in LOCK_FUNCS:
                continue
            largs = sorted(args_by_call.get(cid, []))
            if not largs:
                continue
            obj_code = largs[0][1].strip()
            if not obj_code:
                continue
            region = critical_section_nodes(method_id, cid, c["code"], obj_code, rets,
                                            cfg_next, calls, args_by_call)
            if region:
                crit_regions.append((method_id, obj_code, region))

    # Classify each kept field access: which (method, obj) critical region(s) contain it.
    access_records = []  # (call_id, method_id, path_sig, protecting_obj_sig_or_None)
    for cid, method_id, path_sig in kept_field_accesses:
        protecting = None
        for r_method, r_obj, r_nodes in crit_regions:
            if r_method == method_id and cid in r_nodes:
                obj_sig = normalize_path(r_obj) or r_obj
                protecting = obj_sig
                break  # a well-formed function locks one region at a time in this scope
        access_records.append((cid, method_id, path_sig, protecting))

    # RULE: infer PROTECTED-BY for each path_sig only when every protected occurrence
    # agrees on the SAME lock-object signature (else abstain -- ambiguous evidence).
    protectors_by_path = defaultdict(set)
    for cid, method_id, path_sig, protecting in access_records:
        if protecting is not None:
            protectors_by_path[path_sig].add(protecting)

    findings = []
    classification = defaultdict(int)
    for path_sig, protectors in protectors_by_path.items():
        if len(protectors) != 1:
            classification["AMBIGUOUS_MULTIPLE_PROTECTORS"] += 1
            continue
        lock_sig = next(iter(protectors))
        for cid, method_id, p_sig, protecting in access_records:
            if p_sig != path_sig:
                continue
            if protecting == lock_sig:
                classification["PROTECTED_ACCESS"] += 1
                continue
            classification["MISSING_LOCK_CANDIDATE"] += 1
            findings.append({
                "call_id": cid, "method_id": method_id, "method_name": methods.get(method_id),
                "field_path": path_sig, "field_code": calls[cid]["code"],
                "inferred_protecting_lock": lock_sig,
                "reason": "FIELD_ACCESSED_OUTSIDE_ITS_INFERRED_LOCK",
            })

    json.dump({"schema": "protected-field-verdict/0.1",
               "classification": dict(classification),
               "findings": findings}, open(outp, "w"), indent=1, sort_keys=True)
    print(f"classification: {dict(classification)}")
    print(f"findings: {len(findings)}")


if __name__ == "__main__":
    main()
