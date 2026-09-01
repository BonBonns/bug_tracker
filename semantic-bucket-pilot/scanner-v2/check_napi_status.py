#!/usr/bin/env python3
"""NAPI-STATUS-R01 regression gate: runs napi_status_verdict.py against FROZEN real
Joern output (v4.0.608, the same pinned version as every other capability's fixtures)
checked into study/napi_status/raw_synthetic/, generated from fixture_source.c. All
expectations are API-HANDLING classifications -- none is a vulnerability or impact
claim.

Controls covered (the 11 required by NAPI_STATUS_R01.md, plus structural probes):
   1 c01  unchecked status then output use          -> STATUS_GUARD_MISSING/NO_RELATED_CHECK
   2 c02  correct terminating failure check         -> STATUS_GUARD_ESTABLISHED
   3 c03  status check only after output use        -> STATUS_GUARD_MISSING/RELATED_CHECK_AFTER_USE
   4 c04  check of an unrelated status variable     -> STATUS_GUARD_MISSING/UNRELATED_CHECK_ONLY
   5 c05  failure branch that does not terminate    -> STATUS_GUARD_MISSING/NON_TERMINATING...
   6 c06/c06b direct status propagation             -> STATUS_PROPAGATED_BEFORE_USE
   7 c07  use exclusively in proven success branch  -> STATUS_GUARD_ESTABLISHED
   8 c08  ambiguous output identity (&slots[i])     -> ABSTAIN_OUTPUT_IDENTITY_UNRESOLVED
   9 c09  napi_create_external_buffer               -> INVISIBLE (registration is load-bearing)
  10 c10  known wrapper, proven propagation         -> STATUS_GUARD_ESTABLISHED
  11 c11  unknown wrapper                           -> ABSTAIN_WRAPPER_UNRESOLVED
  +  p01  CFG branch-order/polarity probes (exporter convention verification)
  +  p02  napi_create_buffer_copy, status discarded -> STATUS_GUARD_MISSING/STATUS_DISCARDED
  +  p03  known wrapper, proven TERMINATION          -> STATUS_GUARD_ESTABLISHED
  +  p04  provable compound (success AND flag)       -> STATUS_GUARD_ESTABLISHED
  +  p05  unprovable compound (success OR flag)      -> ABSTAIN_BRANCH_POLARITY_UNRESOLVED
  +  p06  outputs never used                         -> NO_OUTPUT_USE
  +  p07  arity mismatch                             -> ABSTAIN_CALL_IDENTITY_UNRESOLVED

Regenerating the frozen raw facts (only needed if fixture_source.c changes). The
GitHub release zip is not reachable from this environment, so the pinned Joern is
assembled from Maven Central instead (identical artifacts, identical version):
    mkdir joern-mvn && cd joern-mvn && cat > pom.xml   # deps: io.joern:joern-cli_3 and
                                                       # io.joern:c2cpg_3, both 4.0.608
    mvn -B dependency:build-classpath -Dmdep.outputFile=cp.txt
    touch .installation_root                           # console wants an install root
    java -cp "$(cat cp.txt)" io.joern.c2cpg.Main -o /tmp/x.cpg.bin fixture_source.c
    java -cp "$(cat cp.txt)" io.joern.joerncli.console.ReplBridge \
        --script .../export_c_cpp_facts_v03.sc \
        --param cpgFile=/tmp/x.cpg.bin --param outDir=study/napi_status/raw_synthetic
"""
import base64
import json
import pathlib
import subprocess
import sys
from collections import defaultdict

HERE = pathlib.Path(__file__).parent
CAP = HERE / "napi_status_verdict.py"
RAW = HERE / "study" / "napi_status" / "raw_synthetic"

ok = 0
total = 0


def ck(name, cond):
    global ok, total
    total += 1
    ok += bool(cond)
    print(("PASS" if cond else "FAIL"), name)


outpath = HERE / "study" / "napi_status" / "out_synthetic.json"
subprocess.run([sys.executable, str(CAP), str(RAW), str(outpath)], check=True)
r = json.loads(outpath.read_text())
by_fn = defaultdict(list)
for f in r["findings"]:
    by_fn[f["method_name"]].append(f)


def one(fn):
    recs = by_fn.get(fn, [])
    return recs[0] if len(recs) == 1 else {}


# --- the 11 required controls -----------------------------------------------------------
ck("c01 unchecked use -> STATUS_GUARD_MISSING / NO_RELATED_CHECK",
   one("c01_unchecked_use").get("verdict") == "STATUS_GUARD_MISSING"
   and one("c01_unchecked_use").get("sub_reason") == "NO_RELATED_CHECK")
ck("c01 evidence cites the real use variable (data) and a line",
   one("c01_unchecked_use").get("unguarded_use_variable") == "data"
   and bool(one("c01_unchecked_use").get("unguarded_use_line")))
ck("c01 input-size origin recorded as literal (diagnostic only)",
   one("c01_unchecked_use").get("input_size_origin", {}).get("kind") == "literal")

ck("c02 terminating failure check -> STATUS_GUARD_ESTABLISHED",
   one("c02_checked_terminating").get("verdict") == "STATUS_GUARD_ESTABLISHED")
ck("c02 guard evidence nodes recorded",
   bool(one("c02_checked_terminating").get("guard_evidence_nodes")))

ck("c03 check after use -> STATUS_GUARD_MISSING / RELATED_CHECK_AFTER_USE",
   one("c03_check_after_use").get("verdict") == "STATUS_GUARD_MISSING"
   and one("c03_check_after_use").get("sub_reason") == "RELATED_CHECK_AFTER_USE")
ck("c03 the related (too-late) check is cited as evidence",
   bool(one("c03_check_after_use").get("related_check_nodes")))

ck("c04 unrelated status checked -> STATUS_GUARD_MISSING / UNRELATED_CHECK_ONLY",
   one("c04_unrelated_status").get("verdict") == "STATUS_GUARD_MISSING"
   and one("c04_unrelated_status").get("sub_reason") == "UNRELATED_CHECK_ONLY")

ck("c05 non-terminating failure branch -> STATUS_GUARD_MISSING / NON_TERMINATING...",
   one("c05_nonterminating_failure").get("verdict") == "STATUS_GUARD_MISSING"
   and one("c05_nonterminating_failure").get("sub_reason")
   == "NON_TERMINATING_OR_BYPASSED_FAILURE_PATH")

ck("c06 status returned via variable -> STATUS_PROPAGATED_BEFORE_USE",
   one("c06_propagates").get("verdict") == "STATUS_PROPAGATED_BEFORE_USE")
ck("c06b creation call returned directly -> STATUS_PROPAGATED_BEFORE_USE",
   one("c06b_propagates_direct").get("verdict") == "STATUS_PROPAGATED_BEFORE_USE")

ck("c07 use exclusively in success branch -> STATUS_GUARD_ESTABLISHED",
   one("c07_use_in_success_branch").get("verdict") == "STATUS_GUARD_ESTABLISHED")

ck("c08 ambiguous output identity (&slots[i]) -> ABSTAIN_OUTPUT_IDENTITY_UNRESOLVED",
   one("c08_ambiguous_output").get("verdict") == "ABSTAIN_OUTPUT_IDENTITY_UNRESOLVED")

ck("c09 napi_create_external_buffer contributes NOTHING (no record at all)",
   not by_fn.get("c09_external_buffer"))
ck("c09 registration is load-bearing: exactly 17 supported sites counted "
   "(every candidate site in the fixture EXCEPT c09's)",
   r["classification"].get("SUPPORTED_CREATION_CALL_FOUND") == 17)
ck("c09 the unsupported call is not even in the supported list",
   "napi_create_external_buffer" not in r["supported_calls"])

ck("c10 known wrapper (proven identity propagation) -> STATUS_GUARD_ESTABLISHED",
   one("c10_known_wrapper").get("verdict") == "STATUS_GUARD_ESTABLISHED")

ck("c11 unknown wrapper -> ABSTAIN_WRAPPER_UNRESOLVED (neither flagged nor cleared)",
   one("c11_unknown_wrapper").get("verdict") == "ABSTAIN_WRAPPER_UNRESOLVED")

# --- probes ----------------------------------------------------------------------------
ck("p02 buffer_copy, status discarded -> STATUS_GUARD_MISSING / STATUS_DISCARDED",
   one("p02_copy_unchecked").get("verdict") == "STATUS_GUARD_MISSING"
   and one("p02_copy_unchecked").get("sub_reason") == "STATUS_DISCARDED")
ck("p02 input-size origin recorded as parameter (diagnostic only)",
   one("p02_copy_unchecked").get("input_size_origin", {}).get("kind") == "parameter")
ck("p03 known terminating wrapper -> STATUS_GUARD_ESTABLISHED",
   one("p03_known_terminating_wrapper").get("verdict") == "STATUS_GUARD_ESTABLISHED")
ck("p04 provable compound (== napi_ok && flag) -> STATUS_GUARD_ESTABLISHED",
   one("p04_compound_and").get("verdict") == "STATUS_GUARD_ESTABLISHED")
ck("p05 unprovable compound (== napi_ok || flag) -> ABSTAIN_BRANCH_POLARITY_UNRESOLVED",
   one("p05_compound_or_ambiguous").get("verdict")
   == "ABSTAIN_BRANCH_POLARITY_UNRESOLVED")
ck("p06 outputs never used -> NO_OUTPUT_USE (not a finding)",
   one("p06_no_use").get("verdict") == "NO_OUTPUT_USE")
ck("p07 wrong arity -> ABSTAIN_CALL_IDENTITY_UNRESOLVED",
   one("p07_wrong_arity").get("verdict") == "ABSTAIN_CALL_IDENTITY_UNRESOLVED")

ck("no verdict text anywhere claims a vulnerability (claims-boundary lint)",
   "vulnerab" not in json.dumps(r).lower())

# --- structural probes: the exporter conventions the analyzer's proofs rest on ---------
def dec(s):
    if not s:
        return ""
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except Exception:
        return s


calls = {}
owner_of = {}
for ln in (RAW / "calls.tsv").read_text().splitlines():
    xs = ln.split("\t")
    calls[int(xs[0])] = (int(xs[1]), dec(xs[2]), dec(xs[6]))
    owner_of[int(xs[0])] = int(xs[1])
cfg = defaultdict(list)
for ln in (RAW / "cfg_edges.tsv").read_text().splitlines():
    xs = ln.split("\t")
    cfg[(int(xs[0]), int(xs[1]))].append(int(xs[2]))
methods = {}
for ln in (RAW / "methods.tsv").read_text().splitlines():
    xs = ln.split("\t")
    methods[int(xs[0])] = dec(xs[1])
exits = set()
for ln in (RAW / "method_returns.tsv").read_text().splitlines():
    xs = ln.split("\t")
    exits.add(int(xs[0]))


def first_marker_from(mid, start):
    """BFS to the first marker_true/marker_false call reachable from `start`."""
    seen, frontier = set(), [start]
    for _ in range(50):
        nxt = []
        for n in frontier:
            if n in seen:
                continue
            seen.add(n)
            c = calls.get(n)
            if c and c[1] in ("marker_true", "marker_false"):
                return c[1]
            nxt.extend(cfg.get((mid, n), []))
        frontier = nxt
        if not frontier:
            return None
    return None


for probe, op in (("p01_polarity_ne", "<operator>.notEquals"),
                  ("p01_polarity_eq", "<operator>.equals")):
    mid = [m for m, n in methods.items() if n == probe][0]
    cmp_nodes = [c for c, (o, nm, _) in calls.items() if o == mid and nm == op]
    succs = cfg.get((mid, cmp_nodes[0]), []) if len(cmp_nodes) == 1 else []
    ck(f"{probe}: condition has exactly 2 successors", len(succs) == 2)
    ck(f"{probe}: FIRST cfg successor is the TRUE branch (pinned-exporter convention)",
       len(succs) == 2 and first_marker_from(mid, succs[0]) == "marker_true"
       and first_marker_from(mid, succs[1]) == "marker_false")

ck("exit encoding: NO cfg edges into METHOD_RETURN anywhere (returns and noreturn "
   "calls are terminal) -- the assumption prove_terminating_guard rests on",
   not any(t in exits for tos in cfg.values() for t in tos))

abort_calls = [c for c, (o, nm, _) in calls.items() if nm == "abort"]
ck("exit encoding: the fixture's abort() call is terminal (no successors)",
   abort_calls and all(not cfg.get((owner_of[c], c), []) for c in abort_calls))

print(f"NAPI_STATUS_R01={ok}/{total}")
sys.exit(0 if ok == total else 1)
