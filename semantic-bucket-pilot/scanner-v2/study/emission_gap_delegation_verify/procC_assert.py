#!/usr/bin/env python3
"""Proc C: pure-python assertions over the dumps (no scanner imports)."""
import json, sys
SP = "/tmp/claude-0/-home-user-bug-tracker/0fd64c6d-7e3d-554b-9af8-02d9e6597995/scratchpad"
base = json.load(open(f"{SP}/baseline_70805e2.json"))
dele = json.load(open(f"{SP}/delegation_v1.json"))
v2 = json.load(open(f"{SP}/v2_verify.json"))
promos = json.load(open(f"{SP}/full_promotions.json"))

fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else "  :: " + detail))
    if not cond:
        fails.append(name)


# (d) same site SET before/after (zero additions or losses)
bk, dk = set(base), set(dele)
check("site-set identical (no additions/losses)", bk == dk,
      f"only_base={len(bk-dk)} only_deleg={len(dk-bk)}")
check("45 non-bare sites both", len(base) == 45 and len(dele) == 45, f"base={len(base)} deleg={len(dele)}")

# (a) none newly dropped
newly_dropped = [k for k in dk if dele[k]["analysis_status"] == "<DROPPED>"]
check("none newly dropped (all emit)", not newly_dropped, f"dropped={newly_dropped}")

# (c) exactly the expected sites change reason, and only cap_rel->delegated
changed = {k for k in bk & dk if base[k]["reason_code"] != dele[k]["reason_code"]}
detail = {k: (base[k]["reason_code"], dele[k]["reason_code"]) for k in changed}
check("exactly 2 body-wide reason changes", len(changed) == 2, f"changed={detail}")
ok_transition = all(base[k]["reason_code"] == "capacity_relation_not_established"
                    and dele[k]["reason_code"] == "delegated_to_stack_capacity_v2"
                    for k in changed)
check("every change is capacity_relation_not_established -> delegated_to_stack_capacity_v2",
      ok_transition, str(detail))
# status change: those 2 go abstained/open_candidate -> rerouted
status_ok = all(dele[k]["analysis_status"] == "rerouted" for k in changed)
check("changed sites become rerouted", status_ok,
      str({k: dele[k]["analysis_status"] for k in changed}))
# and NON-changed sites are byte-identical in reason+status
unchanged_bad = [k for k in (bk & dk) - changed
                 if base[k]["reason_code"] != dele[k]["reason_code"]
                 or base[k]["analysis_status"] != dele[k]["analysis_status"]]
check("all other 43 sites unchanged in status+reason", not unchanged_bad, str(unchanged_bad))

# (f) V2 canonical + v1_provenance on every adjudicated (delegated) record
check("v2 delegated sites == 2", len(v2["delegated_sites"]) == 2, str(len(v2["delegated_sites"])))
check("every delegated record has v1_provenance", not v2["v1_provenance_missing"],
      str(v2["v1_provenance_missing"]))
check("v2 canonical (status differs from v1 rerouted on all delegated)",
      all(d["v2"]["analysis_status"] != "rerouted" for d in v2["delegated_sites"]),
      str([d["v2"]["analysis_status"] for d in v2["delegated_sites"]]))

# (g) every emitted record validates under schema v2
check("v1 records all schema-valid", v2["v1_invalid"] == [], str(v2["v1_invalid"][:3]))
check("v2 records all schema-valid", v2["v2_invalid"] == [], str(v2["v2_invalid"][:3]))

# (e) promotions: exactly 2 delegated DC (justified) + 2 pre-existing bare-stack, 0 oversized
deleg_dc = [p for p in promos["promotions"] if p["delegated"]]
bare_dc = [p for p in promos["promotions"] if not p["delegated"]]
check("2 delegated deterministic_complete", len(deleg_dc) == 2, str(len(deleg_dc)))
check("0 proven_oversized", promos["proven_oversized_total"] == 0, str(promos["proven_oversized_total"]))
# every DC is a byte-array, offset+width<=count (independently recomputed)
def justified(p):
    if p["elem"] not in ("char", "unsigned char", "signed char", "uint8_t", "int8_t"):
        return False
    off = p["off"] or 0
    try:
        w = int(str(p["width"]))
    except Exception:
        return False
    return isinstance(p["count"], int) and off + w <= p["count"]
unjust = [p for p in promos["promotions"] if not justified(p)]
check("every deterministic_complete justified (byte array, off+width<=count)",
      not unjust, str([(p["dest"], p["note"]) for p in unjust]))

# (b) labeled group-A = 13/20 comes from regression stdout (checked separately)
print("\n" + ("ALL PROC-C ASSERTIONS PASS" if not fails else f"FAILURES: {fails}"))
sys.exit(0 if not fails else 1)
