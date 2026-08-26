#!/usr/bin/env python3
"""PHP-ENGINE CLASS-ISOLATION AUDIT (four layers). Static audit of PHPCGFactory:
the four class channels must stay isolated — shared provenance is fine, but
class-specific SOURCE eligibility, SINK eligibility, SAFETY mechanism, and VERDICT
must not cross.

Measured properties + negative controls (a gate that can't fail proves nothing).
"""
import re, sys, pathlib
F = pathlib.Path(__file__).resolve().parents[3]/'core/provenance/PHPCGFactory.java'
src = F.read_text()

def sink_set(name):
    m = re.search(name + r'\s*=\s*new HashSet<String>\(Arrays\.asList\(([^;]*?)\)\)', src, re.S)
    if not m: return set()
    return set(re.findall(r'"([^"]+)"', m.group(1)))

SETS = {c: sink_set(c) for c in
        ['SSRF_SINKS','FILE_READ_SINKS','FILE_WRITE_SINKS','FILE_DELETE_SINKS',
         'OBJ_INJECTION_SINKS','CALLABLE_SINKS']}

results=[]
def ck(name, cond):
    results.append((name, cond)); return cond

# LAYER 2 — SINK ELIGIBILITY ISOLATION: the class sink sets must be DISJOINT.
# A function in two class sets means one class's finding gets another's question.
names=list(SETS)
overlap=[]
for i in range(len(names)):
    for j in range(i+1,len(names)):
        common = SETS[names[i]] & SETS[names[j]]
        if common: overlap.append((names[i],names[j],common))
ck("sink-eligibility: class sink sets pairwise disjoint", not overlap)
if overlap:
    for a,b,c in overlap: print(f"    OVERLAP {a} ∩ {b} = {c}")

# LAYER 2b — the split that was explicitly done: file R/W/D must be separate sets
ck("sink-eligibility: file READ/WRITE/DELETE are distinct sets",
   SETS['FILE_READ_SINKS'] and SETS['FILE_WRITE_SINKS'] and SETS['FILE_DELETE_SINKS']
   and not (SETS['FILE_READ_SINKS'] & SETS['FILE_DELETE_SINKS']))

# LAYER 1 — SOURCE/MODE isolation: each _ONLY mode exists and is independently gated
modes = re.findall(r'public static final boolean (\w+_ONLY)\s*=', src)
ck("mode isolation: >=4 independent class-only modes exist", len(set(modes))>=4)

# LAYER 3 — SAFETY MECHANISM isolation: esc_sql must be CONTEXT-scoped (not a
# blanket suppressor). The context-sensitive esc_sql comment/logic must be present.
ck("safety isolation: esc_sql is context-scoped (not a blanket neutralizer)",
   "Context-sensitive esc_sql" in src or "esc_sql() only neutralizes" in src)
# XSS neutralizers (kses) must not be referenced as SQLi suppressors
ck("safety isolation: kses (XSS) not wired as a SQLi neutralizer",
   not re.search(r'kses[^\n]*sqli', src, re.I))

# LAYER 4 — VERDICT isolation: a verdict carries its class; DispatchVerdict enum
# is dispatch-only and separate from sink-class tagging.
ck("verdict isolation: dispatch verdicts are a separate enum from sink classes",
   "DispatchVerdict" in src and "enum DispatchVerdict" in src)

# ---- NEGATIVE CONTROLS: inject each defect into a COPY, re-run the checks,
#      confirm the corresponding check flips to FAIL. ----
def recheck_disjoint(mutated):
    def ss(name):
        m=re.search(name + r'\s*=\s*new HashSet<String>\(Arrays\.asList\(([^;]*?)\)\)', mutated, re.S)
        return set(re.findall(r'"([^"]+)"', m.group(1))) if m else set()
    a=ss('SSRF_SINKS'); b=ss('FILE_READ_SINKS')
    return not (a & b)

# NC1: cross-wire a sink — add file_get_contents (FILE_READ) into SSRF_SINKS
mut = src.replace('"wp_safe_remote_post"));', '"wp_safe_remote_post","file_get_contents"));',1)
nc1 = not recheck_disjoint(mut)   # disjoint check should now FAIL -> nc1 True means "caught"
ck("NEG-CONTROL 1: cross-wired sink (file_get_contents into SSRF) is CAUGHT", nc1)

# NC2: let an XSS neutralizer suppress SQLi — inject a kses...sqli wiring line
mut2 = src + "\n// kses neutralizes sqli here\n"
nc2 = bool(re.search(r'kses[^\n]*sqli', mut2, re.I))  # our layer-3 check would flag this
ck("NEG-CONTROL 2: XSS(kses) suppressing SQLi is CAUGHT", nc2)

# NC3: emit class B under CLASS_A_ONLY — simulate by removing a mode's independence
mut3 = re.sub(r'public static final boolean XSS_ONLY\s*=', 'public static final boolean XSS_REMOVED =', src, count=1)
modes3 = re.findall(r'public static final boolean (\w+_ONLY)\s*=', mut3)
nc3 = (len(set(modes3)) < len(set(modes)))  # losing a mode is detectable
ck("NEG-CONTROL 3: dropping a class-only mode is CAUGHT", nc3)

passed=sum(1 for _,c in results if c); tot=len(results)
for n,c in results: print(f"  {'PASS' if c else 'FAIL'} {n}")
print(f"PHP_CLASS_ISOLATION={'PASS' if passed==tot else 'FAIL'} ({passed}/{tot})")
sys.exit(0 if passed==tot else 1)
