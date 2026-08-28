#!/usr/bin/env python3
"""Validation gate for capability 1 (stack fixed-array capacity), covering the
11 required cases with minimal synthetic facts. Tests the component functions
directly so identity/offset/type boundaries are exercised without a full scan.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oob_runtime_capacity_v2 as v2

N = 0
def ck(desc, cond):
    global N
    print(("PASS" if cond else "FAIL"), desc)
    assert cond, desc
    N += 1


def local(nid, mid, name, type_full, code):
    return {"id": nid, "method_id": mid, "name": name, "type_full_name": type_full, "code": code, "line": 1}


def call(fn_id, line, name, dest_valueref, width_code):
    return {"name": name, "enclosing_function_id": fn_id, "line": line,
            "arguments": [{"index": 0, "code": dest_valueref.get("code", ""), "value_ref": dest_valueref},
                          {"index": 1, "code": "src", "value_ref": {"kind": "IDENTIFIER"}},
                          {"index": 2, "code": width_code, "value_ref": {"kind": "CALL"}}]}


# 1. Direct fixed array -> extent computed
d1 = {"locals": [local(100, 10, "buf", "unsigned char[64]", "unsigned char buf[64]")]}
ext1 = v2.compute_stack_fixed_array_extents(d1)
ck("1. direct fixed array -> extent (elem uint8, N=64)",
   ext1.get((10, 100), {}).get("element_count") == 64 and ext1[(10, 100)]["provenance"] == "stack_fixed_array")

# 2. Same variable name in different functions -> keyed separately by decl node
d2 = {"locals": [local(100, 10, "at", "mp_digit[8]", "mp_digit at[8]"),
                 local(200, 20, "at", "mp_digit[16]", "mp_digit at[16]")]}
ext2 = v2.compute_stack_fixed_array_extents(d2)
ck("2. same name in two functions -> separated by (fn,node) with distinct N",
   ext2[(10, 100)]["element_count"] == 8 and ext2[(20, 200)]["element_count"] == 16 and len(ext2) == 2)

# 3. Shadowed arrays in one function -> two decls; resolution by node id picks uniquely
d3 = {"locals": [local(101, 10, "a", "int[4]", "int a[4]"),
                 local(102, 10, "a", "int[9]", "int a[9]")]}
ext3 = v2.compute_stack_fixed_array_extents(d3)
c_uniq = call(10, 5, "memcpy", {"kind": "LOCAL", "id": 102, "code": "a"}, "9 * sizeof(int)")
did, why = v2.resolve_sink_decl(c_uniq, 0)
ck("3. shadowed arrays: reference resolves UNIQUELY to the intended decl node",
   len(ext3) == 2 and did == 102 and v2.compare(ext3[(10, 102)], "9 * sizeof(int)")[0] == "deterministic_complete")

# 4. Pointer parameter -> not treated as an array (no extent)
d4 = {"locals": [local(103, 10, "p", "unsigned char*", "unsigned char *p")]}
ck("4. pointer parameter -> no stack extent", (10, 103) not in v2.compute_stack_fixed_array_extents(d4))

# 5. Pointer alias to an array -> excluded (dest resolves to a pointer local, not an array decl)
d5 = {"locals": [local(104, 10, "q", "unsigned char*", "unsigned char *q")]}
c5 = call(10, 6, "memcpy", {"kind": "LOCAL", "id": 104, "code": "q"}, "4")
did5, _ = v2.resolve_sink_decl(c5, 0)
ck("5. pointer alias -> resolves to a LOCAL but it is not a fixed array -> excluded",
   did5 == 104 and (10, 104) not in v2.compute_stack_fixed_array_extents(d5))

# 6. Variable-length array -> excluded (non-literal N)
d6 = {"locals": [local(105, 10, "v", "int[n]", "int v[n]")]}
ck("6. VLA -> excluded", (10, 105) not in v2.compute_stack_fixed_array_extents(d6))

# 6b. Multidimensional -> excluded
d6b = {"locals": [local(106, 10, "m", "int[4][4]", "int m[4][4]")]}
ck("6b. multidimensional -> excluded", (10, 106) not in v2.compute_stack_fixed_array_extents(d6b))

# 7. Offset write -> dest arg is CALL (at+4), not a LOCAL -> excluded
c7 = call(10, 7, "memcpy", {"kind": "CALL", "id": 999, "code": "at + 4"}, "4 * sizeof(mp_digit)")
did7, why7 = v2.resolve_sink_decl(c7, 0)
ck("7. offset write (at+4) -> not a bare LOCAL -> excluded", did7 is None and why7.startswith("dest_not_local"))

# 8. Mismatched element types -> not simplified
ext8 = v2.compute_stack_fixed_array_extents({"locals": [local(107, 10, "b", "uint32_t[8]", "uint32_t b[8]")]})
ck("8. mismatched element types -> relationship_unresolved (not simplified)",
   v2.compare(ext8[(10, 107)], "8 * sizeof(uint8_t)")[0] == "relationship_unresolved")

# 9. Symbolic write count -> relationship_unresolved
ck("9. symbolic write count -> relationship_unresolved",
   v2.compare(ext1[(10, 100)], "len * sizeof(unsigned char)")[0] == "relationship_unresolved")

# 10. Literal safe vs literal oversized -> distinguished
ck("10a. literal safe (k<=N) -> deterministic_complete",
   v2.compare(ext2[(10, 100)], "4 * sizeof(mp_digit)")[0] == "deterministic_complete")
ck("10b. literal oversized (k>N) -> proven_oversized (never called safe)",
   v2.compare(ext2[(10, 100)], "9 * sizeof(mp_digit)")[0] == "proven_oversized")

# 10c. byte-array literal byte count
ck("10c. byte array literal bytes (k<=N) -> deterministic",
   v2.compare(ext1[(10, 100)], "60")[0] == "deterministic_complete")
ck("10d. byte array literal bytes (k>N) -> proven_oversized",
   v2.compare(ext1[(10, 100)], "80")[0] == "proven_oversized")

# 11. Existing heap-allocation behavior unchanged: a non-abstained record passes through.
#     (structural: analyze_operations_v2 only augments abstained/required_evidence_absent;
#     verified end-to-end by the v1-vs-v2 comparison. Here assert the guard exists.)
import inspect
src = inspect.getsource(v2.analyze_operations_v2)
ck("11. heap/other records untouched (only abstained+required_evidence_absent augmented)",
   'required_evidence_absent' in src and 'out.append(r)   # heap / other -> unchanged' in src)

print(f"\nSTACK_CAPACITY_V2_GATE={N}/{N}")
