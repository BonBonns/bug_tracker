#include <stdlib.h>
#include <string.h>

/* Struct with a FIXED-array member and a POINTER member -- distinguishes the two
 * (member extent known vs unknown) purely from the CPG member declaration. */
struct S { char buf[16]; char *pbuf; };

/* ------------------------------------------------------------------------- *
 * Emission-gap originals (recognized memcpy, previously silently dropped).
 * ------------------------------------------------------------------------- */

/* MEMBER (fixed array char[16]), symbolic width -> capacity known, relation
 * unresolved => capacity_relation_not_established (relationship_unresolved). */
void eg_member(struct S *s, const char *src, int n) { memcpy(s->buf, src, n); }

/* ADDRESS-OF a local scalar (int, 4 bytes), literal width 4 -> fixed extent,
 * literal offset 0, literal width; 4<=4 fits => within-bounds abstention. */
void eg_addrof(const char *src) { int obj; memcpy(&obj, src, 4); }

/* POINTER-ARITHMETIC on a POINTER parameter (base is char*, no compile-time
 * extent) -> identity known, extent absent => required_evidence_absent. */
void eg_ptrarith(char *base, int off, const char *src, int n) { memcpy(base + off, src, n); }

/* BARE pointer, NO allocation -> required_evidence_absent (r01 regression path,
 * bare branch, unchanged) + missing_requirement=destination_capacity. */
void eg_bare_noalloc(char *p, const char *src, int n) { memcpy(p, src, n); }

/* BARE pointer WITH allocation, same width -> deterministic_complete (UNCHANGED). */
void eg_bare_alloc(const char *src, int n) { char *p = malloc(n); memcpy(p, src, n); free(p); }

/* BARE pointer WITH allocation, DIFFERENT width -> open_candidate (UNCHANGED). */
void eg_bare_alloc_open(const char *src, int n, int m) { char *p = malloc(n); memcpy(p, src, m); free(p); }

/* ------------------------------------------------------------------------- *
 * Form controls required for the form-aware split. Each names the exact CPG
 * resolution the diagnosis must perform (NOT a text pattern).
 * ------------------------------------------------------------------------- */

/* &local_scalar: &obj, obj is int -> fixed extent 4, offset 0, LITERAL BYTE width
 * "4" (not sizeof(int)) => relationship_unresolved: comparing a raw byte literal
 * against a 1-int extent would require assuming sizeof(int)==4, an ABI fact this
 * arithmetic never assumes without a real sizeof() in the width expression. */
void f_addr_scalar(const char *src) { int obj; memcpy(&obj, src, 4); }

/* &local_scalar with a WIDTH EXPRESSED AS sizeof(int): unit-safe by construction
 * (k_sizeof, k=1, wt="int" == element_type "int") -> 1<=1 => deterministic_complete.
 * Proves the delegated scalar path actually reaches a safe verdict when the
 * width expression itself carries the unit relationship, rather than only ever
 * proving the two symbolic/unit-mismatch abstention traps. */
void f_addr_scalar_sizeof(const char *src) { int obj; memcpy(&obj, src, sizeof(int)); }

/* fixed-array MEMBER: s->buf is char[16] -> member extent KNOWN, symbolic width
 * => capacity_relation_not_established (fixed_array_member). */
void f_member_fixed(struct S *s, const char *src, int n) { memcpy(s->buf, src, n); }

/* pointer MEMBER: s->pbuf is char* -> member identity known, extent UNKNOWN
 * => required_evidence_absent (pointer_member). */
void f_member_ptr(struct S *s, const char *src, int n) { memcpy(s->pbuf, src, n); }

/* known array + LITERAL offset, symbolic width -> capacity known, relation
 * unresolved (offset literal but width symbolic) => capacity_relation_not_established. */
void f_arr_litoff(const char *src, int n) { char a[64]; memcpy(a + 4, src, n); }

/* known array + SYMBOLIC offset -> capacity known, offset unresolved
 * => capacity_relation_not_established (fixed_extent_symbolic_relation). */
void f_arr_symoff(const char *src, int i, int n) { char a[64]; memcpy(a + i, src, n); }

/* known array + literal offset + literal width, FITS: remaining 64-4=60 >= 8
 * => within-bounds abstention (comparison computed). */
void f_arr_lit_lit(const char *src) { char a[64]; memcpy(a + 4, src, 8); }

/* known array + literal offset + literal width, EXCEEDS: 16-8=8 < 32
 * => open_candidate (provable overrun flagged as candidate, never a hard verdict). */
void f_arr_lit_over(const char *src) { char a[16]; memcpy(a + 8, src, 32); }

/* CAST/alias: (char*)dst where dst is void* param -> cast unwrapped to the
 * pointer object => required_evidence_absent (pointer_object). */
void f_cast(void *dst, const char *src, int n) { memcpy((char*)dst, src, n); }

/* side-effecting destination p++ -> written object identity is unstable
 * => destination_identity_ambiguous (side_effecting_expression). */
void f_sideeffect(char *p, const char *src, int n) { memcpy(p++, src, n); }

/* SHADOWED same-name bases: an inner block redeclares `a` (char[8]) shadowing the
 * outer `a` (char[64]). ref-target resolution must bind each memcpy's `a` to the
 * declaration actually in scope -- the inner write resolves to extent 8, the outer
 * write to extent 64. A name/nearest-decl heuristic would get this wrong. */
void f_shadow(const char *src) {
    char a[64];
    { char a[8]; memcpy(a + 1, src, 2); }   /* inner: extent 8, 1+2=3 <= 8 fits */
    memcpy(a + 60, src, 8);                  /* outer: extent 64, 60+8=68 > 64 exceeds */
}
