// PARAM-R01 gate: a parameter is a MUTABLE STORAGE LOCATION.
// Each case pins one aspect of the contract.

int p1_reassign_before_return(int a, int b) { a = b; return a; }        // b only

int p2_branch_reassign(int a, int b, int c) {                           // MAY {a,b}, never stale EXACT[0]
	if (c) { a = b; }
	return a;
}

int p3_self_assign(int a) { a = a; return a; }                          // still a

int p4_chained(int a, int b, int c) { a = b; b = c; return a; }         // b's value, NOT c

int p5_compound(int a, int b) { a += b; return a; }                     // prior a AND b, never exact

int p6_latest_wins(int a, int b, int c) { a = b; a = c; return a; }     // c only

int p7_dead_after_return(int a, int b) { return a; }                    // a (no reassignment at all)

int p8_ptr_param_mutation(int *p, int v) { *p = v; return *p; }         // v (writes through pointer)
