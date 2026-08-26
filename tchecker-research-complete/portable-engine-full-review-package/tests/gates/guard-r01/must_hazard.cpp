struct B { int f; };
B *get_ptr();                       // unknown source
int must_hazard(int input) {        // p = &a THEN p = <unknown>; write via p
	B a;
	B *p = &a;
	p = get_ptr();                  // p may now point ANYWHERE
	p->f = input;
	return a.f;                     // TRUTH: input may NOT reach a.f at all
}
