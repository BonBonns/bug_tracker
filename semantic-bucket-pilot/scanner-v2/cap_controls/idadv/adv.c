extern unsigned char T[256];

/* TWIN: two IDENTICAL pointer-walk writes on ONE line -- identical text, operator,
 * destination declaration (param p), file, function, and line. Only the source column
 * distinguishes them. */
void twin(char *p, const char *s) {
    char v = *s;
    *p++ = v; *p++ = v;
}

/* SHADOW: two same-named locals `x` declared in separate nested scopes on ONE line, each
 * written through. The declarations must not collide, and the two writes must stay
 * separate. */
void shadow(const char *a, const char *b, char *o1, char *o2) {
    { char *x = o1; *x++ = *a; }  { char *x = o2; *x++ = *b; }
}
