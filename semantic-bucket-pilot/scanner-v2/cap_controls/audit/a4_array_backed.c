void a4_arr(const char *s, unsigned n) {
    char dst[128]; char *w = dst;
    for (unsigned i = 0; i < n; i++) { *w = s[i]; w++; }
}
