void a1_raw(const char *s, unsigned n) {
    char buf[64]; char *p = buf;
    while (n-- != 0) *p++ = *s++;
}
