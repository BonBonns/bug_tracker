void a2_off(const char *s, unsigned n) {
    char buf[64]; char *p = buf;
    while (n-- != 0) { *(p + 1) = *s; p += 1; s++; }
}
