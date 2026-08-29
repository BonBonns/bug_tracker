void two_writes(char *a, char *b, const char *s, unsigned count) {
    char *pa = a; char *pb = b; const char *v = s;
    while (count-- != 0) { *pa++ = *v; *pb++ = *v; }
}
