extern unsigned char TA[256];
void wa(void *dest, const void *srce, unsigned count) {
    unsigned char *u = dest; const unsigned char *v = srce;
    while (count-- != 0) *u++ = TA[*v++];
}
