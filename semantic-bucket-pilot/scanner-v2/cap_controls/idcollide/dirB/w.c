extern unsigned char TB[256];
void wb(void *dest, const void *srce, unsigned count) {
    unsigned char *u = dest; const unsigned char *v = srce;
    while (count-- != 0) *u++ = TB[*v++];
}
