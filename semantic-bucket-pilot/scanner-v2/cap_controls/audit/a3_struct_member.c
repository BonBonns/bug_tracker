struct rgb { unsigned char red, green, blue; };
void a3_struct(const unsigned char *s, unsigned n) {
    struct rgb pal[256]; struct rgb *pp = pal; unsigned i;
    for (i = 0; i < n; i++) { pp->red = s[0]; pp->green = s[1]; pp->blue = s[2]; pp++; s += 3; }
}
