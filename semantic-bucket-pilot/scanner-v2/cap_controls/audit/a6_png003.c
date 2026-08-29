/* PNG003 development body: the EXTRACTED real libpng png_handle_PLTE palette-population
 * loop (pngrutil.c @ a37d4836519517bdce6cb9d956092321eca3e73b), reduced to the
 * write-relevant statements. Struct-member pointer walk over a fixed png_color array --
 * scanner_ok=false in the frozen Magma screen (the cursor producer misses this shape). */
typedef struct { unsigned char red, green, blue; } png_color;
typedef png_color *png_colorp;
#define PNG_MAX_PALETTE_LENGTH 256

void png_handle_PLTE_devsite(const unsigned char *buf_src, int num) {
    png_color palette[PNG_MAX_PALETTE_LENGTH];
    png_colorp pal_ptr;
    int i;
    for (i = 0, pal_ptr = palette; i < num; i++, pal_ptr++) {
        unsigned char buf[3];
        buf[0] = buf_src[3*i]; buf[1] = buf_src[3*i+1]; buf[2] = buf_src[3*i+2];
        pal_ptr->red = buf[0];
        pal_ptr->green = buf[1];
        pal_ptr->blue = buf[2];
    }
}
