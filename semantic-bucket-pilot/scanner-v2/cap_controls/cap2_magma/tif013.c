/* Magma TIF013 dev-site: the _TIFFmemcpy delegation wrapper (libtiff's portable
 * memcpy wrapper, tif_unix.c: `void* _TIFFmemcpy(void*d,const void*s,tmsize_t c)
 * { return memcpy(d,s,c); }`) and the tif_jbig.c JBIGDecode call
 * `_TIFFmemcpy(buffer, pImage, decodedSize)`. The wrapper body is the real
 * one-line delegation; the caller is reduced to the write-relevant statement. */
#include <string.h>

void *_TIFFmemcpy(void *d, const void *s, unsigned long c) { return memcpy(d, s, c); }

void JBIGDecode_devsite(const unsigned char *pImage, unsigned long decodedSize)
{
    unsigned char buffer[512];
    _TIFFmemcpy(buffer, pImage, decodedSize);
}
