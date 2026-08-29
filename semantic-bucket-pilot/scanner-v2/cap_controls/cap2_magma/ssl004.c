/* Magma SSL004 dev-site recovery: the REAL ascii2ebcdic wrapper body (OpenSSL
 * crypto/ebcdic.c @ 3bd5319b5d0df9ecf05c8baba2c401ad8e3ba130) and the REAL call
 * site structure (crypto/x509/x509_obj.c: ebcdic_buf[1024], num clamped, then
 * ascii2ebcdic(ebcdic_buf, q, num)). Verbatim wrapper; caller reduced to the
 * write-relevant statements. NOT a hand model of the shape -- the real body. */
#include <string.h>
extern const unsigned char os_toebcdic[256];

void *ascii2ebcdic(void *dest, const void *srce, size_t count)
{
    unsigned char *udest = dest;
    const unsigned char *usrce = srce;

    while (count-- != 0) {
        *udest++ = os_toebcdic[*usrce++];
    }

    return dest;
}

void X509_NAME_oneline_devsite(const char *q, int num)
{
    unsigned char ebcdic_buf[1024];
    if (num > (int)sizeof(ebcdic_buf))
        num = sizeof(ebcdic_buf);
    ascii2ebcdic(ebcdic_buf, q, num);
}
