#include <stdlib.h>

/* Minimal EXTERNAL prototypes (NOT the real headers) so the decoder calls parse. Unspecified
 * argument lists `()` let one translation unit legally hold both correct-arity and
 * wrong-arity calls of the same name, so the signature-arity gate can be exercised. */
int LZ4_decompress_safe();
int LZ4_decompress_safe_partial();

typedef struct z_stream_s { unsigned char *next_out; unsigned avail_out; } z_stream;
typedef z_stream *z_streamp;
int inflate();

/* BOUNDED: dstCapacity literal 100 == buffer size 100 -> the API cannot write past dst
 * -> deterministic_complete (write extent within destination capacity). */
int dc_fits(const char *src, int n) {
    char dst[100];
    return LZ4_decompress_safe(src, dst, n, 100);
}

/* OVERSIZED: dstCapacity 200 passed for a 64-byte dst -> the decoder is TOLD it may write up
 * to 200 bytes into a 64-byte buffer -> proven_oversized. */
int dc_over(const char *src, int n) {
    char dst[64];
    return LZ4_decompress_safe(src, dst, n, 200);
}

/* BOUNDED via sizeof: dstCapacity == sizeof(dst) binds the extent to the exact capacity. */
int dc_sizeof(const char *src, int n) {
    char dst[100];
    return LZ4_decompress_safe(src, dst, n, sizeof(dst));
}

/* UNRESOLVED (symbolic capacity): the extent argument is a variable -> the max write extent
 * is not bounded -> recognize the operation, relationship unresolved (never a false safe). */
int dc_symbolic(const char *src, int n, int cap) {
    char dst[100];
    return LZ4_decompress_safe(src, dst, n, cap);
}

/* UNRESOLVED (dest capacity): dst is a parameter of unknown capacity; the extent is literal
 * but there is no independently-established buffer size to compare against -> unresolved. */
int dc_param_dst(const char *src, char *dst, int n) {
    return LZ4_decompress_safe(src, dst, n, 128);
}

/* BOUNDED via heap allocation: dst is a literal-count byte allocation; dstCapacity 256 <=
 * 256-byte allocation -> bounded. */
int dc_heap(const char *src, int n) {
    char *dst = malloc(256);
    int r = LZ4_decompress_safe(src, dst, n, 256);
    free(dst);
    return r;
}

/* PARTIAL-WRITE contract: LZ4_decompress_safe_partial, arg4 dstCapacity literal 256 <= 256
 * buffer -> bounded (the dstCapacity bound holds even on the early-stop / partial path). */
int dc_partial(const char *src, int n) {
    char dst[256];
    return LZ4_decompress_safe_partial(src, dst, n, 100, 256);
}

/* STATEFUL decoder (zlib inflate): destination + capacity live in the z_stream (next_out /
 * avail_out). The max write extent is the PRE-call avail_out (remaining capacity), which is
 * NOT tracked and must NOT be read as bytes-written -> recognize, relationship unresolved. */
int dc_inflate(z_streamp strm) {
    return inflate(strm, 0);
}

/* SIGNATURE not NAME #1 -- ARITY MISMATCH: the LZ4 contract signature has 4 parameters; a
 * 3-argument call of the same name is NOT the library API -> not bound. */
int dc_arity(const char *src, int n) {
    char dst[100];
    return LZ4_decompress_safe(src, dst, n);
}

/* SIGNATURE not NAME #2 -- LOCAL SHADOW: a user-defined function whose name AND signature
 * match the zlib deflate contract exactly, but it is locally DEFINED (has a body). The
 * contract is tied to the library, not the name, so cap4 must NOT bind this call. */
static int deflate(z_streamp strm, int flush) { (void)flush; strm->avail_out -= 1; return 0; }
int dc_local_deflate(z_streamp strm) { return deflate(strm, 0); }

/* NEGATIVE: a plain memcpy is not a decoder contract -> no cap4 op. */
void dc_notdecoder(char *d, const char *s, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) d[i] = s[i];
}
