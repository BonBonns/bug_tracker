// GUARD-R01 / task #42: isolated "hard teeth" fixture for OOB_READ. teeth_read's own extent has
// a real DEST_CAPACITY bound (the write side is legitimately guarded) but NO SOURCE_CAPACITY
// bound at all -- a real, correct OOB_READ candidate must survive despite the syntactic guard
// present in the same call, because that guard protects the WRITE side, not the READ side.
#include <cstddef>
#include <cstring>

void teeth_read(size_t n) {
    char dst_buf[32];
    char local_src[8];
    if (n <= sizeof(dst_buf)) {
        memcpy(dst_buf, local_src, n);
    }
}
