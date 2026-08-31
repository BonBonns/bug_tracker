// GUARD-R01 / task #42: isolated "hard teeth" fixture for OOB_WRITE. teeth_case has the exact
// same real shape as g.cpp's nc_b6 (a SOURCE_CAPACITY bound present on the read side, NO bound
// at all on the write side) but reproduced alone so oob_write_controls.py's teeth-hard check
// runs against a minimal, single-function corpus.
#include <cstddef>
#include <cstring>

void teeth_case(size_t n) {
    char dst_buf[64];
    char local_src[8];
    if (n <= sizeof(local_src)) {
        memcpy(dst_buf, local_src, n);
    }
}
