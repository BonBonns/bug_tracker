// C++ CONTROL: the same defect through pointer arithmetic rather than indexing.
#include <cstddef>

const char* find_close(const char* p, const char* end) {
  for (const char* q = p + 1; q < end; ++q) {
    if (*q == '"' && *(q - 1) != '\\') {         // one-position boundary rule
      return q;
    }
  }
  return nullptr;
}
