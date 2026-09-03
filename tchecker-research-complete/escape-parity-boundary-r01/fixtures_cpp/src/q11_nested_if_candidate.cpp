// C++ CONTROL (R09): the same one-position boundary rule as q01, but written as
// two NESTED `if` statements instead of one chained `&&` condition. The quote
// comparison and the escape check are still the SAME logical rule -- the escape
// check only runs when the quote comparison is already true -- so this must stay
// a candidate under the R09 same-boundary-scope requirement, which is not merely
// "same enclosing if" but "one nested inside the other's branch".
#include <cstddef>

bool is_unescaped_closing_quote(const char* s, size_t i) {
  if (s[i] == '"') {
    if (i != 0 && s[i - 1] != '\\') {
      return true;
    }
  }
  return false;
}
