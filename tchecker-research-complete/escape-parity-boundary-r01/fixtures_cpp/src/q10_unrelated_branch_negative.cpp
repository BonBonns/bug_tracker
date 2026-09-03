// C++ REGRESSION (R09, from real code): a single character-by-character scanner
// with TWO SEPARATE `if`/`else if` branches that both compare the current character
// against a quote literal on the SAME buffer and index variable -- but only ONE of
// them has an escape check anywhere near it.
//
// Shape observed in alliedmodders/source2mod core/logic/TextParsers.cpp
// ParseStream_SMC: a "closing quote" branch that DOES check the preceding position
// (`in_quote && c == '"' && buf[i-1] != '\\'`), and a completely separate
// "opening quote" branch a few dozen lines later in the SAME method that has no
// escape check at all (`else if (c == '"') { in_quote = true; }`) because opening
// a quoted region never needs escape-awareness -- only closing one does.
//
// Before R09 the producer paired an escape check with EVERY quote comparison in the
// same METHOD sharing the same base expression and index variable, with no
// requirement that they be part of the same conditional. That borrowed the closing
// branch's real escape check as "evidence" for the opening branch, producing a
// second, spurious ESCAPE_PARITY_PARSER_CANDIDATE where there is no boundary rule
// at all. Expect: the closing branch is a candidate; the opening branch is a
// negative with NO_ESCAPE_AWARENESS, carrying no borrowed single_position_checks.
#include <cstddef>

struct ScanState {
  bool in_quote;
  bool ignoring;
};

void scan_line(const char* buf, size_t len, ScanState& st) {
  for (size_t i = 0; i < len; ++i) {
    char c = buf[i];
    if (st.ignoring) {
      if (st.in_quote) {
        // closing-quote branch: DOES inspect one preceding position
        if (i != 0 && c == '"' && buf[i - 1] != '\\') {
          st.in_quote = false;
          st.ignoring = false;
        }
      }
    } else if (c == '{') {
      // unrelated structural token, same method, same index variable
      continue;
    } else if (c == '"') {
      // opening-quote branch: no escape check anywhere near it -- and none is
      // needed, since you cannot escape a quote that has not started yet.
      st.in_quote = true;
      st.ignoring = true;
    }
  }
}
