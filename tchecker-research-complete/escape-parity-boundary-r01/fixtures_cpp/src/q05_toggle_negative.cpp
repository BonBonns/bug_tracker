// C++ NEGATIVE: a parity-aware state machine; the escape flag toggles per character.
#include <string>
#include <vector>

std::vector<std::string> split_quoted(const std::string& s) {
  std::vector<std::string> out;
  bool escaped = false, in_str = false;
  std::string buf;
  for (size_t i = 0; i < s.size(); ++i) {
    char ch = s[i];
    if (escaped) { escaped = !escaped; buf += ch; continue; }
    if (ch == '\\') { escaped = !escaped; buf += ch; continue; }
    if (ch == '\'') {
      if (in_str) { out.push_back(buf); buf.clear(); in_str = false; }
      else { in_str = true; }
      continue;
    }
    if (in_str) buf += ch;
  }
  return out;
}
