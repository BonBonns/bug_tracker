// E6: the same search-established position, but the rule looks FORWARD for a
// doubled delimiter. That consumes the pair and is parity-correct, so it must
// never reach the candidate path.
#include <string>
#include <vector>

std::vector<std::string> split_quoted_doubling(const std::string& s) {
  const char QUOTE = '"';
  std::vector<std::string> out;
  size_t cursor = 0;
  size_t p = s.find(QUOTE, cursor);
  while (p != std::string::npos) {
    if (s[p + 1] == QUOTE) {
      p = s.find(QUOTE, p + 2);
      continue;
    }
    out.push_back(s.substr(cursor, p - cursor));
    cursor = p + 1;
    p = s.find(QUOTE, cursor);
  }
  return out;
}
