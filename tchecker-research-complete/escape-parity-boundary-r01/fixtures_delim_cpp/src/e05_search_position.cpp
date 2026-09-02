// E5: the quote position comes from std::string::find rather than a comparison,
// with delimiters that resolve. The rule still inspects one preceding position
// -> candidate. Before R06 the quote half of this rule was never found.
#include <string>
#include <vector>

std::vector<std::string> split_quoted_search(const std::string& s) {
  const char QUOTE = '"';
  const char ESCAPE = '\\';
  std::vector<std::string> out;
  size_t cursor = 0;
  size_t p = s.find(QUOTE, cursor);
  while (p != std::string::npos) {
    if (p != 0 && s[p - 1] == ESCAPE) {
      p = s.find(QUOTE, p + 1);
      continue;
    }
    out.push_back(s.substr(cursor, p - cursor));
    cursor = p + 1;
    p = s.find(QUOTE, cursor);
  }
  return out;
}
