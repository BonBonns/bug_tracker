// E1: C++ delimiters held in variables that resolve to one character literal
// each. The rule still inspects a single preceding position -> candidate.
#include <string>
#include <vector>

std::vector<std::string> split_quoted_resolved(const std::string& s) {
  const char QUOTE = '"';
  const char ESCAPE = '\\';
  std::vector<std::string> out;
  size_t start = std::string::npos;
  for (size_t i = 0; i < s.size(); i++) {
    if (s[i] == QUOTE && (i == 0 || s[i - 1] != ESCAPE)) {
      if (start == std::string::npos) start = i;
      else { out.push_back(s.substr(start + 1, i - start - 1)); start = std::string::npos; }
    }
  }
  return out;
}
