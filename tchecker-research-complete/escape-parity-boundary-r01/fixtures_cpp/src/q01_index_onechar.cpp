// C++ CONTROL: the same defect shape as the historical PHP rule, written as a
// hand-rolled scanner. The boundary test inspects exactly ONE preceding position.
#include <string>
#include <vector>

std::vector<std::string> split_quoted(const std::string& s) {
  std::vector<std::string> out;
  long start = -1;
  for (size_t i = 1; i < s.size(); ++i) {
    if (s[i] == '\'' && s[i - 1] != '\\') {      // one-position boundary rule
      if (start < 0) { start = (long)i; }
      else { out.push_back(s.substr(start + 1, i - start - 1)); start = -1; }
    }
  }
  return out;
}
