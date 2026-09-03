// E3: resolvable delimiters with a real escape-run parity count. Resolving a
// delimiter must not turn a correct parser into a candidate.
#include <string>
#include <vector>

std::vector<std::string> split_quoted_parity(const std::string& s) {
  const char QUOTE = '"';
  const char ESCAPE = '\\';
  std::vector<std::string> out;
  size_t start = std::string::npos;
  for (size_t i = 0; i < s.size(); i++) {
    if (s[i] == QUOTE) {
      size_t run = 0;
      size_t j = i;
      while (j > 0 && s[j - 1] == ESCAPE) { run++; j--; }
      if (run % 2 == 0) {
        if (start == std::string::npos) start = i;
        else { out.push_back(s.substr(start + 1, i - start - 1)); start = std::string::npos; }
      }
    }
  }
  return out;
}
