// C++ CONTROL: the one-position rule written with the realistic i==0 guard. The guard
// is about staying in bounds, not about escape-run parity, so this is still a candidate.
#include <string>
#include <vector>

std::vector<std::string> split_quoted(const std::string& s) {
  std::vector<std::string> out;
  long start = -1;
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '\'' && (i == 0 || s[i - 1] != '\\')) {
      if (start < 0) { start = (long)i; }
      else { out.push_back(s.substr(start + 1, i - start - 1)); start = -1; }
    }
  }
  return out;
}
