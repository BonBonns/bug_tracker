// C++ CHAIN CONTROL: the same parser applied to a value built in memory in the same
// call. Not delayed / second-order.
#include <string>
#include <vector>

static std::vector<std::string> split_quoted(const std::string& s) {
  std::vector<std::string> out;
  long start = -1;
  for (size_t i = 0; i < s.size(); ++i)
    if (s[i] == '\'' && (i == 0 || s[i - 1] != '\\')) {
      if (start < 0) start = (long)i;
      else { out.push_back(s.substr(start + 1, i - start - 1)); start = -1; }
    }
  return out;
}

std::vector<std::string> normalize(const std::vector<std::string>& rows) {
  std::string joined;
  for (const auto& r : rows) { joined += r; joined += ", "; }
  return split_quoted(joined);
}
