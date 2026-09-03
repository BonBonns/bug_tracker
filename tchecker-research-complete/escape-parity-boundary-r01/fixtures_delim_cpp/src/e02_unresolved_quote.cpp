// E2: the quote character comes from configuration, so its identity cannot be
// resolved. The site must be recorded and abstain, not disappear.
#include <string>
#include <vector>

std::vector<std::string> split_quoted_configurable(const std::string& s, char cfg_quote) {
  char quote = '"';
  if (cfg_quote != 0) quote = cfg_quote;
  const char ESCAPE = '\\';
  std::vector<std::string> out;
  size_t start = std::string::npos;
  for (size_t i = 0; i < s.size(); i++) {
    if (s[i] == quote && (i == 0 || s[i - 1] != ESCAPE)) {
      if (start == std::string::npos) start = i;
      else { out.push_back(s.substr(start + 1, i - start - 1)); start = std::string::npos; }
    }
  }
  return out;
}
