// C++ REGRESSION (from real code): a one-position boundary rule in a method that ALSO
// contains a boolean toggle -- but the toggle tracks QUOTE STATE, not escape parity.
//
// Shape observed in mozilla-central dom/base/MimeType.cpp SplitMimetype:
//     if (c == '"' && (i == 0 || s[i - 1] != '\\')) { inQuotes = !inQuotes; }
//
// `inQuotes = !inQuotes` is structurally X = !X, exactly like an escape flag, but it is
// driven by the QUOTE comparison. It says nothing about the parity of a preceding escape
// run, so it must NOT exonerate the one-position rule. Expect: candidate.
#include <string>
#include <vector>

std::vector<std::string> split_on_commas(const std::string& s) {
  std::vector<std::string> parts;
  bool inQuotes = false;
  size_t start = 0;
  for (size_t i = 0; i < s.size(); ++i) {
    char c = s[i];
    if (c == '"' && (i == 0 || s[i - 1] != '\\')) {
      inQuotes = !inQuotes;                 // quote state, NOT escape parity
    } else if (c == ',' && !inQuotes) {
      parts.push_back(s.substr(start, i - start));
      start = i + 1;
    }
  }
  if (start < s.size()) parts.push_back(s.substr(start));
  return parts;
}
