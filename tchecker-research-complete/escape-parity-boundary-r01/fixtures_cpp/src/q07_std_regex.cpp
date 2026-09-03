// C++: std::regex patterns. std::regex's DEFAULT grammar is ECMAScript, so these are
// classified through the ECMAScript adapter, exactly like a JS regex literal.
#include <regex>
#include <string>

static const std::regex kIncomplete("'(.*)[^\\\\]'");
static const std::regex kParity("'((?:[^'\\\\]|\\\\.)*)'");

bool has_value(const std::string& s) {
  return std::regex_search(s, kIncomplete) || std::regex_search(s, kParity);
}
