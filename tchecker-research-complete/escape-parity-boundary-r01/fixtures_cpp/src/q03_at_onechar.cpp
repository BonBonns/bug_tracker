// C++ CONTROL: the same defect through std::string::at().
#include <string>

size_t close_pos(const std::string& s) {
  for (size_t i = 1; i < s.size(); ++i) {
    if (s.at(i) == '"' && s.at(i - 1) != '\\') { // one-position boundary rule
      return i;
    }
  }
  return std::string::npos;
}
