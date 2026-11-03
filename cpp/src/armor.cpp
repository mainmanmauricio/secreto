#include "secreto/armor.hpp"

#include "secreto/base64.hpp"

namespace secreto::armor {

namespace {
bool is_ws(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }
}  // namespace

bool looks_armored(ByteView data) {
  std::string_view s(reinterpret_cast<const char*>(data.data()), data.size());
  std::size_t i = 0;
  while (i < s.size() && is_ws(s[i])) ++i;
  return s.substr(i).substr(0, 10) == "-----BEGIN";
}

std::string encode(ByteView data) {
  std::string b64 = b64_encode_padded(data);
  std::string out(kBegin);
  out.push_back('\n');
  for (std::size_t i = 0; i < b64.size(); i += 64) {
    out.append(b64, i, 64);
    out.push_back('\n');
  }
  out.append(kEnd);
  out.push_back('\n');
  return out;
}

Bytes decode(ByteView data) {
  std::string_view s(reinterpret_cast<const char*>(data.data()), data.size());
  while (!s.empty() && is_ws(s.front())) s.remove_prefix(1);
  while (!s.empty() && is_ws(s.back())) s.remove_suffix(1);

  // Split into lines on LF; tolerate a single CR before each LF.
  std::vector<std::string_view> lines;
  std::size_t start = 0;
  while (true) {
    std::size_t nl = s.find('\n', start);
    std::string_view line =
        (nl == std::string_view::npos) ? s.substr(start) : s.substr(start, nl - start);
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    lines.push_back(line);
    if (nl == std::string_view::npos) break;
    start = nl + 1;
  }

  if (lines.size() < 3 || lines.front() != kBegin) fail(kExitFormat, "armor: bad BEGIN line");
  if (lines.back() != kEnd) fail(kExitFormat, "armor: bad END line");

  std::string b64;
  std::size_t body = lines.size() - 2;
  for (std::size_t i = 1; i <= body; ++i) {
    std::string_view l = lines[i];
    bool last = (i == body);
    if (l.empty() || l.size() > 64 || (!last && l.size() != 64))
      fail(kExitFormat, "armor: bad line width");
    b64.append(l);
  }
  auto bin = b64_decode_padded(b64);
  if (!bin) fail(kExitFormat, "armor: invalid base64");
  return std::move(*bin);
}

}  // namespace secreto::armor
