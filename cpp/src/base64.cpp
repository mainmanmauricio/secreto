#include "secreto/base64.hpp"

namespace secreto {

namespace {

constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int decode_char(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

std::string encode(ByteView data, bool pad) {
  std::string out;
  out.reserve((data.size() + 2) / 3 * 4);
  std::size_t i = 0;
  for (; i + 3 <= data.size(); i += 3) {
    std::uint32_t v = (std::uint32_t{data[i]} << 16) | (std::uint32_t{data[i + 1]} << 8) |
                      data[i + 2];
    out.push_back(kAlphabet[(v >> 18) & 63]);
    out.push_back(kAlphabet[(v >> 12) & 63]);
    out.push_back(kAlphabet[(v >> 6) & 63]);
    out.push_back(kAlphabet[v & 63]);
  }
  std::size_t rem = data.size() - i;
  if (rem == 1) {
    std::uint32_t v = std::uint32_t{data[i]} << 16;
    out.push_back(kAlphabet[(v >> 18) & 63]);
    out.push_back(kAlphabet[(v >> 12) & 63]);
    if (pad) out += "==";
  } else if (rem == 2) {
    std::uint32_t v = (std::uint32_t{data[i]} << 16) | (std::uint32_t{data[i + 1]} << 8);
    out.push_back(kAlphabet[(v >> 18) & 63]);
    out.push_back(kAlphabet[(v >> 12) & 63]);
    out.push_back(kAlphabet[(v >> 6) & 63]);
    if (pad) out += "=";
  }
  return out;
}

// Decode `s` (no padding characters) strictly.
std::optional<Bytes> decode_core(std::string_view s) {
  if (s.size() % 4 == 1) return std::nullopt;
  Bytes out;
  out.reserve(s.size() / 4 * 3 + 2);
  std::uint32_t acc = 0;
  int bits = 0;
  for (char c : s) {
    int v = decode_char(c);
    if (v < 0) return std::nullopt;
    acc = (acc << 6) | static_cast<std::uint32_t>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<std::uint8_t>((acc >> bits) & 0xff));
    }
  }
  // Leftover bits (< 8) must be zero for canonical encodings.
  if (bits > 0 && (acc & ((1u << bits) - 1)) != 0) return std::nullopt;
  return out;
}

}  // namespace

std::string b64_encode(ByteView data) { return encode(data, false); }
std::string b64_encode_padded(ByteView data) { return encode(data, true); }

std::optional<Bytes> b64_decode(std::string_view s) { return decode_core(s); }

std::optional<Bytes> b64_decode_padded(std::string_view s) {
  if (s.size() % 4 != 0) return std::nullopt;
  std::size_t pad = 0;
  while (pad < 2 && pad < s.size() && s[s.size() - 1 - pad] == '=') ++pad;
  return decode_core(s.substr(0, s.size() - pad));
}

}  // namespace secreto
