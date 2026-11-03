// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

#include "secreto/bech32.hpp"

#include <cstring>

namespace secreto {

namespace {

constexpr char kCharset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

std::uint32_t polymod(const std::vector<std::uint8_t>& values) {
  static const std::uint32_t gen[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd,
                                       0x2a1462b3};
  std::uint32_t chk = 1;
  for (std::uint8_t v : values) {
    std::uint8_t top = static_cast<std::uint8_t>(chk >> 25);
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (int i = 0; i < 5; ++i) {
      if ((top >> i) & 1) chk ^= gen[i];
    }
  }
  return chk;
}

std::vector<std::uint8_t> hrp_expand(std::string_view lower_hrp) {
  std::vector<std::uint8_t> out;
  out.reserve(lower_hrp.size() * 2 + 1);
  for (char c : lower_hrp) out.push_back(static_cast<std::uint8_t>(c) >> 5);
  out.push_back(0);
  for (char c : lower_hrp) out.push_back(static_cast<std::uint8_t>(c) & 31);
  return out;
}

char lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }
char upper(char c) { return (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c; }

// Regroup bits; `pad` adds trailing zero bits when encoding. Strict when
// decoding: leftover bits must be < from_bits and zero.
bool convert_bits(const std::vector<std::uint8_t>& in, int from, int to, bool pad,
                  std::vector<std::uint8_t>& out) {
  std::uint32_t acc = 0;
  int bits = 0;
  const std::uint32_t maxv = (1u << to) - 1;
  for (std::uint8_t v : in) {
    if ((v >> from) != 0) return false;
    acc = (acc << from) | v;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push_back(static_cast<std::uint8_t>((acc >> bits) & maxv));
    }
    acc &= (1u << bits) - 1;
  }
  if (pad) {
    if (bits > 0) out.push_back(static_cast<std::uint8_t>((acc << (to - bits)) & maxv));
  } else {
    if (bits >= from) return false;
    if (acc != 0) return false;
  }
  return true;
}

}  // namespace

std::string bech32_encode(std::string_view hrp, ByteView data) {
  if (hrp.empty()) fail(kExitUsage, "bech32: empty HRP");
  bool has_upper = false, has_lower = false;
  std::string lhrp;
  for (char c : hrp) {
    unsigned char u = static_cast<unsigned char>(c);
    if (u < 33 || u > 126) fail(kExitUsage, "bech32: invalid HRP character");
    if (c >= 'A' && c <= 'Z') has_upper = true;
    if (c >= 'a' && c <= 'z') has_lower = true;
    lhrp.push_back(lower(c));
  }
  if (has_upper && has_lower) fail(kExitUsage, "bech32: mixed-case HRP");

  std::vector<std::uint8_t> d8(data.begin(), data.end());
  std::vector<std::uint8_t> d5;
  convert_bits(d8, 8, 5, true, d5);

  std::vector<std::uint8_t> values = hrp_expand(lhrp);
  values.insert(values.end(), d5.begin(), d5.end());
  values.insert(values.end(), 6, 0);
  std::uint32_t mod = polymod(values) ^ 1;
  for (int i = 0; i < 6; ++i) d5.push_back(static_cast<std::uint8_t>((mod >> (5 * (5 - i))) & 31));

  std::string out(hrp);
  out.push_back('1');
  for (std::uint8_t v : d5) out.push_back(kCharset[v]);
  if (has_upper) {
    for (char& c : out) c = upper(c);
  }
  if (out.size() > kBech32MaxLen) fail(kExitUsage, "bech32: string too long");
  cleanse(d8);
  return out;
}

std::optional<Bech32Decoded> bech32_decode(std::string_view s) {
  if (s.size() > kBech32MaxLen || s.size() < 8) return std::nullopt;
  bool has_upper = false, has_lower = false;
  for (char c : s) {
    unsigned char u = static_cast<unsigned char>(c);
    if (u < 33 || u > 126) return std::nullopt;
    if (c >= 'A' && c <= 'Z') has_upper = true;
    if (c >= 'a' && c <= 'z') has_lower = true;
  }
  if (has_upper && has_lower) return std::nullopt;

  std::size_t sep = s.rfind('1');
  if (sep == std::string_view::npos || sep < 1 || s.size() - sep - 1 < 6) return std::nullopt;

  std::string lhrp;
  for (char c : s.substr(0, sep)) lhrp.push_back(lower(c));

  std::vector<std::uint8_t> d5;
  for (char c : s.substr(sep + 1)) {
    const char* p = static_cast<const char*>(std::memchr(kCharset, lower(c), 32));
    if (p == nullptr) return std::nullopt;
    d5.push_back(static_cast<std::uint8_t>(p - kCharset));
  }

  std::vector<std::uint8_t> values = hrp_expand(lhrp);
  values.insert(values.end(), d5.begin(), d5.end());
  if (polymod(values) != 1) return std::nullopt;

  d5.resize(d5.size() - 6);
  std::vector<std::uint8_t> d8;
  if (!convert_bits(d5, 5, 8, false, d8)) return std::nullopt;

  Bech32Decoded r;
  r.hrp = std::string(s.substr(0, sep));
  r.data.assign(d8.begin(), d8.end());
  cleanse(d8);
  return r;
}

std::optional<Bytes> bech32_decode_exact(std::string_view s, std::string_view hrp,
                                         std::size_t data_len) {
  auto d = bech32_decode(s);
  if (!d || d->hrp != hrp || d->data.size() != data_len) return std::nullopt;
  return std::move(d->data);
}

}  // namespace secreto
