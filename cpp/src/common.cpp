// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

#include "secreto/common.hpp"

namespace secreto {

void secure_free(void* p, std::size_t n) noexcept {
  if (p == nullptr) return;
  OPENSSL_cleanse(p, n);
  ::operator delete(p);
}

bool ct_equal(ByteView a, ByteView b) {
  if (a.size() != b.size()) return false;
  if (a.empty()) return true;
  return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

std::string hex_encode(ByteView b) {
  static const char* digits = "0123456789abcdef";
  std::string s;
  s.reserve(b.size() * 2);
  for (std::uint8_t c : b) {
    s.push_back(digits[c >> 4]);
    s.push_back(digits[c & 15]);
  }
  return s;
}

static int hex_val(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool hex_decode(std::string_view s, Bytes& out) {
  out.clear();
  if (s.size() % 2 != 0) return false;
  out.reserve(s.size() / 2);
  for (std::size_t i = 0; i < s.size(); i += 2) {
    int hi = hex_val(s[i]);
    int lo = hex_val(s[i + 1]);
    if (hi < 0 || lo < 0) return false;
    out.push_back(static_cast<std::uint8_t>(hi * 16 + lo));
  }
  return true;
}

}  // namespace secreto
