// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

#include "secreto/header.hpp"

#include <algorithm>

#include "secreto/base64.hpp"
#include "secreto/crypto.hpp"

namespace secreto::header {

namespace {

[[noreturn]] void bad(const char* msg) { fail(kExitFormat, std::string("header: ") + msg); }

bool is_vchar(char c) { return c >= 0x21 && c <= 0x7e; }

}  // namespace

Parsed parse(ByteView data) {
  std::string_view s(reinterpret_cast<const char*>(data.data()), data.size());
  if (s.size() < kVersionLine.size() || s.substr(0, kVersionLine.size()) != kVersionLine)
    bad("unsupported or missing version line");

  Parsed out;
  std::size_t pos = kVersionLine.size();

  // Next line (without LF); advances pos past the LF.
  auto next_line = [&](std::string_view& line) {
    std::size_t nl = s.find('\n', pos);
    if (nl == std::string_view::npos) bad("truncated header");
    if (nl - pos > kMaxLineLen) bad("header line too long");
    line = s.substr(pos, nl - pos);
    pos = nl + 1;
    if (pos > kMaxHeaderSize) bad("header too large");
  };

  while (true) {
    std::string_view line;
    std::size_t line_start = pos;
    next_line(line);

    if (line.substr(0, 3) == "---") {
      if (out.stanzas.empty()) bad("no recipient stanzas");
      if (line.size() != 3 + 1 + 86 || line[3] != ' ') bad("malformed MAC line");
      auto mac = b64_decode(line.substr(4));
      if (!mac || mac->size() != kMacLen) bad("malformed MAC value");
      std::copy(mac->begin(), mac->end(), out.mac.begin());
      out.mac_input.assign(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(line_start) + 3);
      out.total_len = pos;
      return out;
    }

    if (line.substr(0, 3) != "-> ") bad("expected stanza or MAC line");
    if (out.stanzas.size() >= kMaxStanzas) bad("too many stanzas");

    Stanza st;
    std::string_view rest = line.substr(3);
    while (true) {
      std::size_t sp = rest.find(' ');
      std::string_view arg = rest.substr(0, sp);
      if (arg.empty()) bad("empty stanza argument");
      for (char c : arg)
        if (!is_vchar(c)) bad("invalid character in stanza argument");
      st.args.emplace_back(arg);
      if (sp == std::string_view::npos) break;
      rest.remove_prefix(sp + 1);
    }

    // Body: full 64-column lines, ended by a shorter (possibly empty) line.
    std::string b64;
    while (true) {
      std::string_view body_line;
      next_line(body_line);
      if (body_line.size() > 64) bad("stanza body line too long");
      b64.append(body_line);
      if (body_line.size() < 64) break;
    }
    auto body = b64_decode(b64);
    if (!body) bad("invalid stanza body encoding");
    st.body = std::move(*body);
    out.stanzas.push_back(std::move(st));
  }
}

std::string serialize_stanza(const Stanza& s) {
  std::string out = "->";
  for (const std::string& a : s.args) {
    out.push_back(' ');
    out += a;
  }
  out.push_back('\n');
  std::string b64 = b64_encode(s.body);
  for (std::size_t i = 0; i + 64 <= b64.size(); i += 64) {
    out.append(b64, i, 64);
    out.push_back('\n');
  }
  out.append(b64, b64.size() / 64 * 64, std::string::npos);
  out.push_back('\n');
  return out;
}

Bytes mac_input(const std::vector<Stanza>& stanzas) {
  Bytes out;
  append(out, kVersionLine);
  for (const Stanza& s : stanzas) append(out, std::string_view(serialize_stanza(s)));
  append(out, std::string_view("---"));
  return out;
}

SecretBytes derive_mac_key(ByteView file_key) {
  return hkdf_sha512(file_key, {}, as_bytes("secreto/v1/header"), 64);
}

std::array<std::uint8_t, kMacLen> compute_mac(ByteView file_key, ByteView input) {
  SecretBytes key = derive_mac_key(file_key);
  return hmac_sha512(key, input);
}

Bytes finish(ByteView input, const std::array<std::uint8_t, kMacLen>& mac) {
  Bytes out(input.begin(), input.end());
  append(out, std::string_view(" "));
  append(out, std::string_view(b64_encode(mac)));
  append(out, std::string_view("\n"));
  return out;
}

}  // namespace secreto::header
