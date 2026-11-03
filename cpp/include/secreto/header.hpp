// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

// secreto/v1 header: version line, recipient stanzas, MAC line.
#pragma once

#include <string>
#include <vector>

#include "secreto/common.hpp"

namespace secreto::header {

inline constexpr std::string_view kVersionLine = "secreto/v1\n";
inline constexpr std::size_t kMaxHeaderSize = 1 << 20;
inline constexpr std::size_t kMaxStanzas = 256;
inline constexpr std::size_t kMaxLineLen = 4096;
inline constexpr std::size_t kMacLen = 64;

struct Stanza {
  std::vector<std::string> args;  // args[0] is the stanza type
  Bytes body;                     // decoded body
};

struct Parsed {
  std::vector<Stanza> stanzas;
  std::array<std::uint8_t, kMacLen> mac{};
  Bytes mac_input;           // header bytes up to and including "---"
  std::size_t total_len = 0;  // header length including the final LF
};

// Parses the header at the start of `data`. Throws Error(kExitFormat).
Parsed parse(ByteView data);

// Serialises one stanza (arg line, 64-column body, short/empty final line).
std::string serialize_stanza(const Stanza& s);

// "secreto/v1\n" + stanzas + "---" : the bytes covered by the MAC.
Bytes mac_input(const std::vector<Stanza>& stanzas);

// mac_key = HKDF-SHA-512(file_key, "", "secreto/v1/header", 64)
SecretBytes derive_mac_key(ByteView file_key);

std::array<std::uint8_t, kMacLen> compute_mac(ByteView file_key, ByteView mac_input);

// Full header text: mac_input + " " + base64(mac) + "\n".
Bytes finish(ByteView mac_input, const std::array<std::uint8_t, kMacLen>& mac);

}  // namespace secreto::header
