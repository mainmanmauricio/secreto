// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

// Bech32 (BIP173 charset and checksum) without the 90-character limit.
#pragma once

#include <optional>
#include <string>
#include <string_view>

#include "secreto/common.hpp"

namespace secreto {

inline constexpr std::size_t kBech32MaxLen = 8192;

struct Bech32Decoded {
  std::string hrp;  // exactly as it appeared in the input (case preserved)
  Bytes data;
};

// Encode. An HRP containing upper-case letters yields an all-upper-case string;
// the checksum always covers the lower-cased HRP. Throws Error on a bad HRP or
// an over-long result.
std::string bech32_encode(std::string_view hrp, ByteView data);

// Decode; nullopt for any malformed input (mixed case, bad checksum, bad
// padding, over-long, ...).
std::optional<Bech32Decoded> bech32_decode(std::string_view s);

// Decode and require a specific HRP (exact case) and payload length.
std::optional<Bytes> bech32_decode_exact(std::string_view s, std::string_view hrp,
                                         std::size_t data_len);

}  // namespace secreto
