// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

// Strict (canonical) standard-alphabet Base64, RFC 4648 section 4.
#pragma once

#include <optional>
#include <string>
#include <string_view>

#include "secreto/common.hpp"

namespace secreto {

// Unpadded encoding (header form).
std::string b64_encode(ByteView data);
// Padded encoding (armor form).
std::string b64_encode_padded(ByteView data);

// Canonical decoders: reject non-alphabet characters, wrong lengths, non-zero
// trailing bits, and (for the unpadded form) any '='.
std::optional<Bytes> b64_decode(std::string_view s);
std::optional<Bytes> b64_decode_padded(std::string_view s);

}  // namespace secreto
