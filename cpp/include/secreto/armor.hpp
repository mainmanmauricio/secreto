// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

// Strict PEM armor (RFC 7468 section 3), label "SECRETO ENCRYPTED FILE".
#pragma once

#include <string>

#include "secreto/common.hpp"

namespace secreto::armor {

inline constexpr std::string_view kBegin = "-----BEGIN SECRETO ENCRYPTED FILE-----";
inline constexpr std::string_view kEnd = "-----END SECRETO ENCRYPTED FILE-----";

// True if, after optional leading whitespace, the data starts with "-----BEGIN".
bool looks_armored(ByteView data);

// LF-terminated, 64-column, padded Base64.
std::string encode(ByteView data);

// Strict decode. Throws Error(kExitFormat) on any deviation (surrounding
// whitespace and CRLF line endings are tolerated).
Bytes decode(ByteView data);

}  // namespace secreto::armor
