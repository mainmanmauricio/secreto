// Bech32 key objects and key-file parsing.
#pragma once

#include <string>
#include <vector>

#include "secreto/common.hpp"

namespace secreto::keys {

inline constexpr std::string_view kHrpRecipient = "secreto";
inline constexpr std::string_view kHrpIdentity = "SECRETO-SECRET-KEY-";
inline constexpr std::string_view kHrpSigningKey = "SECRETO-SIGNING-KEY-";
inline constexpr std::string_view kHrpSignerPublic = "secretosig";

// Each parser throws Error(kExitUsage) on invalid input.
std::string identity_to_bech32(ByteView seed);
SecretBytes identity_from_bech32(std::string_view s);

std::string recipient_to_bech32(ByteView ek);
Bytes recipient_from_bech32(std::string_view s);

std::string signing_key_to_bech32(ByteView sk);
SecretBytes signing_key_from_bech32(std::string_view s);

std::string signer_public_to_bech32(ByteView pk);
Bytes signer_public_from_bech32(std::string_view s);

// Non-empty, non-'#' lines (whitespace-trimmed) of a key file.
std::vector<std::string> key_lines(std::string_view text);

std::vector<SecretBytes> parse_identities(std::string_view text);
std::vector<Bytes> parse_recipients(std::string_view text);
SecretBytes parse_signing_key(std::string_view text);

}  // namespace secreto::keys
