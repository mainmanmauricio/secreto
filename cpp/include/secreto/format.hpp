// High-level secreto/v1 encryption and decryption.
#pragma once

#include <array>
#include <optional>
#include <vector>

#include "secreto/common.hpp"

namespace secreto {

inline constexpr std::uint32_t kArgonDefaultM = 1048576;
inline constexpr std::uint32_t kArgonDefaultT = 3;
inline constexpr std::uint32_t kArgonDefaultP = 4;
inline constexpr std::size_t kFileKeyLen = 32;

struct ArgonParams {
  std::uint32_t m_kib = kArgonDefaultM;
  std::uint32_t t = kArgonDefaultT;
  std::uint32_t p = kArgonDefaultP;
};

struct EncryptOptions {
  std::vector<Bytes> recipients;           // 1665-byte encapsulation keys
  std::optional<SecretBytes> passphrase;   // mutually exclusive with recipients
  ArgonParams argon;                       // spec mandates the defaults; tests may lower them
  bool pad = false;                        // Padme length padding
  std::optional<SecretBytes> signing_key;  // 64-byte signing secret
  bool armor = false;
};

// Returns the complete file (binary, or armored if requested).
// Throws Error (kExitUsage for bad options, kExitIo for resource failures).
Bytes encrypt(ByteView content, const EncryptOptions& opts);

struct DecryptOptions {
  std::vector<SecretBytes> identities;    // 32-byte KEM seeds
  std::optional<SecretBytes> passphrase;
  std::optional<Bytes> verify_key;        // 2624-byte signer public key
};

struct DecryptResult {
  SecretBytes content;
  bool signed_file = false;
  bool verified = false;
  std::array<std::uint8_t, 32> signer_id{};  // valid when signed_file
};

// Throws Error with exit code 3 (no match), 4 (format/authentication) or 5
// (signature). Content is never returned unless every check succeeded.
DecryptResult decrypt(ByteView file, const DecryptOptions& opts);

// Inner plaintext construction / parsing (exposed for tests).
struct InnerParts {
  ByteView content;
  bool signed_file = false;
  ByteView sigblock;
};
SecretBytes build_inner(ByteView content, bool pad, ByteView sigblock);
InnerParts parse_inner(ByteView stream_plaintext);

}  // namespace secreto
