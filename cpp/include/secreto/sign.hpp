// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

// Hybrid signatures: Ed25519 + ML-DSA-87 (empty context), keys from seeds.
#pragma once

#include <array>

#include "secreto/common.hpp"

namespace secreto::sign {

inline constexpr std::size_t kSecretKeyLen = 64;  // ed25519 seed (32) || ML-DSA-87 seed (32)
inline constexpr std::size_t kEd25519PkLen = 32;
inline constexpr std::size_t kMldsaPkLen = 2592;
inline constexpr std::size_t kPublicKeyLen = kEd25519PkLen + kMldsaPkLen;  // 2624
inline constexpr std::size_t kSignerIdLen = 32;
inline constexpr std::size_t kEd25519SigLen = 64;
inline constexpr std::size_t kMldsaSigLen = 4627;
inline constexpr std::size_t kSigblockLen = kSignerIdLen + kEd25519SigLen + kMldsaSigLen;  // 4723

SecretBytes generate_secret_key();

// pk_bytes = ed25519_pk || mldsa87_pk
Bytes public_key(ByteView secret_key);

// SHA-512("secreto/v1/signer-id" || pk_bytes)[:32]
std::array<std::uint8_t, kSignerIdLen> signer_id(ByteView public_key);

// msg = "secreto/v1/signature" || header_mac || u64be(len) || SHA-512(content)
Bytes signature_message(ByteView header_mac, ByteView content);

// signer_id || ed25519_sig || mldsa87_sig
Bytes sign(ByteView secret_key, ByteView header_mac, ByteView content);

// Verifies a sigblock against `public_key`. Throws Error(kExitSignature).
void verify(ByteView public_key, ByteView sigblock, ByteView header_mac, ByteView content);

}  // namespace secreto::sign
