// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

// STREAM payload encryption (age variant) with ChaCha20-Poly1305.
#pragma once

#include "secreto/common.hpp"

namespace secreto::stream {

inline constexpr std::size_t kChunkSize = 65536;
inline constexpr std::size_t kNonceLen = 16;  // payload nonce prefix

// 12-byte AEAD nonce: big-endian 11-byte counter || flag.
std::array<std::uint8_t, 12> chunk_nonce(std::uint64_t counter, bool final);

// payload_key = HKDF-SHA-512(file_key, salt = nonce, info = "secreto/v1/payload", 32)
SecretBytes derive_payload_key(ByteView file_key, ByteView nonce);

// Encrypt the whole plaintext into STREAM chunks (no nonce prefix).
Bytes encrypt(ByteView payload_key, ByteView plaintext);

// Decrypt a complete STREAM ciphertext. Throws Error(kExitFormat) on any
// authentication / framing failure, including an empty final chunk. No
// plaintext is returned unless every chunk verified.
SecretBytes decrypt(ByteView payload_key, ByteView ciphertext);

}  // namespace secreto::stream
