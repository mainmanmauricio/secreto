// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

// Thin wrappers over OpenSSL 3.5 primitives used by secreto.
#pragma once

#include <array>
#include <optional>

#include "secreto/common.hpp"

namespace secreto {

// CSPRNG.
void random_fill(std::uint8_t* out, std::size_t n);
Bytes random_bytes(std::size_t n);
SecretBytes random_secret(std::size_t n);

std::array<std::uint8_t, 64> sha512(ByteView data);
std::array<std::uint8_t, 32> sha3_256(ByteView data);
// SHAKE256 XOF, `out_len` bytes.
SecretBytes shake256(ByteView data, std::size_t out_len);

std::array<std::uint8_t, 64> hmac_sha512(ByteView key, ByteView data);

// HKDF-SHA-512 (RFC 5869).
SecretBytes hkdf_sha512_extract(ByteView salt, ByteView ikm);
SecretBytes hkdf_sha512_expand(ByteView prk, ByteView info, std::size_t length);
SecretBytes hkdf_sha512(ByteView ikm, ByteView salt, ByteView info, std::size_t length);

// ChaCha20-Poly1305 (RFC 8439). Key 32 bytes, nonce 12 bytes, tag 16 bytes.
inline constexpr std::size_t kAeadKeyLen = 32;
inline constexpr std::size_t kAeadNonceLen = 12;
inline constexpr std::size_t kAeadTagLen = 16;
// Returns ciphertext || tag.
Bytes chacha20poly1305_seal(ByteView key, ByteView nonce, ByteView aad, ByteView plaintext);
// nullopt on authentication failure.
std::optional<SecretBytes> chacha20poly1305_open(ByteView key, ByteView nonce, ByteView aad,
                                                 ByteView ciphertext_and_tag);

struct Argon2Input {
  ByteView password;
  ByteView salt;
  ByteView secret;  // optional (empty)
  ByteView ad;      // optional (empty)
  std::uint32_t m_kib = 0;
  std::uint32_t t = 0;
  std::uint32_t p = 0;  // lanes
  std::size_t out_len = 32;
};
// Argon2id via EVP_KDF. Throws Error(kExitIo) if the KDF cannot run
// (e.g. memory exhaustion).
SecretBytes argon2id(const Argon2Input& in);

}  // namespace secreto
