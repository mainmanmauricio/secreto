// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

// MLKEM1024-P384 hybrid KEM (CG framework, SHA3-256 combiner, SHAKE256 PRG).
#pragma once

#include <optional>

#include "secreto/common.hpp"

namespace secreto::kem {

inline constexpr std::size_t kSeedLen = 32;
inline constexpr std::size_t kMlkemEkLen = 1568;
inline constexpr std::size_t kMlkemCtLen = 1568;
inline constexpr std::size_t kP384PointLen = 97;
inline constexpr std::size_t kP384ScalarLen = 48;
inline constexpr std::size_t kEkLen = kMlkemEkLen + kP384PointLen;  // 1665
inline constexpr std::size_t kCtLen = kMlkemCtLen + kP384PointLen;  // 1665
inline constexpr std::size_t kSsLen = 32;
inline constexpr std::size_t kEncapsRandomnessLen = 32 + 48;  // ML-KEM m || P-384 seed

// Expanded decapsulation key (DeriveKeyPair).
struct ExpandedKey {
  SecretBytes pq_seed;   // 64 bytes: d || z for ML-KEM-1024
  SecretBytes t_scalar;  // 48-byte P-384 private scalar
  Bytes ek;              // 1665-byte encapsulation key
};

// RandomScalar_P384: rejection sampling over 48-byte blocks; extra blocks are
// SHAKE256(seed || counter)[:48] with counter = 1, 2, ... (single byte).
SecretBytes random_scalar_p384(ByteView seed48);

SecretBytes generate_seed();
ExpandedKey derive_key_pair(ByteView seed);
// Encapsulation key for a seed.
Bytes encapsulation_key(ByteView seed);
// Validates length, ML-KEM key, and the P-384 point (on curve, non-identity).
// Throws Error(kExitUsage) on failure.
void validate_ek(ByteView ek);
bool ek_is_valid(ByteView ek);

struct Encapsulation {
  SecretBytes shared_secret;  // 32 bytes
  Bytes ciphertext;           // 1665 bytes
};

// Encaps. `randomness` (80 bytes: 32 ML-KEM || 48 P-384 seed) makes the
// operation deterministic; otherwise fresh randomness is drawn.
Encapsulation encaps(ByteView ek, std::optional<ByteView> randomness = std::nullopt);

// Decaps; nullopt if the ciphertext is malformed (bad length / invalid point).
std::optional<SecretBytes> decaps(ByteView seed, ByteView ct);

}  // namespace secreto::kem
