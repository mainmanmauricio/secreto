// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

// HPKE (RFC 9180) Base mode with HKDF-SHA512 and ChaCha20-Poly1305, over the
// MLKEM1024-P384 KEM (KEM id 0x0051).
#pragma once

#include <optional>

#include "secreto/common.hpp"

namespace secreto::hpke {

inline constexpr std::uint16_t kKemMlkem1024P384 = 0x0051;
inline constexpr std::uint16_t kKdfHkdfSha512 = 0x0003;
inline constexpr std::uint16_t kAeadChaCha20Poly1305 = 0x0003;
inline constexpr std::size_t kHashLen = 64;  // Nh for HKDF-SHA512
inline constexpr std::string_view kSecretoInfo = "secreto/v1/mlkem1024p384";

struct Suite {
  std::uint16_t kem_id;
  std::uint16_t kdf_id;
  std::uint16_t aead_id;
  std::size_t nk;  // AEAD key length
  std::size_t nn;  // AEAD nonce length
};

inline constexpr Suite kSecretoSuite{kKemMlkem1024P384, kKdfHkdfSha512, kAeadChaCha20Poly1305, 32,
                                     12};

struct KeySchedule {
  Bytes context;
  SecretBytes secret;
  SecretBytes key;
  SecretBytes base_nonce;
  SecretBytes exporter_secret;
};

// RFC 9180 section 5.1 KeyScheduleContext / KeySchedule (HKDF-SHA512 only).
KeySchedule key_schedule(const Suite& suite, std::uint8_t mode, ByteView shared_secret,
                         ByteView info, ByteView psk = {}, ByteView psk_id = {});

// nonce = base_nonce XOR I2OSP(seq, Nn)
Bytes compute_nonce(ByteView base_nonce, std::uint64_t seq);

struct SealResult {
  Bytes enc;         // 1665 bytes
  Bytes ciphertext;  // |pt| + 16
};

// SealBase to encapsulation key `ek`. `randomness` is the optional 80-byte
// deterministic encaps input (tests only).
SealResult seal_base(ByteView ek, ByteView info, ByteView aad, ByteView plaintext,
                     std::optional<ByteView> randomness = std::nullopt);

// OpenBase with the 32-byte KEM seed; nullopt on any failure.
std::optional<SecretBytes> open_base(ByteView enc, ByteView seed, ByteView info, ByteView aad,
                                     ByteView ciphertext);

}  // namespace secreto::hpke
