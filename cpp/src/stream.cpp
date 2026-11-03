#include "secreto/stream.hpp"

#include <algorithm>

#include "secreto/crypto.hpp"

namespace secreto::stream {

std::array<std::uint8_t, 12> chunk_nonce(std::uint64_t counter, bool final) {
  std::array<std::uint8_t, 12> n{};
  // 11-byte big-endian counter: the upper 3 bytes are always zero for u64.
  for (int i = 0; i < 8; ++i) n[10 - i] = static_cast<std::uint8_t>((counter >> (8 * i)) & 0xff);
  n[11] = final ? 1 : 0;
  return n;
}

SecretBytes derive_payload_key(ByteView file_key, ByteView nonce) {
  return hkdf_sha512(file_key, nonce, as_bytes("secreto/v1/payload"), 32);
}

Bytes encrypt(ByteView key, ByteView plaintext) {
  Bytes out;
  out.reserve(plaintext.size() + (plaintext.size() / kChunkSize + 1) * kAeadTagLen);
  std::size_t chunks = plaintext.empty() ? 1 : (plaintext.size() + kChunkSize - 1) / kChunkSize;
  for (std::size_t i = 0; i < chunks; ++i) {
    std::size_t off = i * kChunkSize;
    std::size_t n = std::min(kChunkSize, plaintext.size() - off);
    auto nonce = chunk_nonce(i, i + 1 == chunks);
    Bytes ct = chacha20poly1305_seal(key, nonce, {}, plaintext.subspan(off, n));
    append(out, ct);
  }
  return out;
}

SecretBytes decrypt(ByteView key, ByteView ct) {
  constexpr std::size_t kFull = kChunkSize + kAeadTagLen;
  if (ct.size() < kAeadTagLen) fail(kExitFormat, "payload truncated");
  std::size_t chunks = (ct.size() + kFull - 1) / kFull;
  SecretBytes out;
  out.reserve(ct.size());
  for (std::size_t i = 0; i < chunks; ++i) {
    std::size_t off = i * kFull;
    std::size_t n = std::min(kFull, ct.size() - off);
    bool final = (i + 1 == chunks);
    auto nonce = chunk_nonce(i, final);
    auto pt = chacha20poly1305_open(key, nonce, {}, ct.subspan(off, n));
    if (!pt) {
      cleanse(out);
      fail(kExitFormat, "payload authentication failed");
    }
    if (final && pt->empty()) {
      cleanse(out);
      fail(kExitFormat, "empty final payload chunk");
    }
    append(out, ByteView(*pt));
  }
  return out;
}

}  // namespace secreto::stream
