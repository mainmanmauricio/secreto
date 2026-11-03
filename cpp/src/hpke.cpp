#include "secreto/hpke.hpp"

#include "secreto/crypto.hpp"
#include "secreto/kem.hpp"

namespace secreto::hpke {

namespace {

void put_u16(Bytes& b, std::uint16_t v) {
  b.push_back(static_cast<std::uint8_t>(v >> 8));
  b.push_back(static_cast<std::uint8_t>(v & 0xff));
}

Bytes suite_id(const Suite& s) {
  Bytes id;
  append(id, std::string_view("HPKE"));
  put_u16(id, s.kem_id);
  put_u16(id, s.kdf_id);
  put_u16(id, s.aead_id);
  return id;
}

SecretBytes labeled_extract(ByteView sid, ByteView salt, std::string_view label, ByteView ikm) {
  SecretBytes labeled;
  append(labeled, std::string_view("HPKE-v1"));
  append(labeled, sid);
  append(labeled, label);
  append(labeled, ikm);
  return hkdf_sha512_extract(salt, labeled);
}

SecretBytes labeled_expand(ByteView sid, ByteView prk, std::string_view label, ByteView info,
                           std::size_t length) {
  Bytes labeled_info;
  put_u16(labeled_info, static_cast<std::uint16_t>(length));
  append(labeled_info, std::string_view("HPKE-v1"));
  append(labeled_info, sid);
  append(labeled_info, label);
  append(labeled_info, info);
  return hkdf_sha512_expand(prk, labeled_info, length);
}

}  // namespace

KeySchedule key_schedule(const Suite& suite, std::uint8_t mode, ByteView shared_secret,
                         ByteView info, ByteView psk, ByteView psk_id) {
  Bytes sid = suite_id(suite);
  SecretBytes psk_id_hash = labeled_extract(sid, {}, "psk_id_hash", psk_id);
  SecretBytes info_hash = labeled_extract(sid, {}, "info_hash", info);

  KeySchedule ks;
  ks.context.push_back(mode);
  append(ks.context, ByteView(psk_id_hash));
  append(ks.context, ByteView(info_hash));

  SecretBytes secret = labeled_extract(sid, shared_secret, "secret", psk);
  ks.key = labeled_expand(sid, secret, "key", ks.context, suite.nk);
  ks.base_nonce = labeled_expand(sid, secret, "base_nonce", ks.context, suite.nn);
  ks.exporter_secret = labeled_expand(sid, secret, "exp", ks.context, kHashLen);
  ks.secret = std::move(secret);
  return ks;
}

Bytes compute_nonce(ByteView base_nonce, std::uint64_t seq) {
  Bytes nonce(base_nonce.begin(), base_nonce.end());
  for (std::size_t i = 0; i < 8 && i < nonce.size(); ++i)
    nonce[nonce.size() - 1 - i] ^= static_cast<std::uint8_t>((seq >> (8 * i)) & 0xff);
  return nonce;
}

SealResult seal_base(ByteView ek, ByteView info, ByteView aad, ByteView plaintext,
                     std::optional<ByteView> randomness) {
  kem::Encapsulation e = kem::encaps(ek, randomness);
  KeySchedule ks = key_schedule(kSecretoSuite, 0, e.shared_secret, info);
  Bytes nonce = compute_nonce(ks.base_nonce, 0);
  SealResult r;
  r.enc = std::move(e.ciphertext);
  r.ciphertext = chacha20poly1305_seal(ks.key, nonce, aad, plaintext);
  return r;
}

std::optional<SecretBytes> open_base(ByteView enc, ByteView seed, ByteView info, ByteView aad,
                                     ByteView ciphertext) {
  auto ss = kem::decaps(seed, enc);
  if (!ss) return std::nullopt;
  KeySchedule ks = key_schedule(kSecretoSuite, 0, *ss, info);
  Bytes nonce = compute_nonce(ks.base_nonce, 0);
  return chacha20poly1305_open(ks.key, nonce, aad, ciphertext);
}

}  // namespace secreto::hpke
