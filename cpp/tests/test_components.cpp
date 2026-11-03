// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

// Component vectors: vectors/components/*.json
#include <openssl/evp.h>

#include <string>

#include "secreto/bech32.hpp"
#include "secreto/crypto.hpp"
#include "secreto/hpke.hpp"
#include "secreto/kem.hpp"
#include "secreto/padme.hpp"
#include "secreto/stream.hpp"
#include "testutil.hpp"

using namespace secreto;
using namespace testutil;

static const std::string kDir = std::string(SECRETO_VECTORS_DIR) + "/components/";

static void test_argon2id() {
  Json j = load_json(kDir + "argon2id.json");
  for (const Json& v : j.at("vectors").arr) {
    Bytes pw = unhex(v.at("password").str), salt = unhex(v.at("salt").str);
    Bytes secret = unhex(v.at("secret").str), ad = unhex(v.at("ad").str);
    Argon2Input in;
    in.password = pw;
    in.salt = salt;
    in.secret = secret;
    in.ad = ad;
    in.m_kib = static_cast<std::uint32_t>(v.at("m_kib").num);
    in.t = static_cast<std::uint32_t>(v.at("t").num);
    in.p = static_cast<std::uint32_t>(v.at("p").num);
    in.out_len = static_cast<std::size_t>(v.at("tag_length").num);
    SecretBytes tag = argon2id(in);
    CHECK(hex_encode(tag) == v.at("tag").str);
  }
}

static void test_bech32() {
  Json j = load_json(kDir + "bech32.json");
  for (const Json& v : j.at("vectors").arr) {
    Bytes data = unhex(v.at("data_hex").str);
    std::string enc = bech32_encode(v.at("hrp").str, data);
    CHECK(enc == v.at("encoded").str);
    auto dec = bech32_decode(v.at("encoded").str);
    CHECK(dec.has_value());
    if (dec) {
      CHECK(dec->hrp == v.at("hrp").str);
      CHECK(dec->data == data);
    }
  }
  for (const Json& v : j.at("invalid").arr) {
    CHECK_MSG(!bech32_decode(v.at("encoded").str).has_value(), v.at("reason").str);
  }
  // Extra negative cases.
  CHECK(!bech32_decode("").has_value());
  CHECK(!bech32_decode("secreto1").has_value());
  CHECK(!bech32_decode("1qq6704ds").has_value());                      // empty HRP
  CHECK(!bech32_decode(std::string(8193, 'a')).has_value());           // over length limit
  CHECK(!bech32_decode("secreto1qq6704dsx").has_value());              // trailing garbage
  // Large payload round-trips (no 90-char limit).
  Bytes big(2624);
  for (std::size_t i = 0; i < big.size(); ++i) big[i] = static_cast<std::uint8_t>(i * 7 + 1);
  auto rt = bech32_decode(bech32_encode("secretosig", big));
  CHECK(rt && rt->data == big);
}

static void test_hpke_key_schedule() {
  Json j = load_json(kDir + "hpke_key_schedule_sha512.json");
  const Json& suite = j.at("suite");
  hpke::Suite s{static_cast<std::uint16_t>(suite.at("kem_id").num),
                static_cast<std::uint16_t>(suite.at("kdf_id").num),
                static_cast<std::uint16_t>(suite.at("aead_id").num), 32, 12};
  Bytes info = unhex(j.at("info").str);
  Bytes ss = unhex(j.at("shared_secret").str);
  hpke::KeySchedule ks =
      hpke::key_schedule(s, static_cast<std::uint8_t>(suite.at("mode").num), ss, info);
  CHECK(hex_encode(ks.context) == j.at("key_schedule_context").str);
  CHECK(hex_encode(ks.secret) == j.at("secret").str);
  CHECK(hex_encode(ks.key) == j.at("key").str);
  CHECK(hex_encode(ks.base_nonce) == j.at("base_nonce").str);
  CHECK(hex_encode(ks.exporter_secret) == j.at("exporter_secret").str);

  // The vector suite uses AES-256-GCM; check nonce derivation and sealing.
  for (const Json& e : j.at("encryptions").arr) {
    Bytes nonce = hpke::compute_nonce(ks.base_nonce, static_cast<std::uint64_t>(e.at("sequence_number").num));
    CHECK(hex_encode(nonce) == e.at("nonce").str);
    Bytes pt = unhex(e.at("pt").str), aad = unhex(e.at("aad").str);
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(),
                                                                       &EVP_CIPHER_CTX_free);
    Bytes ct(pt.size() + 16);
    int len = 0;
    bool ok = EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, ks.key.data(), nonce.data()) == 1 &&
              EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) == 1 &&
              EVP_EncryptUpdate(ctx.get(), ct.data(), &len, pt.data(), static_cast<int>(pt.size())) == 1 &&
              EVP_EncryptFinal_ex(ctx.get(), ct.data() + len, &len) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, 16, ct.data() + pt.size()) == 1;
    CHECK(ok);
    CHECK(hex_encode(ct) == e.at("ct").str);
  }
}

static void test_mlkem1024p384() {
  Json j = load_json(kDir + "mlkem1024p384.json");
  for (const Json& v : j.at("vectors").arr) {
    Bytes seed = unhex(v.at("seed").str);
    Bytes rnd = unhex(v.at("randomness").str);
    Bytes ek = unhex(v.at("encapsulation_key").str);
    Bytes ct = unhex(v.at("ciphertext").str);
    Bytes ss = unhex(v.at("shared_secret").str);
    CHECK(v.at("decapsulation_key").str == hex_encode(seed));

    kem::ExpandedKey dk = kem::derive_key_pair(seed);
    CHECK(hex_encode(dk.pq_seed) == v.at("decapsulation_key_pq").str);
    CHECK(hex_encode(dk.t_scalar) == v.at("decapsulation_key_t").str);
    CHECK(dk.ek == ek);
    CHECK(kem::ek_is_valid(ek));

    kem::Encapsulation e = kem::encaps(ek, ByteView(rnd));
    CHECK(e.ciphertext == ct);
    CHECK(hex_encode(e.shared_secret) == hex_encode(ss));

    auto d = kem::decaps(seed, ct);
    CHECK(d.has_value());
    if (d) CHECK(hex_encode(*d) == hex_encode(ss));

    // Tampered P-384 ciphertext point -> rejected; tampered ML-KEM part ->
    // implicit rejection gives a different secret.
    Bytes bad = ct;
    bad[ct.size() - 1] ^= 1;
    CHECK(!kem::decaps(seed, bad).has_value());
    Bytes bad2 = ct;
    bad2[10] ^= 1;
    auto d2 = kem::decaps(seed, bad2);
    CHECK(d2.has_value() && hex_encode(*d2) != hex_encode(ss));
    CHECK(!kem::decaps(seed, ByteView(ct).first(ct.size() - 1)).has_value());
  }
  // Invalid encapsulation keys.
  Json first = j.at("vectors").arr[0];
  Bytes ek = unhex(first.at("encapsulation_key").str);
  CHECK(!kem::ek_is_valid(ByteView(ek).first(ek.size() - 1)));
  Bytes bad = ek;
  bad[kem::kMlkemEkLen] = 0x02;  // not uncompressed
  CHECK(!kem::ek_is_valid(bad));
  bad = ek;
  bad[ek.size() - 1] ^= 1;  // off curve
  CHECK(!kem::ek_is_valid(bad));
}

static void test_random_scalar() {
  // 48 zero bytes -> invalid (zero) -> extension blocks are used.
  Bytes zero(48, 0);
  SecretBytes s = kem::random_scalar_p384(zero);
  Bytes in = zero;
  in.push_back(1);
  SecretBytes want = shake256(in, 48);
  CHECK(s == want);
  // All 0xff >= n -> rejected as well.
  Bytes ff(48, 0xff);
  SecretBytes s2 = kem::random_scalar_p384(ff);
  Bytes in2 = ff;
  in2.push_back(1);
  CHECK(s2 == shake256(in2, 48));
  // An honest seed is returned unchanged.
  Bytes ok(48, 0x11);
  CHECK(kem::random_scalar_p384(ok) == SecretBytes(ok.begin(), ok.end()));
}

static void test_padme() {
  Json j = load_json(kDir + "padme.json");
  for (const Json& v : j.at("vectors").arr)
    CHECK_MSG(padme(static_cast<std::uint64_t>(v.at("L").num)) ==
                  static_cast<std::uint64_t>(v.at("padded").num),
              "L=" + std::to_string(v.at("L").num));
  CHECK(padme(0) == 0);
}

static void test_stream_nonces() {
  Json j = load_json(kDir + "stream.json");
  CHECK(static_cast<std::size_t>(j.at("chunk_size").num) == stream::kChunkSize);
  for (const Json& v : j.at("nonce_examples").arr) {
    auto n = stream::chunk_nonce(static_cast<std::uint64_t>(v.at("counter").num), v.at("final").b);
    CHECK(hex_encode(n) == v.at("nonce_hex").str);
  }
  // Round trip across chunk boundaries and the "empty final chunk" rule.
  Bytes key(32, 7);
  for (std::size_t len : {1u, 65535u, 65536u, 65537u, 131072u, 200000u}) {
    Bytes pt(len);
    for (std::size_t i = 0; i < len; ++i) pt[i] = static_cast<std::uint8_t>(i * 31);
    Bytes ct = stream::encrypt(key, pt);
    SecretBytes back = stream::decrypt(key, ct);
    CHECK(back.size() == pt.size() && std::equal(back.begin(), back.end(), pt.begin()));
    // Truncation by a whole chunk or by one byte must fail.
    CHECK_THROWS_CODE(stream::decrypt(key, ByteView(ct).first(ct.size() - 1)), kExitFormat);
    // Trailing byte must fail.
    Bytes extra = ct;
    extra.push_back(0);
    CHECK_THROWS_CODE(stream::decrypt(key, extra), kExitFormat);
  }
  CHECK_THROWS_CODE(stream::decrypt(key, Bytes{}), kExitFormat);
  // An empty final chunk (valid tag, zero plaintext) is rejected.
  Bytes empty_ct = stream::encrypt(key, Bytes{});
  CHECK(empty_ct.size() == 16);
  CHECK_THROWS_CODE(stream::decrypt(key, empty_ct), kExitFormat);
}

int main() {
  try {
    test_argon2id();
    test_bech32();
    test_hpke_key_schedule();
    test_mlkem1024p384();
    test_random_scalar();
    test_padme();
    test_stream_nonces();
  } catch (const std::exception& e) {
    std::fprintf(stderr, "exception: %s\n", e.what());
    return 1;
  }
  return finish("test_components");
}
