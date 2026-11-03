// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

#include "secreto/crypto.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/thread.h>

#include <cstring>
#include <memory>

namespace secreto {

namespace {

struct MdCtxDel {
  void operator()(EVP_MD_CTX* c) const { EVP_MD_CTX_free(c); }
};
using MdCtx = std::unique_ptr<EVP_MD_CTX, MdCtxDel>;

struct CipherCtxDel {
  void operator()(EVP_CIPHER_CTX* c) const { EVP_CIPHER_CTX_free(c); }
};
using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDel>;

struct MdDel {
  void operator()(EVP_MD* m) const { EVP_MD_free(m); }
};
using MdPtr = std::unique_ptr<EVP_MD, MdDel>;

struct KdfDel {
  void operator()(EVP_KDF* k) const { EVP_KDF_free(k); }
};
struct KdfCtxDel {
  void operator()(EVP_KDF_CTX* k) const { EVP_KDF_CTX_free(k); }
};

const std::uint8_t kEmpty = 0;
const std::uint8_t* data_or_dummy(ByteView v) { return v.empty() ? &kEmpty : v.data(); }

}  // namespace

void random_fill(std::uint8_t* out, std::size_t n) {
  if (n == 0) return;
  if (RAND_bytes(out, static_cast<int>(n)) != 1) fail(kExitIo, "random number generator failure");
}

Bytes random_bytes(std::size_t n) {
  Bytes b(n);
  random_fill(b.data(), n);
  return b;
}

SecretBytes random_secret(std::size_t n) {
  SecretBytes b(n);
  random_fill(b.data(), n);
  return b;
}

std::array<std::uint8_t, 64> sha512(ByteView data) {
  std::array<std::uint8_t, 64> out{};
  unsigned int len = 0;
  if (EVP_Digest(data_or_dummy(data), data.size(), out.data(), &len, EVP_sha512(), nullptr) != 1)
    fail(kExitIo, "SHA-512 failure");
  return out;
}

std::array<std::uint8_t, 32> sha3_256(ByteView data) {
  std::array<std::uint8_t, 32> out{};
  unsigned int len = 0;
  if (EVP_Digest(data_or_dummy(data), data.size(), out.data(), &len, EVP_sha3_256(), nullptr) != 1)
    fail(kExitIo, "SHA3-256 failure");
  return out;
}

SecretBytes shake256(ByteView data, std::size_t out_len) {
  MdPtr md(EVP_MD_fetch(nullptr, "SHAKE-256", nullptr));
  MdCtx ctx(EVP_MD_CTX_new());
  SecretBytes out(out_len);
  if (!md || !ctx || EVP_DigestInit_ex(ctx.get(), md.get(), nullptr) != 1 ||
      EVP_DigestUpdate(ctx.get(), data_or_dummy(data), data.size()) != 1 ||
      EVP_DigestFinalXOF(ctx.get(), out.data(), out.size()) != 1)
    fail(kExitIo, "SHAKE256 failure");
  return out;
}

std::array<std::uint8_t, 64> hmac_sha512(ByteView key, ByteView data) {
  std::array<std::uint8_t, 64> out{};
  unsigned int len = 0;
  if (HMAC(EVP_sha512(), data_or_dummy(key), static_cast<int>(key.size()), data_or_dummy(data),
           data.size(), out.data(), &len) == nullptr ||
      len != 64)
    fail(kExitIo, "HMAC-SHA-512 failure");
  return out;
}

SecretBytes hkdf_sha512_extract(ByteView salt, ByteView ikm) {
  std::array<std::uint8_t, 64> zero{};
  ByteView key = salt.empty() ? ByteView(zero) : salt;
  auto prk = hmac_sha512(key, ikm);
  SecretBytes out(prk.begin(), prk.end());
  cleanse(prk.data(), prk.size());
  return out;
}

SecretBytes hkdf_sha512_expand(ByteView prk, ByteView info, std::size_t length) {
  if (length > 255 * 64) fail(kExitIo, "HKDF output too long");
  SecretBytes out;
  out.reserve(length + 64);
  SecretBytes t;
  std::uint8_t counter = 1;
  while (out.size() < length) {
    SecretBytes msg;
    append(msg, ByteView(t));
    append(msg, info);
    msg.push_back(counter++);
    auto block = hmac_sha512(prk, msg);
    t.assign(block.begin(), block.end());
    cleanse(block.data(), block.size());
    append(out, ByteView(t));
  }
  out.resize(length);
  return out;
}

SecretBytes hkdf_sha512(ByteView ikm, ByteView salt, ByteView info, std::size_t length) {
  SecretBytes prk = hkdf_sha512_extract(salt, ikm);
  return hkdf_sha512_expand(prk, info, length);
}

Bytes chacha20poly1305_seal(ByteView key, ByteView nonce, ByteView aad, ByteView plaintext) {
  if (key.size() != kAeadKeyLen || nonce.size() != kAeadNonceLen)
    fail(kExitIo, "ChaCha20-Poly1305: bad key/nonce size");
  CipherCtx ctx(EVP_CIPHER_CTX_new());
  Bytes out(plaintext.size() + kAeadTagLen);
  int len = 0;
  if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()),
                          nullptr) != 1 ||
      EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
    fail(kExitIo, "ChaCha20-Poly1305 init failure");
  if (!aad.empty() &&
      EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1)
    fail(kExitIo, "ChaCha20-Poly1305 aad failure");
  int total = 0;
  if (!plaintext.empty()) {
    if (EVP_EncryptUpdate(ctx.get(), out.data(), &len, plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1)
      fail(kExitIo, "ChaCha20-Poly1305 encrypt failure");
    total = len;
  }
  if (EVP_EncryptFinal_ex(ctx.get(), out.data() + total, &len) != 1)
    fail(kExitIo, "ChaCha20-Poly1305 final failure");
  total += len;
  if (static_cast<std::size_t>(total) != plaintext.size() ||
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, static_cast<int>(kAeadTagLen),
                          out.data() + plaintext.size()) != 1)
    fail(kExitIo, "ChaCha20-Poly1305 tag failure");
  return out;
}

std::optional<SecretBytes> chacha20poly1305_open(ByteView key, ByteView nonce, ByteView aad,
                                                 ByteView ct) {
  if (key.size() != kAeadKeyLen || nonce.size() != kAeadNonceLen || ct.size() < kAeadTagLen)
    return std::nullopt;
  std::size_t pt_len = ct.size() - kAeadTagLen;
  CipherCtx ctx(EVP_CIPHER_CTX_new());
  SecretBytes out(pt_len);
  int len = 0;
  if (!ctx || EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()),
                          nullptr) != 1 ||
      EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
    return std::nullopt;
  if (!aad.empty() &&
      EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1)
    return std::nullopt;
  int total = 0;
  if (pt_len > 0) {
    if (EVP_DecryptUpdate(ctx.get(), out.data(), &len, ct.data(), static_cast<int>(pt_len)) != 1)
      return std::nullopt;
    total = len;
  }
  std::uint8_t tag[kAeadTagLen];
  std::memcpy(tag, ct.data() + pt_len, kAeadTagLen);
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, static_cast<int>(kAeadTagLen), tag) !=
      1)
    return std::nullopt;
  if (EVP_DecryptFinal_ex(ctx.get(), out.data() + total, &len) != 1) {
    cleanse(out);
    return std::nullopt;
  }
  return out;
}

SecretBytes argon2id(const Argon2Input& in) {
  std::unique_ptr<EVP_KDF, KdfDel> kdf(EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr));
  if (!kdf) fail(kExitIo, "ARGON2ID is not available in this OpenSSL");

  // Try with one worker thread per lane first, then fall back to a single
  // thread (thread pools may be unavailable in constrained environments).
  const std::uint32_t attempts[2] = {in.p, 1};
  for (int attempt = 0; attempt < 2; ++attempt) {
    std::uint32_t threads = attempts[attempt];
    if (attempt == 1 && attempts[0] == 1) break;
    if (threads > 1) OSSL_set_max_threads(nullptr, threads);

    std::unique_ptr<EVP_KDF_CTX, KdfCtxDel> ctx(EVP_KDF_CTX_new(kdf.get()));
    if (!ctx) fail(kExitIo, "cannot create Argon2 context");
    std::uint32_t iter = in.t, lanes = in.p, mem = in.m_kib;
    OSSL_PARAM params[9];
    int n = 0;
    params[n++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_PASSWORD, const_cast<std::uint8_t*>(data_or_dummy(in.password)),
        in.password.size());
    params[n++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, const_cast<std::uint8_t*>(data_or_dummy(in.salt)), in.salt.size());
    if (!in.secret.empty())
      params[n++] = OSSL_PARAM_construct_octet_string(
          OSSL_KDF_PARAM_SECRET, const_cast<std::uint8_t*>(in.secret.data()), in.secret.size());
    if (!in.ad.empty())
      params[n++] = OSSL_PARAM_construct_octet_string(
          OSSL_KDF_PARAM_ARGON2_AD, const_cast<std::uint8_t*>(in.ad.data()), in.ad.size());
    params[n++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iter);
    params[n++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes);
    params[n++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads);
    params[n++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &mem);
    params[n++] = OSSL_PARAM_construct_end();

    SecretBytes out(in.out_len);
    if (EVP_KDF_derive(ctx.get(), out.data(), out.size(), params) == 1) return out;
  }
  fail(kExitIo, "Argon2id derivation failed");
}

}  // namespace secreto
