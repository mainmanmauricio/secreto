// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

#include "secreto/kem.hpp"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>

#include <cstring>
#include <memory>

#include "secreto/crypto.hpp"

namespace secreto::kem {

namespace {

struct PkeyDel {
  void operator()(EVP_PKEY* k) const { EVP_PKEY_free(k); }
};
using Pkey = std::unique_ptr<EVP_PKEY, PkeyDel>;
struct PctxDel {
  void operator()(EVP_PKEY_CTX* c) const { EVP_PKEY_CTX_free(c); }
};
using Pctx = std::unique_ptr<EVP_PKEY_CTX, PctxDel>;
struct BldDel {
  void operator()(OSSL_PARAM_BLD* b) const { OSSL_PARAM_BLD_free(b); }
};
using Bld = std::unique_ptr<OSSL_PARAM_BLD, BldDel>;
struct ParamDel {
  void operator()(OSSL_PARAM* p) const { OSSL_PARAM_free(p); }
};
using Params = std::unique_ptr<OSSL_PARAM, ParamDel>;
struct BnDel {
  void operator()(BIGNUM* b) const { BN_clear_free(b); }
};
using Bn = std::unique_ptr<BIGNUM, BnDel>;
struct GroupDel {
  void operator()(EC_GROUP* g) const { EC_GROUP_free(g); }
};
struct PointDel {
  void operator()(EC_POINT* p) const { EC_POINT_free(p); }
};
struct BnCtxDel {
  void operator()(BN_CTX* c) const { BN_CTX_free(c); }
};

// NIST P-384 group order n (big-endian).
constexpr std::uint8_t kOrder[48] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2,
    0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73};

constexpr char kLabel[] = "MLKEM1024-P384";

bool scalar_valid(ByteView s) {
  if (s.size() != kP384ScalarLen) return false;
  bool zero = true;
  for (std::uint8_t b : s) zero = zero && (b == 0);
  if (zero) return false;
  return std::memcmp(s.data(), kOrder, kP384ScalarLen) < 0;
}

// --- P-384 -----------------------------------------------------------------

// scalar * G as an uncompressed SEC1 point.
Bytes p384_base_mul(ByteView scalar) {
  std::unique_ptr<EC_GROUP, GroupDel> group(EC_GROUP_new_by_curve_name(NID_secp384r1));
  std::unique_ptr<BN_CTX, BnCtxDel> bnctx(BN_CTX_new());
  std::unique_ptr<EC_POINT, PointDel> pt(group ? EC_POINT_new(group.get()) : nullptr);
  Bn k(BN_bin2bn(scalar.data(), static_cast<int>(scalar.size()), nullptr));
  Bytes out(kP384PointLen);
  if (!group || !bnctx || !pt || !k ||
      EC_POINT_mul(group.get(), pt.get(), k.get(), nullptr, nullptr, bnctx.get()) != 1 ||
      EC_POINT_point2oct(group.get(), pt.get(), POINT_CONVERSION_UNCOMPRESSED, out.data(),
                         out.size(), bnctx.get()) != kP384PointLen)
    fail(kExitIo, "P-384 scalar multiplication failed");
  return out;
}

Pkey p384_key(const SecretBytes* scalar, ByteView pub) {
  Bld bld(OSSL_PARAM_BLD_new());
  Bn bn;
  if (!bld || OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, "P-384", 0) != 1 ||
      OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, pub.data(),
                                       pub.size()) != 1)
    return nullptr;
  if (scalar != nullptr) {
    bn.reset(BN_bin2bn(scalar->data(), static_cast<int>(scalar->size()), nullptr));
    if (!bn || OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_PRIV_KEY, bn.get()) != 1)
      return nullptr;
  }
  Params params(OSSL_PARAM_BLD_to_param(bld.get()));
  Pctx ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
  if (!params || !ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1) return nullptr;
  EVP_PKEY* raw = nullptr;
  if (EVP_PKEY_fromdata(ctx.get(), &raw, scalar ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY,
                        params.get()) != 1)
    return nullptr;
  return Pkey(raw);
}

// Validate an uncompressed P-384 point (on curve, not identity).
bool p384_point_valid(ByteView pub) {
  if (pub.size() != kP384PointLen || pub[0] != 0x04) return false;
  Pkey key = p384_key(nullptr, pub);
  if (!key) return false;
  Pctx ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr));
  return ctx && EVP_PKEY_public_check(ctx.get()) == 1;
}

// X coordinate of scalar * peer via EVP ECDH. nullopt for an invalid peer.
std::optional<SecretBytes> p384_ecdh(const SecretBytes& scalar, ByteView self_pub, ByteView peer) {
  if (!p384_point_valid(peer)) return std::nullopt;
  Pkey self = p384_key(&scalar, self_pub);
  Pkey other = p384_key(nullptr, peer);
  if (!self || !other) return std::nullopt;
  Pctx ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, self.get(), nullptr));
  if (!ctx || EVP_PKEY_derive_init(ctx.get()) != 1 ||
      EVP_PKEY_derive_set_peer(ctx.get(), other.get()) != 1)
    return std::nullopt;
  std::size_t len = 0;
  if (EVP_PKEY_derive(ctx.get(), nullptr, &len) != 1 || len != kP384ScalarLen) return std::nullopt;
  SecretBytes out(len);
  if (EVP_PKEY_derive(ctx.get(), out.data(), &len) != 1 || len != kP384ScalarLen)
    return std::nullopt;
  return out;
}

// --- ML-KEM-1024 -----------------------------------------------------------

Pkey mlkem_from_params(OSSL_PARAM* params, int selection) {
  Pctx ctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-1024", nullptr));
  if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1) return nullptr;
  EVP_PKEY* raw = nullptr;
  if (EVP_PKEY_fromdata(ctx.get(), &raw, selection, params) != 1) return nullptr;
  return Pkey(raw);
}

Pkey mlkem_from_seed(ByteView seed64) {
  OSSL_PARAM params[2] = {
      OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED,
                                        const_cast<std::uint8_t*>(seed64.data()), seed64.size()),
      OSSL_PARAM_construct_end()};
  return mlkem_from_params(params, EVP_PKEY_KEYPAIR);
}

Pkey mlkem_from_public(ByteView ek) {
  OSSL_PARAM params[2] = {
      OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                        const_cast<std::uint8_t*>(ek.data()), ek.size()),
      OSSL_PARAM_construct_end()};
  return mlkem_from_params(params, EVP_PKEY_PUBLIC_KEY);
}

Bytes mlkem_public_bytes(EVP_PKEY* key) {
  Bytes out(kMlkemEkLen);
  std::size_t len = 0;
  if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, out.data(), out.size(),
                                      &len) != 1 ||
      len != kMlkemEkLen)
    fail(kExitIo, "cannot export ML-KEM public key");
  return out;
}

SecretBytes combine(ByteView ss_pq, ByteView ss_t, ByteView ct_t, ByteView ek_t) {
  SecretBytes input;
  append(input, ss_pq);
  append(input, ss_t);
  append(input, ct_t);
  append(input, ek_t);
  append(input, std::string_view(kLabel));
  auto h = sha3_256(input);
  SecretBytes out(h.begin(), h.end());
  cleanse(h.data(), h.size());
  return out;
}

}  // namespace

SecretBytes random_scalar_p384(ByteView seed48) {
  if (seed48.size() != kP384ScalarLen) fail(kExitIo, "RandomScalar: seed must be 48 bytes");
  if (scalar_valid(seed48)) return SecretBytes(seed48.begin(), seed48.end());
  // Extension material for the (cryptographically negligible) rejection case.
  for (unsigned counter = 1; counter < 256; ++counter) {
    SecretBytes in(seed48.begin(), seed48.end());
    in.push_back(static_cast<std::uint8_t>(counter));
    SecretBytes block = shake256(in, kP384ScalarLen);
    if (scalar_valid(block)) return block;
  }
  fail(kExitIo, "RandomScalar: rejection sampling exhausted");
}

SecretBytes generate_seed() { return random_secret(kSeedLen); }

ExpandedKey derive_key_pair(ByteView seed) {
  if (seed.size() != kSeedLen) fail(kExitIo, "KEM seed must be 32 bytes");
  SecretBytes full = shake256(seed, 64 + 48);
  ExpandedKey k;
  k.pq_seed.assign(full.begin(), full.begin() + 64);
  SecretBytes seed_t(full.begin() + 64, full.end());
  k.t_scalar = random_scalar_p384(seed_t);

  Pkey pq = mlkem_from_seed(k.pq_seed);
  if (!pq) fail(kExitIo, "ML-KEM key derivation failed");
  k.ek = mlkem_public_bytes(pq.get());
  Bytes ek_t = p384_base_mul(k.t_scalar);
  append(k.ek, ek_t);
  return k;
}

Bytes encapsulation_key(ByteView seed) { return derive_key_pair(seed).ek; }

bool ek_is_valid(ByteView ek) {
  if (ek.size() != kEkLen) return false;
  if (!p384_point_valid(ek.subspan(kMlkemEkLen))) return false;
  return static_cast<bool>(mlkem_from_public(ek.first(kMlkemEkLen)));
}

void validate_ek(ByteView ek) {
  if (!ek_is_valid(ek)) fail(kExitUsage, "invalid MLKEM1024-P384 encapsulation key");
}

Encapsulation encaps(ByteView ek, std::optional<ByteView> randomness) {
  validate_ek(ek);
  SecretBytes rnd;
  if (randomness) {
    if (randomness->size() != kEncapsRandomnessLen)
      fail(kExitIo, "encaps randomness must be 80 bytes");
    rnd.assign(randomness->begin(), randomness->end());
  } else {
    rnd = random_secret(kEncapsRandomnessLen);
  }
  ByteView ek_pq = ek.first(kMlkemEkLen);
  ByteView ek_t = ek.subspan(kMlkemEkLen);

  // ML-KEM-1024 encapsulation with explicit randomness (IKME).
  Pkey pq = mlkem_from_public(ek_pq);
  if (!pq) fail(kExitUsage, "invalid ML-KEM encapsulation key");
  Pctx ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, pq.get(), nullptr));
  OSSL_PARAM params[2] = {OSSL_PARAM_construct_octet_string(OSSL_KEM_PARAM_IKME, rnd.data(), 32),
                          OSSL_PARAM_construct_end()};
  std::size_t ct_len = 0, ss_len = 0;
  if (!ctx || EVP_PKEY_encapsulate_init(ctx.get(), params) != 1 ||
      EVP_PKEY_encapsulate(ctx.get(), nullptr, &ct_len, nullptr, &ss_len) != 1 ||
      ct_len != kMlkemCtLen || ss_len != 32)
    fail(kExitIo, "ML-KEM encapsulation setup failed");
  Bytes ct(ct_len);
  SecretBytes ss_pq(ss_len);
  if (EVP_PKEY_encapsulate(ctx.get(), ct.data(), &ct_len, ss_pq.data(), &ss_len) != 1)
    fail(kExitIo, "ML-KEM encapsulation failed");

  // P-384 ephemeral.
  SecretBytes sk_e = random_scalar_p384(ByteView(rnd).subspan(32, 48));
  Bytes ct_t = p384_base_mul(sk_e);
  auto ss_t = p384_ecdh(sk_e, ct_t, ek_t);
  if (!ss_t) fail(kExitUsage, "invalid P-384 public key");

  Encapsulation out;
  out.shared_secret = combine(ss_pq, *ss_t, ct_t, ek_t);
  out.ciphertext = std::move(ct);
  append(out.ciphertext, ct_t);
  return out;
}

std::optional<SecretBytes> decaps(ByteView seed, ByteView ct) {
  if (ct.size() != kCtLen || seed.size() != kSeedLen) return std::nullopt;
  ExpandedKey dk = derive_key_pair(seed);
  ByteView ct_pq = ct.first(kMlkemCtLen);
  ByteView ct_t = ct.subspan(kMlkemCtLen);
  ByteView ek_t = ByteView(dk.ek).subspan(kMlkemEkLen);

  auto ss_t = p384_ecdh(dk.t_scalar, ek_t, ct_t);
  if (!ss_t) return std::nullopt;

  Pkey pq = mlkem_from_seed(dk.pq_seed);
  if (!pq) return std::nullopt;
  Pctx ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, pq.get(), nullptr));
  if (!ctx || EVP_PKEY_decapsulate_init(ctx.get(), nullptr) != 1) return std::nullopt;
  SecretBytes ss_pq(32);
  std::size_t ss_len = ss_pq.size();
  if (EVP_PKEY_decapsulate(ctx.get(), ss_pq.data(), &ss_len, ct_pq.data(), ct_pq.size()) != 1 ||
      ss_len != 32)
    return std::nullopt;
  return combine(ss_pq, *ss_t, ct_t, ek_t);
}

}  // namespace secreto::kem
