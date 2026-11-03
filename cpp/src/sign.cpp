#include "secreto/sign.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <memory>

#include "secreto/crypto.hpp"

namespace secreto::sign {

namespace {

struct PkeyDel {
  void operator()(EVP_PKEY* k) const { EVP_PKEY_free(k); }
};
using Pkey = std::unique_ptr<EVP_PKEY, PkeyDel>;
struct PctxDel {
  void operator()(EVP_PKEY_CTX* c) const { EVP_PKEY_CTX_free(c); }
};
using Pctx = std::unique_ptr<EVP_PKEY_CTX, PctxDel>;
struct MdCtxDel {
  void operator()(EVP_MD_CTX* c) const { EVP_MD_CTX_free(c); }
};
using MdCtx = std::unique_ptr<EVP_MD_CTX, MdCtxDel>;

Pkey ed25519_private(ByteView seed) {
  return Pkey(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size()));
}
Pkey ed25519_public(ByteView pk) {
  return Pkey(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pk.data(), pk.size()));
}

Pkey mldsa_from(const char* param, ByteView data, int selection) {
  Pctx ctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-DSA-87", nullptr));
  OSSL_PARAM params[2] = {
      OSSL_PARAM_construct_octet_string(param, const_cast<std::uint8_t*>(data.data()), data.size()),
      OSSL_PARAM_construct_end()};
  if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1) return nullptr;
  EVP_PKEY* raw = nullptr;
  if (EVP_PKEY_fromdata(ctx.get(), &raw, selection, params) != 1) return nullptr;
  return Pkey(raw);
}

Pkey mldsa_private(ByteView seed) {
  return mldsa_from(OSSL_PKEY_PARAM_ML_DSA_SEED, seed, EVP_PKEY_KEYPAIR);
}
Pkey mldsa_public(ByteView pk) {
  return mldsa_from(OSSL_PKEY_PARAM_PUB_KEY, pk, EVP_PKEY_PUBLIC_KEY);
}

Bytes raw_public(EVP_PKEY* key, std::size_t expect) {
  Bytes out(expect);
  std::size_t len = 0;
  if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, out.data(), out.size(), &len) !=
          1 ||
      len != expect)
    fail(kExitIo, "cannot export public key");
  return out;
}

void check_secret_key(ByteView sk) {
  if (sk.size() != kSecretKeyLen) fail(kExitUsage, "signing key must be 64 bytes");
}

}  // namespace

SecretBytes generate_secret_key() { return random_secret(kSecretKeyLen); }

Bytes public_key(ByteView sk) {
  check_secret_key(sk);
  Pkey ed = ed25519_private(sk.first(32));
  Pkey ml = mldsa_private(sk.subspan(32, 32));
  if (!ed || !ml) fail(kExitUsage, "invalid signing key");
  Bytes pk(kEd25519PkLen);
  std::size_t len = pk.size();
  if (EVP_PKEY_get_raw_public_key(ed.get(), pk.data(), &len) != 1 || len != kEd25519PkLen)
    fail(kExitIo, "cannot export Ed25519 public key");
  Bytes mlpk = raw_public(ml.get(), kMldsaPkLen);
  append(pk, mlpk);
  return pk;
}

std::array<std::uint8_t, kSignerIdLen> signer_id(ByteView pk) {
  Bytes in;
  append(in, std::string_view("secreto/v1/signer-id"));
  append(in, pk);
  auto h = sha512(in);
  std::array<std::uint8_t, kSignerIdLen> id{};
  std::copy(h.begin(), h.begin() + kSignerIdLen, id.begin());
  return id;
}

Bytes signature_message(ByteView header_mac, ByteView content) {
  Bytes msg;
  append(msg, std::string_view("secreto/v1/signature"));
  append(msg, header_mac);
  std::uint64_t n = content.size();
  for (int i = 7; i >= 0; --i) msg.push_back(static_cast<std::uint8_t>((n >> (8 * i)) & 0xff));
  auto h = sha512(content);
  append(msg, ByteView(h));
  return msg;
}

Bytes sign(ByteView sk, ByteView header_mac, ByteView content) {
  check_secret_key(sk);
  Bytes pk = public_key(sk);
  Bytes msg = signature_message(header_mac, content);

  Pkey ed = ed25519_private(sk.first(32));
  Pkey ml = mldsa_private(sk.subspan(32, 32));
  if (!ed || !ml) fail(kExitUsage, "invalid signing key");

  Bytes out;
  auto id = signer_id(pk);
  out.insert(out.end(), id.begin(), id.end());

  {
    MdCtx ctx(EVP_MD_CTX_new());
    Bytes sig(kEd25519SigLen);
    std::size_t len = sig.size();
    if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, ed.get()) != 1 ||
        EVP_DigestSign(ctx.get(), sig.data(), &len, msg.data(), msg.size()) != 1 ||
        len != kEd25519SigLen)
      fail(kExitIo, "Ed25519 signing failed");
    append(out, sig);
  }
  {
    // ML-DSA-87, pure mode, empty context string (the default).
    MdCtx ctx(EVP_MD_CTX_new());
    Bytes sig(kMldsaSigLen);
    std::size_t len = sig.size();
    if (!ctx || EVP_DigestSignInit_ex(ctx.get(), nullptr, nullptr, nullptr, nullptr, ml.get(),
                                      nullptr) != 1 ||
        EVP_DigestSign(ctx.get(), sig.data(), &len, msg.data(), msg.size()) != 1 ||
        len != kMldsaSigLen)
      fail(kExitIo, "ML-DSA-87 signing failed");
    append(out, sig);
  }
  return out;
}

void verify(ByteView pk, ByteView sigblock, ByteView header_mac, ByteView content) {
  if (pk.size() != kPublicKeyLen) fail(kExitSignature, "invalid signer public key");
  if (sigblock.size() != kSigblockLen) fail(kExitSignature, "malformed signature block");

  auto want_id = signer_id(pk);
  if (!ct_equal(sigblock.first(kSignerIdLen), want_id))
    fail(kExitSignature, "file was signed by a different signer");

  Bytes msg = signature_message(header_mac, content);
  ByteView ed_sig = sigblock.subspan(kSignerIdLen, kEd25519SigLen);
  ByteView ml_sig = sigblock.subspan(kSignerIdLen + kEd25519SigLen, kMldsaSigLen);

  Pkey ed = ed25519_public(pk.first(kEd25519PkLen));
  Pkey ml = mldsa_public(pk.subspan(kEd25519PkLen));
  if (!ed || !ml) fail(kExitSignature, "invalid signer public key");

  bool ed_ok = false, ml_ok = false;
  {
    MdCtx ctx(EVP_MD_CTX_new());
    ed_ok = ctx && EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, ed.get()) == 1 &&
            EVP_DigestVerify(ctx.get(), ed_sig.data(), ed_sig.size(), msg.data(), msg.size()) == 1;
  }
  {
    MdCtx ctx(EVP_MD_CTX_new());
    ml_ok = ctx &&
            EVP_DigestVerifyInit_ex(ctx.get(), nullptr, nullptr, nullptr, nullptr, ml.get(),
                                    nullptr) == 1 &&
            EVP_DigestVerify(ctx.get(), ml_sig.data(), ml_sig.size(), msg.data(), msg.size()) == 1;
  }
  if (!ed_ok || !ml_ok) fail(kExitSignature, "signature verification failed");
}

}  // namespace secreto::sign
