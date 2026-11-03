// SPDX-FileCopyrightText: 2026 secreto contributors
// SPDX-License-Identifier: EUPL-1.2

// Unit tests for the library building blocks and end-to-end round trips.
#include <algorithm>
#include <cctype>
#include <string>

#include "secreto/armor.hpp"
#include "secreto/base64.hpp"
#include "secreto/crypto.hpp"
#include "secreto/format.hpp"
#include "secreto/header.hpp"
#include "secreto/kem.hpp"
#include "secreto/keys.hpp"
#include "secreto/padme.hpp"
#include "secreto/sign.hpp"
#include "testutil.hpp"

using namespace secreto;
using namespace testutil;

static void test_common() {
  CHECK(hex_encode(Bytes{0x00, 0xab, 0xff}) == "00abff");
  Bytes out;
  CHECK(hex_decode("00AbfF", out) && out == (Bytes{0x00, 0xab, 0xff}));
  CHECK(!hex_decode("0", out));
  CHECK(!hex_decode("zz", out));
  CHECK(ct_equal(Bytes{1, 2}, Bytes{1, 2}));
  CHECK(!ct_equal(Bytes{1, 2}, Bytes{1, 3}));
  CHECK(!ct_equal(Bytes{1, 2}, Bytes{1}));
}

static void test_base64() {
  // RFC 4648 vectors (unpadded and padded).
  CHECK(b64_encode(view("")) == "");
  CHECK(b64_encode(view("f")) == "Zg");
  CHECK(b64_encode(view("fo")) == "Zm8");
  CHECK(b64_encode(view("foo")) == "Zm9v");
  CHECK(b64_encode(view("foobar")) == "Zm9vYmFy");
  CHECK(b64_encode_padded(view("f")) == "Zg==");
  CHECK(b64_encode_padded(view("fo")) == "Zm8=");
  CHECK(b64_decode("Zm8").has_value());
  CHECK(!b64_decode("Zm8=").has_value());   // padding not allowed
  CHECK(!b64_decode("Zh").has_value());     // non-canonical trailing bits
  CHECK(!b64_decode("Z").has_value());      // impossible length
  CHECK(!b64_decode("Zm9v\n").has_value());
  CHECK(!b64_decode("Zm-v").has_value());   // URL-safe alphabet
  CHECK(b64_decode_padded("Zg==").has_value());
  CHECK(!b64_decode_padded("Zg").has_value());
  CHECK(!b64_decode_padded("Zh==").has_value());
  CHECK(!b64_decode_padded("Zg=A").has_value());
  CHECK(!b64_decode_padded("Z===").has_value());
}

static void test_crypto_primitives() {
  // SHA-512("abc"), SHA3-256("abc"), SHAKE256("") prefix.
  auto h = sha512(view("abc"));
  CHECK(hex_encode(h).substr(0, 32) == "ddaf35a193617abacc417349ae204131");
  auto h3 = sha3_256(view("abc"));
  CHECK(hex_encode(h3) == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
  SecretBytes sh = shake256(Bytes{}, 32);
  CHECK(hex_encode(sh) == "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
  // HMAC-SHA-512 (RFC 4231 test case 2).
  auto mac = hmac_sha512(view("Jefe"), view("what do ya want for nothing?"));
  CHECK(hex_encode(mac).substr(0, 32) == "164b7a7bfcf819e2e395fbe73b56e0a3");
  // HKDF-SHA-512 must agree with a manual extract+expand and be length-exact.
  SecretBytes okm = hkdf_sha512(view("ikm"), view("salt"), view("info"), 100);
  CHECK(okm.size() == 100);
  SecretBytes okm2 = hkdf_sha512(view("ikm"), view("salt"), view("info"), 40);
  CHECK(std::equal(okm2.begin(), okm2.end(), okm.begin()));
  // ChaCha20-Poly1305 (RFC 8439 section 2.8.2).
  Bytes key = unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
  Bytes nonce = unhex("070000004041424344454647");
  Bytes aad = unhex("50515253c0c1c2c3c4c5c6c7");
  std::string pt =
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
      "sunscreen would be it.";
  Bytes ct = chacha20poly1305_seal(key, nonce, aad, view(pt));
  CHECK(hex_encode(ByteView(ct).last(16)) == "1ae10b594f09e26a7e902ecbd0600691");
  auto back = chacha20poly1305_open(key, nonce, aad, ct);
  CHECK(back && to_string(*back) == pt);
  ct[3] ^= 1;
  CHECK(!chacha20poly1305_open(key, nonce, aad, ct).has_value());
}

static void test_armor() {
  Bytes data = random_bytes(500);
  std::string a = armor::encode(data);
  CHECK(armor::looks_armored(view(a)));
  CHECK(armor::decode(view(a)) == data);
  CHECK(armor::decode(view("\n  " + a + "\n\n")) == data);
  // CRLF line endings are accepted.
  std::string crlf;
  for (char c : a) {
    if (c == '\n') crlf += '\r';
    crlf += c;
  }
  CHECK(armor::decode(view(crlf)) == data);
  // Exact multiple of 48 bytes -> final line is a full 64 columns.
  Bytes d48 = random_bytes(96);
  CHECK(armor::decode(view(armor::encode(d48))) == d48);
  // Rejections.
  CHECK_THROWS_CODE(armor::decode(view("junk\n" + a)), kExitFormat);
  CHECK_THROWS_CODE(armor::decode(view(a + "junk\n")), kExitFormat);
  CHECK_THROWS_CODE(armor::decode(view(a + a)), kExitFormat);
  std::string no_end = a.substr(0, a.rfind("-----END"));
  CHECK_THROWS_CODE(armor::decode(view(no_end)), kExitFormat);
  CHECK(!armor::looks_armored(view("secreto/v1\n")));
}

static void test_padme_inner() {
  Bytes c(100, 0x41);
  SecretBytes inner = build_inner(c, false, {});
  CHECK(inner.size() == 102 && inner[0] == 0 && inner[101] == 0x80);
  SecretBytes padded = build_inner(c, true, {});
  CHECK(padded.size() == padme(102));
  InnerParts p = parse_inner(padded);
  CHECK(!p.signed_file && p.content.size() == 100);
  // Content that ends with 0x80/zeros survives.
  Bytes tricky = {'a', 0x80, 0, 0};
  SecretBytes t = build_inner(tricky, true, {});
  CHECK(parse_inner(t).content.size() == tricky.size());
  // Rejections.
  CHECK_THROWS_CODE(parse_inner(Bytes{0x02, 0x80}), kExitFormat);
  CHECK_THROWS_CODE(parse_inner(Bytes{0x00, 0x00}), kExitFormat);
  CHECK_THROWS_CODE(parse_inner(Bytes{0x00, 'a'}), kExitFormat);
  CHECK_THROWS_CODE(parse_inner(Bytes{0x01, 0x80}), kExitFormat);
  CHECK_THROWS_CODE(parse_inner(Bytes{}), kExitFormat);
}

static void test_keys() {
  SecretBytes seed = kem::generate_seed();
  std::string id = keys::identity_to_bech32(seed);
  CHECK(id.rfind("SECRETO-SECRET-KEY-1", 0) == 0);
  CHECK(keys::identity_from_bech32(id) == seed);
  CHECK_THROWS_CODE(keys::identity_from_bech32(std::string(id).replace(0, 7, "secreto")),
                    kExitUsage);
  std::string lower = id;
  for (char& ch : lower) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  CHECK_THROWS_CODE(keys::identity_from_bech32(lower), kExitUsage);

  Bytes ek = kem::encapsulation_key(seed);
  std::string r = keys::recipient_to_bech32(ek);
  CHECK(r.rfind("secreto1", 0) == 0);
  CHECK(keys::recipient_from_bech32(r) == ek);

  SecretBytes sk = sign::generate_secret_key();
  std::string s = keys::signing_key_to_bech32(sk);
  CHECK(keys::signing_key_from_bech32(s) == sk);
  Bytes pk = sign::public_key(sk);
  CHECK(pk.size() == sign::kPublicKeyLen);
  CHECK(keys::signer_public_from_bech32(keys::signer_public_to_bech32(pk)) == pk);

  auto ids = keys::parse_identities("# comment\n\n  " + id + "  \r\n" + id + "\n");
  CHECK(ids.size() == 2);
  CHECK_THROWS_CODE(keys::parse_identities("# nothing\n"), kExitUsage);
  CHECK_THROWS_CODE(keys::parse_identities("garbage\n"), kExitUsage);
  CHECK_THROWS_CODE(keys::parse_signing_key(s + "\n" + s + "\n"), kExitUsage);
}

static void test_signatures() {
  SecretBytes sk = sign::generate_secret_key();
  Bytes pk = sign::public_key(sk);
  Bytes mac = random_bytes(64);
  Bytes content = {'h', 'e', 'l', 'l', 'o'};
  Bytes sb = sign::sign(sk, mac, content);
  CHECK(sb.size() == sign::kSigblockLen);
  sign::verify(pk, sb, mac, content);
  CHECK(ByteView(sb).first(32).size() == 32);
  CHECK(ct_equal(ByteView(sb).first(32), sign::signer_id(pk)));
  Bytes other = {'h', 'e', 'l', 'l', 'p'};
  CHECK_THROWS_CODE(sign::verify(pk, sb, mac, other), kExitSignature);
  Bytes mac2 = mac;
  mac2[0] ^= 1;
  CHECK_THROWS_CODE(sign::verify(pk, sb, mac2, content), kExitSignature);
  for (std::size_t off : {std::size_t{0}, std::size_t{40}, std::size_t{100}, sb.size() - 1}) {
    Bytes bad = sb;
    bad[off] ^= 1;
    CHECK_THROWS_CODE(sign::verify(pk, bad, mac, content), kExitSignature);
  }
  SecretBytes sk2 = sign::generate_secret_key();
  CHECK_THROWS_CODE(sign::verify(sign::public_key(sk2), sb, mac, content), kExitSignature);
  CHECK_THROWS_CODE(sign::verify(pk, ByteView(sb).first(sb.size() - 1), mac, content),
                    kExitSignature);
  // Deterministic key derivation from the seed.
  CHECK(sign::public_key(sk) == pk);
}

static void test_header() {
  header::Stanza a;
  a.args = {"mlkem1024p384", "AAAA"};
  a.body = random_bytes(48);
  header::Stanza b;
  b.args = {"x-test", "y"};
  b.body = {};
  std::vector<header::Stanza> v = {a, b};
  Bytes in = header::mac_input(v);
  Bytes fk = random_bytes(32);
  auto mac = header::compute_mac(fk, in);
  Bytes full = header::finish(in, mac);
  append(full, std::string_view("payload"));
  header::Parsed p = header::parse(full);
  CHECK(p.stanzas.size() == 2);
  CHECK(p.stanzas[0].args == a.args && p.stanzas[0].body == a.body);
  CHECK(p.stanzas[1].args == b.args && p.stanzas[1].body.empty());
  CHECK(p.mac_input == in);
  CHECK(std::equal(p.mac.begin(), p.mac.end(), mac.begin()));
  CHECK(std::string(full.begin() + static_cast<std::ptrdiff_t>(p.total_len), full.end()) ==
        "payload");
  // 48-byte body serialises as one full line followed by an empty line.
  CHECK(header::serialize_stanza(a).find("\n\n") != std::string::npos);

  CHECK_THROWS_CODE(header::parse(view("secreto/v2\n")), kExitFormat);
  CHECK_THROWS_CODE(header::parse(view("")), kExitFormat);
  CHECK_THROWS_CODE(header::parse(view("secreto/v1\n--- AAAA\n")), kExitFormat);
}

static void test_roundtrip_recipients() {
  SecretBytes seed1 = kem::generate_seed(), seed2 = kem::generate_seed(), seed3 = kem::generate_seed();
  Bytes ek1 = kem::encapsulation_key(seed1), ek2 = kem::encapsulation_key(seed2);
  Bytes content = random_bytes(70000);  // spans two STREAM chunks

  EncryptOptions eo;
  eo.recipients = {ek1, ek2};
  Bytes file = encrypt(content, eo);

  for (const SecretBytes* s : {&seed1, &seed2}) {
    DecryptOptions d;
    d.identities = {*s};
    DecryptResult r = decrypt(file, d);
    CHECK(r.content.size() == content.size() &&
          std::equal(r.content.begin(), r.content.end(), content.begin()));
    CHECK(!r.signed_file);
  }
  DecryptOptions wrong;
  wrong.identities = {seed3};
  CHECK_THROWS_CODE(decrypt(file, wrong), kExitNoMatch);
  CHECK_THROWS_CODE(decrypt(file, DecryptOptions{}), kExitNoMatch);
  DecryptOptions pass_only;
  pass_only.passphrase = SecretBytes{'x'};
  CHECK_THROWS_CODE(decrypt(file, pass_only), kExitNoMatch);

  // Any single-byte header corruption yields no content (exit 3 or 4).
  DecryptOptions ok;
  ok.identities = {seed1};
  for (std::size_t off : {std::size_t{3}, std::size_t{40}, std::size_t{900}}) {
    Bytes bad = file;
    bad[off] ^= 0x01;
    bool threw = false;
    try {
      decrypt(bad, ok);
    } catch (const Error& e) {
      threw = (e.code() == kExitNoMatch || e.code() == kExitFormat);
    }
    CHECK(threw);
  }
  // Payload corruption -> exit 4.
  Bytes bad = file;
  bad[bad.size() - 5] ^= 1;
  CHECK_THROWS_CODE(decrypt(bad, ok), kExitFormat);
  bad = file;
  bad.pop_back();
  CHECK_THROWS_CODE(decrypt(bad, ok), kExitFormat);

  // Armor.
  eo.armor = true;
  Bytes armored = encrypt(content, eo);
  CHECK(armor::looks_armored(armored));
  DecryptResult r = decrypt(armored, ok);
  CHECK(r.content.size() == content.size());

  // Empty content, padding.
  EncryptOptions pe;
  pe.recipients = {ek1};
  pe.pad = true;
  for (std::size_t n : {std::size_t{0}, std::size_t{1}, std::size_t{100}, std::size_t{1000}}) {
    Bytes c = random_bytes(n);
    Bytes f = encrypt(c, pe);
    DecryptResult pr = decrypt(f, ok);
    CHECK(pr.content.size() == n);
  }
}

static void test_roundtrip_signed() {
  SecretBytes seed = kem::generate_seed();
  SecretBytes sk = sign::generate_secret_key();
  Bytes pk = sign::public_key(sk);
  Bytes content = random_bytes(5000);

  EncryptOptions eo;
  eo.recipients = {kem::encapsulation_key(seed)};
  eo.signing_key = sk;
  eo.pad = true;
  Bytes file = encrypt(content, eo);

  DecryptOptions d;
  d.identities = {seed};
  DecryptResult r = decrypt(file, d);  // no --verify: still released
  CHECK(r.signed_file && !r.verified && r.content.size() == content.size());
  CHECK(ct_equal(r.signer_id, sign::signer_id(pk)));

  d.verify_key = pk;
  r = decrypt(file, d);
  CHECK(r.signed_file && r.verified);

  SecretBytes other = sign::generate_secret_key();
  d.verify_key = sign::public_key(other);
  CHECK_THROWS_CODE(decrypt(file, d), kExitSignature);

  // verify requested on an unsigned file
  EncryptOptions plain;
  plain.recipients = eo.recipients;
  Bytes unsigned_file = encrypt(content, plain);
  d.verify_key = pk;
  CHECK_THROWS_CODE(decrypt(unsigned_file, d), kExitSignature);
}

static void test_roundtrip_passphrase() {
  EncryptOptions eo;
  eo.passphrase = SecretBytes{'p', 'w'};
  eo.argon = {65536, 3, 2};  // decryption-side minimum m/t; fast enough for tests
  Bytes content = random_bytes(1234);
  Bytes file = encrypt(content, eo);
  DecryptOptions d;
  d.passphrase = SecretBytes{'p', 'w'};
  DecryptResult r = decrypt(file, d);
  CHECK(r.content.size() == content.size());
  d.passphrase = SecretBytes{'p', 'x'};
  CHECK_THROWS_CODE(decrypt(file, d), kExitNoMatch);
  DecryptOptions id_only;
  id_only.identities = {kem::generate_seed()};
  CHECK_THROWS_CODE(decrypt(file, id_only), kExitNoMatch);

  // Both credential kinds may be offered; the matching one wins.
  d.passphrase = SecretBytes{'p', 'w'};
  d.identities = {kem::generate_seed()};
  CHECK(decrypt(file, d).content.size() == content.size());

  // Option validation.
  EncryptOptions bad;
  CHECK_THROWS_CODE(encrypt(content, bad), kExitUsage);
  bad.passphrase = SecretBytes{'a'};
  bad.recipients = {kem::encapsulation_key(kem::generate_seed())};
  CHECK_THROWS_CODE(encrypt(content, bad), kExitUsage);
}

int main() {
  try {
    test_common();
    test_base64();
    test_crypto_primitives();
    test_armor();
    test_padme_inner();
    test_keys();
    test_signatures();
    test_header();
    test_roundtrip_recipients();
    test_roundtrip_signed();
    test_roundtrip_passphrase();
  } catch (const std::exception& e) {
    std::fprintf(stderr, "exception: %s\n", e.what());
    return 1;
  }
  return finish("test_unit");
}
