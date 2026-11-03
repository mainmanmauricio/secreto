#include "secreto/format.hpp"

#include <algorithm>

#include "secreto/armor.hpp"
#include "secreto/base64.hpp"
#include "secreto/crypto.hpp"
#include "secreto/header.hpp"
#include "secreto/hpke.hpp"
#include "secreto/kem.hpp"
#include "secreto/padme.hpp"
#include "secreto/sign.hpp"
#include "secreto/stream.hpp"

namespace secreto {

namespace {

constexpr std::string_view kTypeMlkem = "mlkem1024p384";
constexpr std::string_view kTypeArgon = "argon2id";
constexpr std::size_t kWrappedKeyLen = kFileKeyLen + kAeadTagLen;  // 48
constexpr std::size_t kArgonSaltLen = 16;

[[noreturn]] void format_error(const char* msg) { fail(kExitFormat, msg); }

// ----------------------------------------------------------------- argon2id

struct ArgonStanza {
  Bytes salt;
  ArgonParams params;
};

// Canonical decimal: ^[1-9][0-9]*$, must fit in 32 bits.
bool parse_canonical_u32(std::string_view s, std::uint32_t& out) {
  if (s.empty() || s.size() > 10 || s[0] < '1' || s[0] > '9') return false;
  std::uint64_t v = 0;
  for (char c : s) {
    if (c < '0' || c > '9') return false;
    v = v * 10 + static_cast<std::uint64_t>(c - '0');
  }
  if (v > 0xffffffffull) return false;
  out = static_cast<std::uint32_t>(v);
  return true;
}

// Validates an argon2id stanza (exit 4 on any problem).
ArgonStanza parse_argon_stanza(const header::Stanza& st) {
  if (st.args.size() != 5) format_error("malformed argon2id stanza");
  ArgonStanza a;
  auto salt = b64_decode(st.args[1]);
  if (!salt || salt->size() != kArgonSaltLen) format_error("malformed argon2id salt");
  a.salt = std::move(*salt);
  if (!parse_canonical_u32(st.args[2], a.params.m_kib) ||
      !parse_canonical_u32(st.args[3], a.params.t) ||
      !parse_canonical_u32(st.args[4], a.params.p))
    format_error("malformed argon2id parameters");
  if (a.params.m_kib < 65536 || a.params.m_kib > 4194304 || a.params.t < 3 || a.params.t > 16 ||
      a.params.p < 1 || a.params.p > 16)
    format_error("argon2id parameters out of range");
  if (st.body.size() != kWrappedKeyLen) format_error("malformed argon2id body");
  return a;
}

SecretBytes argon_wrap_key(ByteView passphrase, ByteView salt, const ArgonParams& p) {
  Bytes s;
  append(s, std::string_view("secreto/v1/argon2id"));
  append(s, salt);
  Argon2Input in;
  in.password = passphrase;
  in.salt = s;
  in.m_kib = p.m_kib;
  in.t = p.t;
  in.p = p.p;
  in.out_len = 32;
  return argon2id(in);
}

// ------------------------------------------------------------------- stanzas

header::Stanza make_mlkem_stanza(ByteView ek, ByteView file_key) {
  hpke::SealResult sealed = hpke::seal_base(ek, as_bytes(hpke::kSecretoInfo), {}, file_key);
  header::Stanza st;
  st.args = {std::string(kTypeMlkem), b64_encode(sealed.enc)};
  st.body = std::move(sealed.ciphertext);
  return st;
}

header::Stanza make_argon_stanza(ByteView passphrase, ByteView file_key, const ArgonParams& p) {
  Bytes salt = random_bytes(kArgonSaltLen);
  SecretBytes wrap = argon_wrap_key(passphrase, salt, p);
  std::array<std::uint8_t, kAeadNonceLen> zero{};
  header::Stanza st;
  st.args = {std::string(kTypeArgon), b64_encode(salt), std::to_string(p.m_kib),
             std::to_string(p.t), std::to_string(p.p)};
  st.body = chacha20poly1305_seal(wrap, zero, {}, file_key);
  return st;
}

// Well-formed mlkem1024p384 stanza -> (enc, body); nullopt means "not a match
// candidate" (malformed stanzas are skipped, never errors).
struct MlkemStanza {
  Bytes enc;
  const Bytes* body;
};
std::optional<MlkemStanza> parse_mlkem_stanza(const header::Stanza& st) {
  if (st.args.size() != 2) return std::nullopt;
  auto enc = b64_decode(st.args[1]);
  if (!enc || enc->size() != kem::kCtLen) return std::nullopt;
  if (st.body.size() != kWrappedKeyLen) return std::nullopt;
  return MlkemStanza{std::move(*enc), &st.body};
}

// Header-level rules independent of credentials (exit 4).
void validate_header_stanzas(const header::Parsed& h) {
  bool any_argon = false;
  for (const auto& st : h.stanzas)
    if (st.args[0] == kTypeArgon) any_argon = true;
  if (!any_argon) return;
  if (h.stanzas.size() != 1) format_error("argon2id stanza must be the only stanza");
  (void)parse_argon_stanza(h.stanzas[0]);
}

std::optional<SecretBytes> unwrap_file_key(const header::Parsed& h, const DecryptOptions& opts) {
  for (const auto& st : h.stanzas) {
    if (st.args[0] == kTypeMlkem) {
      auto m = parse_mlkem_stanza(st);
      if (!m) continue;
      for (const SecretBytes& id : opts.identities) {
        auto fk = hpke::open_base(m->enc, id, as_bytes(hpke::kSecretoInfo), {}, *m->body);
        if (fk && fk->size() == kFileKeyLen) return fk;
      }
    } else if (st.args[0] == kTypeArgon && opts.passphrase) {
      ArgonStanza a = parse_argon_stanza(st);
      SecretBytes wrap = argon_wrap_key(*opts.passphrase, a.salt, a.params);
      std::array<std::uint8_t, kAeadNonceLen> zero{};
      auto fk = chacha20poly1305_open(wrap, zero, {}, st.body);
      if (fk && fk->size() == kFileKeyLen) return fk;
    }
  }
  return std::nullopt;
}

}  // namespace

// ------------------------------------------------------------ inner plaintext

SecretBytes build_inner(ByteView content, bool pad, ByteView sigblock) {
  const bool signed_file = !sigblock.empty();
  if (signed_file && sigblock.size() != sign::kSigblockLen)
    fail(kExitUsage, "bad signature block size");
  std::uint64_t unpadded = 1 + content.size() + 1 + sigblock.size();
  std::uint64_t target = pad ? padme(unpadded) : unpadded;
  SecretBytes inner;
  inner.reserve(target);
  inner.push_back(signed_file ? 0x01 : 0x00);
  append(inner, content);
  inner.push_back(0x80);
  inner.insert(inner.end(), target - unpadded, 0x00);
  append(inner, sigblock);
  return inner;
}

InnerParts parse_inner(ByteView p) {
  if (p.empty()) format_error("empty inner plaintext");
  InnerParts r;
  if (p[0] == 0x00) {
    r.signed_file = false;
  } else if (p[0] == 0x01) {
    r.signed_file = true;
  } else {
    format_error("unknown inner flags");
  }
  ByteView rest = p.subspan(1);
  if (r.signed_file) {
    if (rest.size() < sign::kSigblockLen) format_error("truncated signature block");
    r.sigblock = rest.last(sign::kSigblockLen);
    rest = rest.first(rest.size() - sign::kSigblockLen);
  }
  std::size_t end = rest.size();
  while (end > 0 && rest[end - 1] == 0x00) --end;
  if (end == 0 || rest[end - 1] != 0x80) format_error("invalid padding");
  r.content = rest.first(end - 1);
  return r;
}

// -------------------------------------------------------------------- encrypt

Bytes encrypt(ByteView content, const EncryptOptions& opts) {
  const bool has_recipients = !opts.recipients.empty();
  const bool has_pass = opts.passphrase.has_value();
  if (has_recipients == has_pass)
    fail(kExitUsage, "encryption needs either recipients or a passphrase (not both)");

  SecretBytes file_key = random_secret(kFileKeyLen);

  std::vector<header::Stanza> stanzas;
  if (has_pass) {
    stanzas.push_back(make_argon_stanza(*opts.passphrase, file_key, opts.argon));
  } else {
    for (const Bytes& ek : opts.recipients) stanzas.push_back(make_mlkem_stanza(ek, file_key));
  }
  if (stanzas.size() > header::kMaxStanzas) fail(kExitUsage, "too many recipients");

  Bytes mac_in = header::mac_input(stanzas);
  auto mac = header::compute_mac(file_key, mac_in);
  Bytes out = header::finish(mac_in, mac);

  Bytes sigblock;
  if (opts.signing_key) sigblock = sign::sign(*opts.signing_key, mac, content);
  SecretBytes inner = build_inner(content, opts.pad, sigblock);

  Bytes nonce = random_bytes(stream::kNonceLen);
  SecretBytes payload_key = stream::derive_payload_key(file_key, nonce);
  append(out, nonce);
  Bytes ct = stream::encrypt(payload_key, inner);
  append(out, ct);

  if (opts.armor) {
    std::string a = armor::encode(out);
    return Bytes(a.begin(), a.end());
  }
  return out;
}

// -------------------------------------------------------------------- decrypt

DecryptResult decrypt(ByteView file, const DecryptOptions& opts) {
  Bytes dearmored;
  if (armor::looks_armored(file)) {
    dearmored = armor::decode(file);
    file = dearmored;
  }

  header::Parsed h = header::parse(file);
  validate_header_stanzas(h);

  auto file_key = unwrap_file_key(h, opts);
  if (!file_key) fail(kExitNoMatch, "no matching identity or passphrase");

  auto mac = header::compute_mac(*file_key, h.mac_input);
  if (!ct_equal(mac, h.mac)) format_error("header MAC verification failed");

  ByteView payload = file.subspan(h.total_len);
  if (payload.size() < stream::kNonceLen) format_error("payload truncated");
  SecretBytes payload_key =
      stream::derive_payload_key(*file_key, payload.first(stream::kNonceLen));
  SecretBytes inner = stream::decrypt(payload_key, payload.subspan(stream::kNonceLen));

  InnerParts parts = parse_inner(inner);

  DecryptResult res;
  res.signed_file = parts.signed_file;
  if (opts.verify_key) {
    if (!parts.signed_file) fail(kExitSignature, "file is not signed");
    sign::verify(*opts.verify_key, parts.sigblock, h.mac, parts.content);
    res.verified = true;
  }
  if (parts.signed_file) {
    std::copy_n(parts.sigblock.begin(), res.signer_id.size(), res.signer_id.begin());
  }
  res.content.assign(parts.content.begin(), parts.content.end());
  cleanse(inner);
  return res;
}

}  // namespace secreto
