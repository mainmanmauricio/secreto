#include "secreto/keys.hpp"

#include "secreto/bech32.hpp"
#include "secreto/kem.hpp"
#include "secreto/sign.hpp"

namespace secreto::keys {

namespace {

[[noreturn]] void invalid(const char* what) {
  fail(kExitUsage, std::string("invalid ") + what);
}

std::string_view trim(std::string_view s) {
  auto ws = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
  while (!s.empty() && ws(s.front())) s.remove_prefix(1);
  while (!s.empty() && ws(s.back())) s.remove_suffix(1);
  return s;
}

}  // namespace

std::string identity_to_bech32(ByteView seed) { return bech32_encode(kHrpIdentity, seed); }

SecretBytes identity_from_bech32(std::string_view s) {
  auto d = bech32_decode_exact(s, kHrpIdentity, kem::kSeedLen);
  if (!d) invalid("identity");
  SecretBytes out(d->begin(), d->end());
  cleanse(*d);
  return out;
}

std::string recipient_to_bech32(ByteView ek) { return bech32_encode(kHrpRecipient, ek); }

Bytes recipient_from_bech32(std::string_view s) {
  auto d = bech32_decode_exact(s, kHrpRecipient, kem::kEkLen);
  if (!d) invalid("recipient");
  if (!kem::ek_is_valid(*d)) invalid("recipient (bad encapsulation key)");
  return std::move(*d);
}

std::string signing_key_to_bech32(ByteView sk) { return bech32_encode(kHrpSigningKey, sk); }

SecretBytes signing_key_from_bech32(std::string_view s) {
  auto d = bech32_decode_exact(s, kHrpSigningKey, sign::kSecretKeyLen);
  if (!d) invalid("signing key");
  SecretBytes out(d->begin(), d->end());
  cleanse(*d);
  return out;
}

std::string signer_public_to_bech32(ByteView pk) { return bech32_encode(kHrpSignerPublic, pk); }

Bytes signer_public_from_bech32(std::string_view s) {
  auto d = bech32_decode_exact(s, kHrpSignerPublic, sign::kPublicKeyLen);
  if (!d) invalid("signer public key");
  return std::move(*d);
}

std::vector<std::string> key_lines(std::string_view text) {
  std::vector<std::string> out;
  std::size_t start = 0;
  while (start <= text.size()) {
    std::size_t nl = text.find('\n', start);
    std::string_view line =
        (nl == std::string_view::npos) ? text.substr(start) : text.substr(start, nl - start);
    line = trim(line);
    if (!line.empty() && line.front() != '#') out.emplace_back(line);
    if (nl == std::string_view::npos) break;
    start = nl + 1;
  }
  return out;
}

std::vector<SecretBytes> parse_identities(std::string_view text) {
  std::vector<SecretBytes> out;
  for (std::string& l : key_lines(text)) {
    out.push_back(identity_from_bech32(l));
    cleanse(l.data(), l.size());
  }
  if (out.empty()) fail(kExitUsage, "no identities found");
  return out;
}

std::vector<Bytes> parse_recipients(std::string_view text) {
  std::vector<Bytes> out;
  for (const std::string& l : key_lines(text)) out.push_back(recipient_from_bech32(l));
  if (out.empty()) fail(kExitUsage, "no recipients found");
  return out;
}

SecretBytes parse_signing_key(std::string_view text) {
  auto lines = key_lines(text);
  if (lines.empty()) fail(kExitUsage, "no signing key found");
  if (lines.size() != 1) fail(kExitUsage, "multiple signing keys in file");
  SecretBytes sk = signing_key_from_bech32(lines[0]);
  cleanse(lines[0].data(), lines[0].size());
  return sk;
}

}  // namespace secreto::keys
