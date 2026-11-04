<!--
SPDX-FileCopyrightText: 2026 secreto contributors
SPDX-License-Identifier: EUPL-1.2
-->

# secreto/v1 file format

This document is normative. The key words MUST, MUST NOT, SHOULD, MAY are as
in BCP 14.

Base64 throughout the header is standard Base64 (RFC 4648 §4) **without**
`=` padding. Encoders MUST emit canonical base64; decoders MUST reject
non-canonical encodings and any encoding that ends with `=`.

`||` denotes concatenation. `0xNN` is a byte. `[:N]` truncates to the first
N bytes.

## Overview

A secreto file is:

```
header || payload
```

The header is UTF-8 text ending with a MAC line. The payload is binary and
starts immediately after the header's final LF.

Files MAY use the extension `.sec`.

## File key

Each file uses a fresh 32-byte **file key** from a CSPRNG. It MUST NOT be
reused across files.

## Header

### Version line

```
secreto/v1\n
```

Anything other than exactly this version string MUST be rejected.

### Recipient stanza

A stanza starts with `->`, a space, one or more space-separated arguments,
and a LF. The body is base64 wrapped at 64 columns; the final body line MUST
be shorter than 64 characters (it MAY be empty).

```
arg-line    = "-> " argument *(SP argument) LF
full-line   = 64base64char LF
final-line  = *63base64char LF
stanza      = arg-line *full-line final-line
argument    = 1*VCHAR
```

Unrecognized stanza types MUST be ignored when searching for a matching
identity, unless a recognized type that forbids mixing is present (see
argon2id).

### Header MAC

The final header line is:

```
--- <base64-of-64-byte-mac>\n
```

The MAC is HMAC-SHA-512 over the entire header up to and including the three
hyphens `---` (excluding the space and MAC value). The HMAC key is:

```
mac_key = HKDF-SHA-512(
  ikm  = file_key,
  salt = empty,
  info = "secreto/v1/header",
  L    = 64
)
```

Verification MUST use a constant-time comparison. On MAC failure the
implementation MUST reject the file (exit 4) and MUST NOT release payload
plaintext.

### Limits

| Limit | Value |
|-------|-------|
| Header size | ≤ 1 MiB |
| Stanza count | ≤ 256 |
| Header line length | ≤ 4096 bytes (excluding LF) |
| Bech32 string length | ≤ 8192 characters |

Exceeding a limit MUST cause rejection (exit 4 for ciphertext; exit 1 for
key/recipient files).

### ABNF summary

```
header     = version-line 1*stanza end
version-line = %s"secreto/v1" LF
end        = "--- " 86base64char LF
```

86 base64 characters encode exactly 64 bytes without padding.

## Recipient type: mlkem1024p384

### Key encoding

- **Identity** (secret): 32-byte hybrid KEM seed, Bech32 HRP
  `SECRETO-SECRET-KEY-` (uppercase).
- **Recipient** (public): 1665-byte encapsulation key, Bech32 HRP `secreto`
  (lowercase).

### Stanza

```
-> mlkem1024p384 <base64(enc)>
<body: exactly 48 bytes base64-encoded>
```

`enc` is the 1665-byte HPKE encapsulated key (Nenc). The body is the HPKE
ciphertext for a 32-byte plaintext (16-byte Poly1305 tag → 48 bytes).

Identity implementations MUST ignore stanzas whose first argument is not
`mlkem1024p384`. They MUST otherwise reject the stanza (treat as non-match)
if:

- argument count ≠ 2, or
- the second argument is not canonical base64 of exactly 1665 bytes, or
- the body length ≠ 48 bytes.

### Hybrid KEM: MLKEM1024-P384 (CG framework)

Constants: see [registry.md](registry.md).

**DeriveKeyPair(seed)** with `|seed|=32`:

```
seed_full = SHAKE256(seed, 112)          # 64 + 48
seed_PQ   = seed_full[0:64]
seed_T    = seed_full[64:112]
(dk_PQ, ek_PQ) = ML-KEM-1024.KeyGen_internal(seed_PQ[0:32], seed_PQ[32:64])
dk_T = RandomScalar_P384(seed_T)         # rejection sampling, Nscalar=48
ek_T = P384_BaseMul(dk_T)                # uncompressed 97 bytes
ek   = ek_PQ || ek_T                     # 1568 + 97 = 1665
dk   = seed                              # stored as 32-byte seed
```

**RandomScalar_P384(seed)** (Nseed=48 for Encaps ephemeral; for DeriveKeyPair
the 48-byte seed_T is expanded — see concrete-hybrid-kems-04):

For Encaps, `random(Group_T.Nseed)` yields 48 bytes used as
`RandomScalar` input. Rejection sampling:

```
start = 0; end = 48
sk = OS2IP(seed[start:end])
while sk == 0 or sk >= n_P384:
  start = end; end = end + 48
  if end > len(seed): fail
  sk = OS2IP(seed[start:end])
return sk
```

For DeriveKeyPair, `seed_T` is 48 bytes. The PRG output for keygen is
exactly `KEM_PQ.Nseed + Group_T.Nseed = 112` bytes from SHAKE256(seed),
so RandomScalar receives a 48-byte seed. Implementations MUST obtain
enough rejection-sampling material by expanding with SHAKE256 if needed:
if the 48-byte seed alone would reject (cryptographically negligible for
P-384), re-derive additional 48-byte blocks as
`SHAKE256(seed_T || counter)` — **OR**, per the concrete draft, treat
`RandomScalar` input length as Nseed with extension via the PRG during
`expandDecapsKeyG`. In practice for P-384 the rejection probability is
`< 2^-192`, so a single 48-byte draw never rejects for honest seeds.

**Encaps(ek)**:

```
(ek_PQ, ek_T) = split(1568, 97, ek)
(ss_PQ, ct_PQ) = ML-KEM-1024.Encaps(ek_PQ)
sk_E = RandomScalar(random(48))
ct_T = P384_BaseMul(sk_E)                # 97 bytes uncompressed
ss_T = X_coordinate(P384_Mul(ek_T, sk_E)) # 48 bytes
ss   = SHA3-256(ss_PQ || ss_T || ct_T || ek_T || "MLKEM1024-P384")
ct   = ct_PQ || ct_T                     # 1568 + 97 = 1665
return (ss, ct)
```

**Decaps(dk, ct)** expands `dk` via DeriveKeyPair expansion, splits `ct`,
computes `ss_PQ` and `ss_T`, and applies the same combiner.

P-384 points MUST be uncompressed SEC1 encodings (0x04 || X || Y). Points
MUST be validated on-curve and MUST NOT be the point at infinity / identity.

### HPKE SealBase / OpenBase

Suite: KEM `0x0051`, KDF `0x0003`, AEAD `0x0003`.

```
info = "secreto/v1/mlkem1024p384"
aad  = empty
pt   = file_key   # 32 bytes
```

Key schedule, Seal, and Open follow RFC 9180 Base mode. The AEAD nonce for
sealing the file key is the HPKE base_nonce (not a fixed zero nonce).

Decryption MUST check body length == 48 before OpenBase (partitioning
oracle mitigation).

## Recipient type: argon2id

### Stanza

```
-> argon2id <base64(salt)> <m_kib> <t> <p>
<body: exactly 48 bytes>
```

- `salt` is 16 random bytes, fresh per stanza/file.
- `m_kib`, `t`, `p` are canonical decimal integers (no leading zeros;
  regex `^[1-9][0-9]*$`).

Encryption MUST use `t=3`, `p=4`, and an `m_kib` inside the decryption
acceptance range `[65536, 4194304]`. The default is `m_kib=65536`
(64 MiB). Implementations MAY expose a way to choose a higher `m_kib`
within that range (for example `1048576` for 1 GiB).

```
wrap_key = Argon2id(
  P = passphrase,
  S = "secreto/v1/argon2id" || salt,
  m = m_kib, t = t, p = p,
  tagLength = 32
)
body = ChaCha20-Poly1305(
  key = wrap_key,
  nonce = 12 zero bytes,
  plaintext = file_key
)
```

### Mixing rule

If an `argon2id` stanza is present it MUST be the only stanza. Headers that
mix argon2id with any other stanza MUST be rejected (exit 4).

### Decryption parameter limits

Reject (exit 4) if `m_kib` ∉ [65536, 4194304], `t` ∉ [3, 16], or
`p` ∉ [1, 16], or any number is non-canonical.

Body length MUST be exactly 48 before attempting AEAD decrypt.

## Payload

Immediately after the header:

```
nonce (16 bytes) || STREAM ciphertext
```

```
payload_key = HKDF-SHA-512(
  ikm  = file_key,
  salt = nonce,
  info = "secreto/v1/payload",
  L    = 32
)
```

STREAM (age variant): plaintext is split into chunks of 65536 bytes. Each
chunk is encrypted with ChaCha20-Poly1305 using `payload_key` and a 12-byte
nonce:

```
nonce = big_endian_u88(counter) || flag
flag  = 0x00 for non-final chunks, 0x01 for the final chunk
```

The final chunk MAY be shorter than 65536 but MUST NOT be empty unless the
whole STREAM plaintext is empty. In secreto/v1 the STREAM plaintext is the
**inner plaintext**, which is always at least 2 bytes (`flags || 0x80`), so
an empty final chunk MUST always be rejected.

Streaming decryption MUST error if EOF is reached without a verified final
chunk. No plaintext chunk MAY be released before its tag verifies.

## Inner plaintext

```
inner = flags (1 byte) || content || 0x80 || 0x00*k || [sigblock]
```

### Flags

| Value | Meaning |
|-------|---------|
| `0x00` | unsigned |
| `0x01` | signed (sigblock present) |

Any other flag MUST be rejected (exit 4).

### Padding

The terminator `0x80` is always present. Without `--pad`, `k = 0`.

With `--pad`, let `L` be the length of `flags || content || 0x80` plus the
sigblock length if signed (i.e. the full unpadded inner length including
terminator and optional sigblock). Then `k = Padmé(L) - L` zero bytes are
inserted **immediately after** `0x80` and **before** the sigblock when
signed.

**Padmé(L)** for `L ≥ 1`:

```
E = floor(log2(L))
S = floor(floor(log2(E)) / 2)          # for E >= 1; if E == 0, S = 0
mask = (1 << (E - S)) - 1
return (L + mask) & ~mask
```

For `L = 0`, Padmé(0) = 0 (unused; secreto never pads an empty inner).

When unsigned: unpadded length `L = 1 + |content| + 1`.
When signed: unpadded length `L = 1 + |content| + 1 + 4723`.

Decryption MUST strip a trailing `0x80 || 0x00*` run from the STREAM
plaintext before the fixed-size sigblock (if flags say signed). Invalid
padding (no `0x80` found in the held-back region) MUST be rejected.

### Signature block (4723 bytes)

Present iff `flags == 0x01`:

```
sigblock = signer_id (32) || ed25519_sig (64) || mldsa87_sig (4627)
```

```
signer_id = SHA-512("secreto/v1/signer-id" || pk_bytes)[:32]
pk_bytes  = ed25519_pk (32) || mldsa87_pk (2592)   # 2624 bytes
```

Signature message:

```
msg = "secreto/v1/signature"
   || header_mac (64)
   || content_len as u64 big-endian (8)
   || SHA-512(content) (64)
```

Both Ed25519 and ML-DSA-87 MUST verify over `msg`. ML-DSA-87 uses an empty
context string. If either fails, reject (exit 5 when `--verify` was used;
exit 4 if the file claims to be signed but the block is truncated).

## ASCII armor

Optional PEM encoding per RFC 7468 §3, label `SECRETO ENCRYPTED FILE`.

Implementations MUST reject non-canonical armor (except optional surrounding
whitespace), MUST reject data before/after the PEM block (aside from
whitespace), and MAY accept both LF and CRLF inside the armor.

## Decryption order of checks

1. Detect armor; decode if present.
2. Parse header (version, stanzas, MAC line); enforce limits.
3. Attempt to unwrap file key from matching stanzas / passphrase.
4. If no file key: exit 3.
5. Verify header MAC; on failure exit 4.
6. Decrypt STREAM payload; on failure exit 4.
7. Parse inner plaintext (flags, padding, optional sigblock).
8. If `--verify`: verify signatures; on failure exit 5. Do not release
   content before verification succeeds.
9. If signed and `--verify` not set: release content and warn on stderr.
10. Write content.

All AEAD / MAC comparisons MUST be constant-time. Stanza unwrap failures
MUST be indistinguishable (same exit path toward "no match" until MAC).

## Test kit file layout

Files under `vectors/testkit/` begin with metadata lines, a blank line, then
the ciphertext (raw or armored):

```
expect: success | no-match | header-failure | payload-failure | signature-failure
identity: <bech32>          # optional, repeatable
passphrase: <string>        # optional
verify: <bech32 secretosig> # optional
payload: <hex of expected content>
armored: yes                # optional
<blank line>
<file bytes>
```
