<!--
SPDX-FileCopyrightText: 2026 secreto contributors
SPDX-License-Identifier: EUPL-1.2
-->

# secreto

File encryption with authenticated encryption, hybrid post-quantum key
exchange, and three independent implementations (Rust, Python, C++) that
interoperate byte-for-byte on `secreto/v1`.

## Algorithms (`secreto/v1`)

| Role | Algorithm |
|------|-----------|
| Key exchange | MLKEM1024-P384 (hybrid PQ/T HPKE KEM `0x0051`) |
| Passphrase | Argon2id (`m=1 GiB`, `t=3`, `p=4` on encrypt) |
| Payload AEAD | ChaCha20-Poly1305 (256-bit file key, STREAM 64 KiB chunks) |
| KDF / MAC | HKDF-SHA-512 / HMAC-SHA-512 |
| Signatures (optional) | Ed25519 + ML-DSA-87 hybrid |

Age v1 and weaker algorithms (X25519-only, X-Wing / MLKEM768-X25519, scrypt,
SHA-256 KDFs, ML-DSA-65) are intentionally unsupported. See
[spec/format.md](spec/format.md), [spec/cli.md](spec/cli.md), and
[spec/registry.md](spec/registry.md). Draft pins are in
[spec/references.md](spec/references.md).

## Layout

```
spec/          normative format + CLI
vectors/       component JSON + whole-file testkit (203 files)
rust/          reference implementation (secreto-core, CLI, vector generator)
python/        independent Python implementation
cpp/           independent C++20 / OpenSSL 3.5 implementation
interop/       3×3 cross-language harness
```

## Build

Requirements: Rust 1.88+, Python 3.11+, CMake 3.20+, OpenSSL 3.5+, g++.

```bash
make build
```

Binaries:

| Impl | `secreto` | `secreto-keygen` |
|------|-----------|------------------|
| Rust | `rust/target/release/secreto` | `rust/target/release/secreto-keygen` |
| Python | `python/.venv/bin/secreto` | `python/.venv/bin/secreto-keygen` |
| C++ | `cpp/build/secreto` | `cpp/build/secreto-keygen` |

## Packages (Linux)

Build and install the Rust CLI as a system package (needs `cargo-deb` /
`cargo-generate-rpm`, plus `sudo`):

```bash
make package-deb          # → rust/target/debian/secreto_*.deb
make package-rpm          # → rust/target/generate-rpm/secreto-*.rpm
make install-deb          # build + dpkg -i
make install-rpm          # build + dnf/yum/zypper/rpm -Uvh
make uninstall-deb
make uninstall-rpm
make reinstall-deb
make reinstall-rpm
```

`make install` / `uninstall` / `reinstall` pick `.deb` or `.rpm` from the host.

## Usage

```bash
secreto-keygen -o key.txt                 # identity; recipient on stderr
secreto-keygen -y key.txt > recipient.txt
secreto -e -r "$(cat recipient.txt)" -o secret.sec message.txt
secreto -d -i key.txt -o message.out secret.sec

# Optional: armor, Padmé padding, hybrid signatures
secreto-keygen --signing -o sign.key
secreto-keygen --signing -y sign.key > signer.pub
secreto -e -r "$(cat recipient.txt)" --sign sign.key --pad -a -o secret.asc message.txt
secreto -d -i key.txt --verify "$(cat signer.pub)" -o message.out secret.asc
```

Passphrases: `-p` (read from `/dev/tty`, or from
`SECRETO_PASSPHRASE_FD`). Encrypt uses Argon2id with 1 GiB memory.

Exit codes: `0` ok, `1` usage/key, `2` I/O, `3` no match, `4` format/auth,
`5` signature.

## Test

```bash
make check    # unit tests + vectors-check + interop + C++ ASan/UBSan
```

Individual targets: `make test`, `make vectors-check`, `make interop`,
`make test-cpp-asan`.

## Security notes

- The Rust `ml-kem` and `ml-dsa` crates have not been independently audited.
- MLKEM1024-P384 is specified by IRTF CFRG drafts that may still change;
  `secreto/v1` pins concrete draft versions in `spec/references.md`.
- Forward secrecy covers the sender side only (fresh ephemeral per stanza).
- Decrypting a signed file without `--verify` still releases plaintext and
  prints a warning naming the signer ID.
- Passphrase encryption intentionally costs ~1 GiB RAM; decryption accepts
  a bounded parameter range to resist DoS while rejecting weak files.

## License

Copyright 2026 secreto contributors.

Licensed under the EUPL (European Union Public Licence), version 1.2.
See [LICENSE](LICENSE). Source files carry `SPDX-License-Identifier: EUPL-1.2`.
