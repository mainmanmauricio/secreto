<!--
SPDX-FileCopyrightText: 2026 secreto contributors
SPDX-License-Identifier: EUPL-1.2
-->

# Algorithm registry (secreto/v1)

Only the identifiers listed here are valid in secreto/v1. Implementations
MUST reject any other stanza type as unrecognized (skip for decryption
matching) or reject the file when the type is required and missing.

## Stanza types

| First argument | Meaning |
|----------------|---------|
| `mlkem1024p384` | HPKE SealBase wrapping of the file key |
| `argon2id` | Argon2id wrapping of the file key |

## HPKE suite (for `mlkem1024p384`)

| Parameter | Value |
|-----------|-------|
| KEM | `0x0051` MLKEM1024-P384 |
| KDF | `0x0003` HKDF-SHA512 |
| AEAD | `0x0003` ChaCha20Poly1305 |
| mode | Base (0) |
| info | `secreto/v1/mlkem1024p384` |
| aad | empty |

## Hybrid KEM constants (MLKEM1024-P384)

| Constant | Value |
|----------|-------|
| Nseed | 32 |
| Ndk | 32 |
| Nek | 1665 |
| Nct | 1665 |
| Nss | 32 |
| Label | ASCII `MLKEM1024-P384` |
| PRG | SHAKE256 |
| Combiner KDF | SHA3-256 |
| Framework | CG (C2PRI + nominal group) |
| PQ component | ML-KEM-1024 (Nseed=64, Nek=1568, Nct=1568, Nss=32) |
| T component | P-384 (Nseed=48, Nscalar=48, Nelem=97, Nss=48) |

## Argon2id (encryption defaults)

| Parameter | Value |
|-----------|-------|
| m (KiB) | 65536 (default; encryptors MAY choose any value in the decrypt range) |
| t | 3 |
| p | 4 |
| output length | 32 |
| salt length | 16 |

### Decryption acceptance ranges

| Parameter | Min | Max |
|-----------|-----|-----|
| m (KiB) | 65536 | 4194304 |
| t | 3 | 16 |
| p | 1 | 16 |

## Symmetric

| Role | Algorithm | Output size |
|------|-----------|-------------|
| File key | CSPRNG | 32 |
| Header MAC key | HKDF-SHA-512 | 64 |
| Header MAC | HMAC-SHA-512 | 64 |
| Payload key | HKDF-SHA-512 | 32 |
| Payload AEAD | ChaCha20-Poly1305 | — |
| Chunk size | STREAM | 65536 plaintext bytes |

## Signatures

| Component | Algorithm | Size |
|-----------|-----------|------|
| signer_id | SHA-512 prefix | 32 |
| Ed25519 signature | Ed25519 | 64 |
| ML-DSA-87 signature | ML-DSA-87 (empty context) | 4627 |
| Total sigblock | — | 4723 |

## Bech32 HRPs

| Object | HRP | Case | Data bytes |
|--------|-----|------|------------|
| Recipient | `secreto` | lowercase | 1665 |
| Identity | `SECRETO-SECRET-KEY-` | uppercase | 32 |
| Signing secret | `SECRETO-SIGNING-KEY-` | uppercase | 64 |
| Signer public | `secretosig` | lowercase | 2624 |

## Version and armor

| Item | Value |
|------|-------|
| Version line | `secreto/v1` |
| Armor label | `SECRETO ENCRYPTED FILE` |

## Domain-separation labels

| Label | Use |
|-------|-----|
| `secreto/v1/header` | HKDF info for header MAC key |
| `secreto/v1/payload` | HKDF info for payload key |
| `secreto/v1/mlkem1024p384` | HPKE info |
| `secreto/v1/argon2id` | Argon2id salt prefix |
| `secreto/v1/signature` | Signature message prefix |
| `secreto/v1/signer-id` | Signer ID hash prefix |
