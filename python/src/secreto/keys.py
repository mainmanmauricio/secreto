# SPDX-FileCopyrightText: 2026 secreto contributors
# SPDX-License-Identifier: EUPL-1.2

"""Key types and their Bech32 encodings (spec/registry.md, *Bech32 HRPs*)."""

from __future__ import annotations

from . import bech32, kem
from .error import InvalidKeyError
from .sign import PK_LEN, SK_LEN, SignerPublicKey, SigningKey

HRP_RECIPIENT = "secreto"
HRP_IDENTITY = "SECRETO-SECRET-KEY-"
HRP_SIGNING_KEY = "SECRETO-SIGNING-KEY-"
HRP_SIGNER_PUBLIC = "secretosig"


class Identity:
    """32-byte MLKEM1024-P384 seed."""

    def __init__(self, seed: bytes):
        if len(seed) != kem.SEED_LEN:
            raise InvalidKeyError("identity seed must be 32 bytes")
        self.seed = bytes(seed)
        self._expanded: kem.ExpandedKey | None = None

    def __repr__(self) -> str:
        return "Identity(..)"

    @classmethod
    def generate(cls) -> "Identity":
        return cls(kem.generate_seed())

    @property
    def expanded(self) -> kem.ExpandedKey:
        if self._expanded is None:
            self._expanded = kem.ExpandedKey(self.seed)
        return self._expanded

    def to_bech32(self) -> str:
        return bech32.encode(HRP_IDENTITY, self.seed)

    @classmethod
    def from_bech32(cls, s: str) -> "Identity":
        return cls(bech32.decode_exact(s, HRP_IDENTITY, kem.SEED_LEN))

    def recipient(self) -> "Recipient":
        return Recipient(self.expanded.ek)


class Recipient:
    """1665-byte MLKEM1024-P384 encapsulation key."""

    def __init__(self, ek: bytes):
        kem.validate_ek(bytes(ek))
        self.ek = bytes(ek)

    def __repr__(self) -> str:
        return f"Recipient({self.to_bech32()[:16]}..)"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Recipient) and self.ek == other.ek

    def __hash__(self) -> int:
        return hash(self.ek)

    def to_bech32(self) -> str:
        return bech32.encode(HRP_RECIPIENT, self.ek)

    @classmethod
    def from_bech32(cls, s: str) -> "Recipient":
        return cls(bech32.decode_exact(s, HRP_RECIPIENT, kem.EK_LEN))


def signing_key_to_bech32(sk: SigningKey) -> str:
    return bech32.encode(HRP_SIGNING_KEY, sk.sk_bytes)


def signing_key_from_bech32(s: str) -> SigningKey:
    return SigningKey(bech32.decode_exact(s, HRP_SIGNING_KEY, SK_LEN))


def signer_public_to_bech32(pk: SignerPublicKey) -> str:
    return bech32.encode(HRP_SIGNER_PUBLIC, pk.pk_bytes)


def signer_public_from_bech32(s: str) -> SignerPublicKey:
    return SignerPublicKey(bech32.decode_exact(s, HRP_SIGNER_PUBLIC, PK_LEN))


def _key_lines(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def parse_recipients(text: str) -> list[Recipient]:
    v = [Recipient.from_bech32(ln) for ln in _key_lines(text)]
    if not v:
        raise InvalidKeyError("no recipients found")
    return v


def parse_identities(text: str) -> list[Identity]:
    v = [Identity.from_bech32(ln) for ln in _key_lines(text)]
    if not v:
        raise InvalidKeyError("no identities found")
    return v


def parse_signing_key(text: str) -> SigningKey:
    lines = _key_lines(text)
    if not lines:
        raise InvalidKeyError("no signing key found")
    if len(lines) > 1:
        raise InvalidKeyError("multiple signing keys in file")
    return signing_key_from_bech32(lines[0])
