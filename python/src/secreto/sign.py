"""Hybrid Ed25519 + ML-DSA-87 signatures (spec/format.md, *Signature block*)."""

from __future__ import annotations

import hashlib
import os
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.mldsa import (
    MLDSA87PrivateKey,
    MLDSA87PublicKey,
)

from .error import InvalidKeyError, SignatureError

ED_PK_LEN = 32
MLDSA_PK_LEN = 2592
PK_LEN = ED_PK_LEN + MLDSA_PK_LEN  # 2624
SK_LEN = 64  # ed25519 seed (32) || ml-dsa-87 seed (32)
ED_SIG_LEN = 64
MLDSA_SIG_LEN = 4627
SIGNER_ID_LEN = 32
SIGBLOCK_LEN = SIGNER_ID_LEN + ED_SIG_LEN + MLDSA_SIG_LEN  # 4723
_MSG_LABEL = b"secreto/v1/signature"
_ID_LABEL = b"secreto/v1/signer-id"


def signer_id(pk_bytes: bytes) -> bytes:
    return hashlib.sha512(_ID_LABEL + pk_bytes).digest()[:SIGNER_ID_LEN]


def signature_message(header_mac: bytes, content: bytes) -> bytes:
    return (
        _MSG_LABEL
        + header_mac
        + struct.pack(">Q", len(content))
        + hashlib.sha512(content).digest()
    )


class SignerPublicKey:
    def __init__(self, pk_bytes: bytes):
        pk_bytes = bytes(pk_bytes)
        if len(pk_bytes) != PK_LEN:
            raise InvalidKeyError("invalid signer public key length")
        try:
            self._ed = Ed25519PublicKey.from_public_bytes(pk_bytes[:ED_PK_LEN])
            self._ml = MLDSA87PublicKey.from_public_bytes(pk_bytes[ED_PK_LEN:])
        except ValueError:
            raise InvalidKeyError("invalid signer public key") from None
        self.pk_bytes = pk_bytes

    @property
    def signer_id(self) -> bytes:
        return signer_id(self.pk_bytes)

    def verify(self, sigblock: bytes, msg: bytes) -> None:
        """Raise :class:`SignatureError` unless both signatures verify."""
        if len(sigblock) != SIGBLOCK_LEN:
            raise SignatureError("malformed signature block")
        if sigblock[:SIGNER_ID_LEN] != self.signer_id:
            raise SignatureError("signature from a different signer")
        ed_sig = sigblock[SIGNER_ID_LEN : SIGNER_ID_LEN + ED_SIG_LEN]
        ml_sig = sigblock[SIGNER_ID_LEN + ED_SIG_LEN :]
        try:
            self._ed.verify(ed_sig, msg)
            ed_ok = True
        except InvalidSignature:
            ed_ok = False
        try:
            self._ml.verify(ml_sig, msg, b"")
            ml_ok = True
        except (InvalidSignature, ValueError):
            ml_ok = False
        if not (ed_ok and ml_ok):
            raise SignatureError("signature verification failed")

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SignerPublicKey) and self.pk_bytes == other.pk_bytes

    def __hash__(self) -> int:
        return hash(self.pk_bytes)


class SigningKey:
    def __init__(self, sk_bytes: bytes):
        sk_bytes = bytes(sk_bytes)
        if len(sk_bytes) != SK_LEN:
            raise InvalidKeyError("invalid signing key length")
        self.sk_bytes = sk_bytes
        self._ed = Ed25519PrivateKey.from_private_bytes(sk_bytes[:32])
        self._ml = MLDSA87PrivateKey.from_seed_bytes(sk_bytes[32:])

    @classmethod
    def generate(cls) -> "SigningKey":
        return cls(os.urandom(SK_LEN))

    def public_key(self) -> SignerPublicKey:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        ed_pk = self._ed.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return SignerPublicKey(ed_pk + self._ml.public_key().public_bytes_raw())

    def sign(self, header_mac: bytes, content: bytes) -> bytes:
        """Return the 4723-byte signature block over ``content``."""
        msg = signature_message(header_mac, content)
        pk = self.public_key()
        block = pk.signer_id + self._ed.sign(msg) + self._ml.sign(msg, b"")
        assert len(block) == SIGBLOCK_LEN
        return block
