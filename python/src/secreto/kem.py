# SPDX-FileCopyrightText: 2026 secreto contributors
# SPDX-License-Identifier: EUPL-1.2

"""MLKEM1024-P384 hybrid KEM (CG framework, draft-irtf-cfrg-concrete-hybrid-kems-04)."""

from __future__ import annotations

import hashlib
import os

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM1024PrivateKey,
    MLKEM1024PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import _mlkem_ref
from .error import FormatError, InvalidKeyError

SEED_LEN = 32
SEED_PQ_LEN = 64
SEED_T_LEN = 48
EK_PQ_LEN = 1568
EK_T_LEN = 97
EK_LEN = EK_PQ_LEN + EK_T_LEN  # 1665
CT_LEN = EK_LEN
SS_LEN = 32
LABEL = b"MLKEM1024-P384"
P384_ORDER = int(
    "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
    "581a0db248b0a77aecec196accc52973",
    16,
)
_CURVE = ec.SECP384R1()


def _shake256(data: bytes, n: int) -> bytes:
    return hashlib.shake_256(data).digest(n)


def _scalar_from_block(block: bytes) -> int | None:
    sk = int.from_bytes(block, "big")
    return sk if 0 < sk < P384_ORDER else None


def random_scalar(seed: bytes) -> int:
    """RandomScalar_P384 for a 48-byte seed.

    A rejected block (probability < 2^-190) is extended with
    ``SHAKE256(seed || counter)[0:48]`` using a one-byte counter from 1.
    """
    if len(seed) != SEED_T_LEN:
        raise ValueError("P-384 seed must be 48 bytes")
    s = _scalar_from_block(seed)
    if s is not None:
        return s
    for counter in range(1, 256):
        s = _scalar_from_block(_shake256(seed + bytes([counter]), SEED_T_LEN))
        if s is not None:
            return s
    raise InvalidKeyError("P-384 scalar derivation failed")


def _p384_priv(scalar: int) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(scalar, _CURVE)


def _point_bytes(pub: ec.EllipticCurvePublicKey) -> bytes:
    return pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def parse_point(data: bytes) -> ec.EllipticCurvePublicKey:
    """Parse an uncompressed SEC1 P-384 point; validates on-curve, non-identity."""
    if len(data) != EK_T_LEN or data[0] != 0x04:
        raise FormatError("invalid P-384 point encoding")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, bytes(data))
    except ValueError:
        raise FormatError("invalid P-384 point") from None


def generate_seed() -> bytes:
    return os.urandom(SEED_LEN)


class ExpandedKey:
    """Expanded decapsulation key derived from a 32-byte seed."""

    __slots__ = ("pq", "t", "ek_pq", "ek_t")

    def __init__(self, seed: bytes):
        if len(seed) != SEED_LEN:
            raise InvalidKeyError("seed must be 32 bytes")
        full = _shake256(seed, SEED_PQ_LEN + SEED_T_LEN)
        seed_pq, seed_t = full[:SEED_PQ_LEN], full[SEED_PQ_LEN:]
        self.pq = MLKEM1024PrivateKey.from_seed_bytes(seed_pq)
        self.ek_pq = self.pq.public_key().public_bytes_raw()
        self.t = _p384_priv(random_scalar(seed_t))
        self.ek_t = _point_bytes(self.t.public_key())

    @property
    def ek(self) -> bytes:
        return self.ek_pq + self.ek_t


def derive_key_pair(seed: bytes) -> tuple[ExpandedKey, bytes]:
    """DeriveKeyPair: returns ``(expanded dk, ek)``."""
    k = ExpandedKey(seed)
    return k, k.ek


def validate_ek(ek: bytes) -> None:
    """Check encapsulation-key length and component validity."""
    if len(ek) != EK_LEN:
        raise InvalidKeyError("invalid encapsulation key length")
    try:
        MLKEM1024PublicKey.from_public_bytes(bytes(ek[:EK_PQ_LEN]))
        parse_point(ek[EK_PQ_LEN:])
    except (ValueError, FormatError):
        raise InvalidKeyError("invalid encapsulation key") from None


def combiner(ss_pq: bytes, ss_t: bytes, ct_t: bytes, ek_t: bytes) -> bytes:
    return hashlib.sha3_256(ss_pq + ss_t + ct_t + ek_t + LABEL).digest()


def _encaps_with(ek: bytes, ss_pq: bytes, ct_pq: bytes, seed_t: bytes) -> tuple[bytes, bytes]:
    ek_t = ek[EK_PQ_LEN:]
    peer = parse_point(ek_t)
    sk_e = _p384_priv(random_scalar(seed_t))
    ct_t = _point_bytes(sk_e.public_key())
    ss_t = sk_e.exchange(ec.ECDH(), peer)
    return combiner(ss_pq, ss_t, ct_t, ek_t), ct_pq + ct_t


def encaps(ek: bytes) -> tuple[bytes, bytes]:
    """Encaps(ek) -> ``(shared_secret, ciphertext)``."""
    if len(ek) != EK_LEN:
        raise InvalidKeyError("invalid encapsulation key length")
    try:
        pk = MLKEM1024PublicKey.from_public_bytes(bytes(ek[:EK_PQ_LEN]))
    except ValueError:
        raise InvalidKeyError("invalid ML-KEM encapsulation key") from None
    ss_pq, ct_pq = pk.encapsulate()
    return _encaps_with(ek, ss_pq, ct_pq, os.urandom(SEED_T_LEN))


def encaps_derand(ek: bytes, randomness: bytes) -> tuple[bytes, bytes]:
    """EncapsDerand: ``randomness = mlkem_m (32) || p384_seed (48)``."""
    if len(ek) != EK_LEN or len(randomness) != 32 + SEED_T_LEN:
        raise InvalidKeyError("invalid encaps input length")
    ss_pq, ct_pq = _mlkem_ref.encaps_derand(ek[:EK_PQ_LEN], randomness[:32])
    return _encaps_with(ek, ss_pq, ct_pq, randomness[32:])


def decaps(dk: ExpandedKey | bytes, ct: bytes) -> bytes:
    """Decaps; ``dk`` is an :class:`ExpandedKey` or a 32-byte seed."""
    if isinstance(dk, (bytes, bytearray)):
        dk = ExpandedKey(bytes(dk))
    if len(ct) != CT_LEN:
        raise FormatError("invalid ciphertext length")
    ct_pq, ct_t = ct[:EK_PQ_LEN], ct[EK_PQ_LEN:]
    peer = parse_point(ct_t)
    try:
        ss_pq = dk.pq.decapsulate(bytes(ct_pq))
        ss_t = dk.t.exchange(ec.ECDH(), peer)
    except (ValueError, InvalidKey):
        raise FormatError("decapsulation failed") from None
    return combiner(ss_pq, ss_t, ct_t, dk.ek_t)
