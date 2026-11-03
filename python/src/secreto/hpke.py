# SPDX-FileCopyrightText: 2026 secreto contributors
# SPDX-License-Identifier: EUPL-1.2

"""HPKE (RFC 9180) Base-mode Seal/Open for MLKEM1024-P384 / HKDF-SHA512 / ChaCha20Poly1305."""

from __future__ import annotations

import hashlib
import hmac

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from . import kem
from .error import FormatError

KEM_ID = 0x0051
KDF_ID = 0x0003
AEAD_ID = 0x0003
INFO = b"secreto/v1/mlkem1024p384"
NK = 32
NN = 12
NH = 64
MODE_BASE = 0


def suite_id(kem_id: int = KEM_ID, kdf_id: int = KDF_ID, aead_id: int = AEAD_ID) -> bytes:
    return b"HPKE" + kem_id.to_bytes(2, "big") + kdf_id.to_bytes(2, "big") + aead_id.to_bytes(2, "big")


def _extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or b"\x00" * NH, ikm, hashlib.sha512).digest()


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    t = b""
    i = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha512).digest()
        out += t
        i += 1
    return out[:length]


def labeled_extract(sid: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return _extract(salt, b"HPKE-v1" + sid + label + ikm)


def labeled_expand(sid: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    return _expand(prk, length.to_bytes(2, "big") + b"HPKE-v1" + sid + label + info, length)


def key_schedule(
    shared_secret: bytes,
    info: bytes = INFO,
    sid: bytes | None = None,
    mode: int = MODE_BASE,
    nk: int = NK,
    nn: int = NN,
) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    """Base-mode key schedule; returns ``(key, base_nonce, exporter_secret, secret, context)``."""
    sid = sid if sid is not None else suite_id()
    psk_id_hash = labeled_extract(sid, b"", b"psk_id_hash", b"")
    info_hash = labeled_extract(sid, b"", b"info_hash", info)
    context = bytes([mode]) + psk_id_hash + info_hash
    secret = labeled_extract(sid, shared_secret, b"secret", b"")
    key = labeled_expand(sid, secret, b"key", context, nk)
    base_nonce = labeled_expand(sid, secret, b"base_nonce", context, nn)
    exporter = labeled_expand(sid, secret, b"exp", context, NH)
    return key, base_nonce, exporter, secret, context


def seal_base(ek: bytes, plaintext: bytes, info: bytes = INFO, aad: bytes = b"") -> tuple[bytes, bytes]:
    """SealBase: returns ``(enc, ciphertext)``."""
    shared, enc = kem.encaps(ek)
    key, nonce, *_ = key_schedule(shared, info)
    return enc, ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad or None)


def open_base(
    dk: kem.ExpandedKey | bytes, enc: bytes, ciphertext: bytes, info: bytes = INFO, aad: bytes = b""
) -> bytes:
    """OpenBase; raises :class:`FormatError` on any failure."""
    shared = kem.decaps(dk, enc)
    key, nonce, *_ = key_schedule(shared, info)
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad or None)
    except InvalidTag:
        raise FormatError("HPKE open failed") from None
