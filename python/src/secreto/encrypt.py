# SPDX-FileCopyrightText: 2026 secreto contributors
# SPDX-License-Identifier: EUPL-1.2

"""Encryption (spec/format.md)."""

from __future__ import annotations

import base64
import hashlib
import os
from collections.abc import Sequence
from typing import Any, BinaryIO

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from . import argon, armor, header, hpke, inner, padme, stream
from .error import FormatError, InvalidKeyError
from .header import Stanza
from .keys import Recipient
from .sign import SigningKey, signature_message_hashed

STANZA_MLKEM = "mlkem1024p384"


def _mlkem_stanza(recipient: Recipient, file_key: bytes) -> Stanza:
    enc, ct = hpke.seal_base(recipient.ek, file_key)
    return Stanza([STANZA_MLKEM, header.b64_encode(enc)], ct)


def _build_stanzas(
    file_key: bytes,
    recipients: Sequence[Recipient] | None,
    passphrase: bytes | None,
    m_kib: int,
    t: int,
    p: int,
) -> list[Stanza]:
    if (passphrase is None) == (not recipients):
        raise InvalidKeyError("provide either recipients or a passphrase")
    if recipients and len(recipients) > header.MAX_STANZAS:
        raise InvalidKeyError("too many recipients")
    if passphrase is not None:
        return [argon.wrap(passphrase, file_key, m_kib=m_kib, t=t, p=p)]
    return [_mlkem_stanza(r, file_key) for r in recipients or ()]


def encrypt(
    content: bytes,
    recipients: Sequence[Recipient] | None = None,
    passphrase: bytes | None = None,
    pad: bool = False,
    signer: SigningKey | None = None,
    m_kib: int = argon.DEFAULT_M,
    t: int = argon.DEFAULT_T,
    p: int = argon.DEFAULT_P,
) -> bytes:
    """Encrypt ``content`` to recipients XOR a passphrase; returns binary ciphertext."""
    file_key = os.urandom(32)
    stanzas = _build_stanzas(file_key, recipients, passphrase, m_kib, t, p)
    hdr, mac = header.serialize(stanzas, file_key)
    sigblock = signer.sign(mac, content) if signer is not None else None
    plain = inner.build(content, sigblock, pad)
    nonce = os.urandom(stream.NONCE_LEN)
    key = stream.payload_key(file_key, nonce)
    return hdr + nonce + stream.encrypt(key, plain)


def encrypt_armored(content: bytes, **kwargs: Any) -> bytes:
    return armor.encode(encrypt(content, **kwargs))


class _ArmorWriter:
    """Streaming PEM writer emitting 64-column Base64 lines."""

    def __init__(self, out: BinaryIO) -> None:
        self._out = out
        self._pending = bytearray()
        self._started = False

    def write(self, data: bytes) -> int:
        if not self._started:
            self._out.write(armor.BEGIN.encode("ascii") + b"\n")
            self._started = True
        self._pending.extend(data)
        while len(self._pending) >= 48:
            line = base64.b64encode(bytes(self._pending[:48])).decode("ascii")
            self._out.write(line.encode("ascii") + b"\n")
            del self._pending[:48]
        return len(data)

    def finish(self) -> None:
        if not self._started:
            self._out.write(armor.BEGIN.encode("ascii") + b"\n")
            self._started = True
        if self._pending:
            line = base64.b64encode(bytes(self._pending)).decode("ascii")
            self._out.write(line.encode("ascii") + b"\n")
            self._pending.clear()
        self._out.write(armor.END.encode("ascii") + b"\n")


def encrypt_to(
    reader: BinaryIO,
    writer: BinaryIO,
    recipients: Sequence[Recipient] | None = None,
    passphrase: bytes | None = None,
    pad: bool = False,
    signer: SigningKey | None = None,
    m_kib: int = argon.DEFAULT_M,
    t: int = argon.DEFAULT_T,
    p: int = argon.DEFAULT_P,
    armored: bool = False,
) -> None:
    """Encrypt plaintext from ``reader`` into ``writer`` (binary or armored)."""
    out: Any = _ArmorWriter(writer) if armored else writer
    file_key = os.urandom(32)
    stanzas = _build_stanzas(file_key, recipients, passphrase, m_kib, t, p)
    hdr, mac = header.serialize(stanzas, file_key)
    out.write(hdr)

    nonce = os.urandom(stream.NONCE_LEN)
    out.write(nonce)
    key = stream.payload_key(file_key, nonce)
    aead = ChaCha20Poly1305(key)

    signed = signer is not None
    buf = bytearray([inner.FLAG_SIGNED if signed else inner.FLAG_UNSIGNED])
    hasher = hashlib.sha512()
    content_len = 0
    counter = 0

    def flush_full() -> None:
        nonlocal counter
        while len(buf) >= stream.CHUNK:
            chunk = bytes(buf[: stream.CHUNK])
            del buf[: stream.CHUNK]
            out.write(aead.encrypt(stream.chunk_nonce(counter, False), chunk, None))
            counter += 1

    while True:
        block = reader.read(8192)
        if not block:
            break
        hasher.update(block)
        content_len += len(block)
        buf.extend(block)
        flush_full()

    sigblock = None
    if signer is not None:
        msg = signature_message_hashed(mac, content_len, hasher.digest())
        sigblock = signer.sign_msg(msg)

    unpadded = 1 + content_len + 1 + (len(sigblock) if sigblock else 0)
    k = padme.padding_len(unpadded) if pad else 0
    buf.append(0x80)
    buf.extend(b"\x00" * k)
    if sigblock:
        buf.extend(sigblock)

    flush_full()
    if not buf:
        raise FormatError("empty STREAM plaintext")
    out.write(aead.encrypt(stream.chunk_nonce(counter, True), bytes(buf), None))
    if armored:
        out.finish()
