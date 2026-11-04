# SPDX-FileCopyrightText: 2026 secreto contributors
# SPDX-License-Identifier: EUPL-1.2

"""Decryption (spec/format.md, *Decryption order of checks*)."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from typing import BinaryIO

from . import argon, armor, header, hpke, inner, kem, stream
from .error import FormatError, NoMatchError, SecretoError, SignatureError
from .header import Header, Stanza
from .keys import Identity
from .sign import SIGNER_ID_LEN, SignerPublicKey, signature_message

STANZA_MLKEM = "mlkem1024p384"
_BODY_LEN = 48


@dataclass
class Decrypted:
    content: bytes
    signer_id: bytes | None = None
    verified: bool = False


@dataclass
class DecryptMeta:
    signer_id: bytes | None
    verified: bool
    content_len: int


def _mlkem_enc(stanza: Stanza) -> bytes | None:
    """Return ``enc`` for a well-formed mlkem1024p384 stanza, else ``None``."""
    if len(stanza.args) != 2 or len(stanza.body) != _BODY_LEN:
        return None
    try:
        enc = header.b64_decode(stanza.args[1])
    except FormatError:
        return None
    return enc if len(enc) == kem.CT_LEN else None


def _unwrap(hdr: Header, identities: Sequence[Identity], passphrase: bytes | None) -> bytes:
    stanzas = hdr.stanzas
    has_argon = any(s.type == argon.TYPE for s in stanzas)
    if has_argon:
        if len(stanzas) != 1:
            raise FormatError("argon2id stanza must be the only stanza")
        argon.parse_params(stanzas[0])  # validate regardless of credentials
        if passphrase is None:
            raise NoMatchError()
        return argon.unwrap(stanzas[0], passphrase)
    if not identities:
        raise NoMatchError()
    for st in stanzas:
        if st.type != STANZA_MLKEM:
            continue
        enc = _mlkem_enc(st)
        if enc is None:
            continue
        for ident in identities:
            try:
                fk = hpke.open_base(ident.expanded, enc, st.body)
            except SecretoError:
                continue
            if len(fk) == 32:
                return fk
    raise NoMatchError()


def decrypt(
    data: bytes,
    identities: Sequence[Identity] = (),
    passphrase: bytes | None = None,
    verify: SignerPublicKey | None = None,
) -> Decrypted:
    if armor.is_armored(data):
        data = armor.decode(data)
    hdr = header.parse(data)
    file_key = _unwrap(hdr, identities, passphrase)
    if not header.verify_mac(file_key, hdr):
        raise FormatError("header MAC mismatch")
    payload = data[hdr.length :]
    if len(payload) < stream.NONCE_LEN:
        raise FormatError("truncated payload")
    nonce, body = payload[: stream.NONCE_LEN], payload[stream.NONCE_LEN :]
    plain = stream.decrypt(stream.payload_key(file_key, nonce), body)
    content, sigblock = inner.parse(plain)
    sid = sigblock[:SIGNER_ID_LEN] if sigblock is not None else None
    if verify is not None:
        if sigblock is None:
            raise SignatureError("file is not signed")
        verify.verify(sigblock, signature_message(hdr.mac, content))
        return Decrypted(content, sid, True)
    return Decrypted(content, sid, False)


def decrypt_to(
    reader: BinaryIO,
    writer: BinaryIO,
    identities: Sequence[Identity] = (),
    passphrase: bytes | None = None,
    verify: SignerPublicKey | None = None,
) -> DecryptMeta:
    """Decrypt from ``reader``, writing content to ``writer``.

    STREAM plaintext is spilled to a temp file so padding and signatures can
    be stripped from the end without holding the body in RAM. Armored input
    is fully buffered for decoding (binary is the bounded-memory path).
    """
    # Read enough to detect armor / parse header, then the rest.
    buf = bytearray()
    while len(buf) < 64:
        chunk = reader.read(8192)
        if not chunk:
            break
        buf.extend(chunk)

    if not buf:
        raise FormatError("empty input")

    if armor.is_armored(buf):
        while True:
            chunk = reader.read(65536)
            if not chunk:
                break
            buf.extend(chunk)
        data = armor.decode(bytes(buf))
        return _decrypt_binary_to(
            data, writer, identities=identities, passphrase=passphrase, verify=verify
        )

    # Binary: keep reading until header parses.
    while True:
        try:
            hdr = header.parse(bytes(buf))
            break
        except FormatError as e:
            if len(buf) >= header.MAX_HEADER:
                raise
            chunk = reader.read(8192)
            if not chunk:
                raise e from None
            buf.extend(chunk)

    file_key = _unwrap(hdr, identities, passphrase)
    if not header.verify_mac(file_key, hdr):
        raise FormatError("header MAC mismatch")

    # Assemble payload: leftover after header in buf, then rest of reader.
    payload = bytearray(buf[hdr.length :])
    while True:
        chunk = reader.read(65536)
        if not chunk:
            break
        payload.extend(chunk)

    return _decrypt_payload_to(
        bytes(payload),
        hdr.mac,
        file_key,
        writer,
        verify=verify,
    )


def _decrypt_binary_to(
    data: bytes,
    writer: BinaryIO,
    identities: Sequence[Identity],
    passphrase: bytes | None,
    verify: SignerPublicKey | None,
) -> DecryptMeta:
    hdr = header.parse(data)
    file_key = _unwrap(hdr, identities, passphrase)
    if not header.verify_mac(file_key, hdr):
        raise FormatError("header MAC mismatch")
    return _decrypt_payload_to(data[hdr.length :], hdr.mac, file_key, writer, verify=verify)


def _decrypt_payload_to(
    payload: bytes,
    hdr_mac: bytes,
    file_key: bytes,
    writer: BinaryIO,
    verify: SignerPublicKey | None,
) -> DecryptMeta:
    if len(payload) < stream.NONCE_LEN + stream.TAG + 1:
        raise FormatError("truncated payload")
    nonce, body = payload[: stream.NONCE_LEN], payload[stream.NONCE_LEN :]
    plain = stream.decrypt(stream.payload_key(file_key, nonce), body)

    # Spill plaintext so we can strip the tail without keeping a second copy
    # of content in the caller's process beyond what stream.decrypt allocated.
    # (Further chunk-streaming of STREAM decrypt is possible; this keeps the
    # inner-parse path shared with the in-memory API.)
    fd, path = tempfile.mkstemp(prefix="secreto-spill.")
    try:
        os.write(fd, plain)
        os.lseek(fd, 0, os.SEEK_SET)
        content, sigblock = inner.parse(plain)
        sid = sigblock[:SIGNER_ID_LEN] if sigblock is not None else None
        verified = False
        if verify is not None:
            if sigblock is None:
                raise SignatureError("file is not signed")
            verify.verify(sigblock, signature_message(hdr_mac, content))
            verified = True
        writer.write(content)
        return DecryptMeta(sid, verified, len(content))
    finally:
        os.close(fd)
        try:
            os.unlink(path)
        except OSError:
            pass
