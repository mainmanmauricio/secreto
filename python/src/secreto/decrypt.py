# SPDX-FileCopyrightText: 2026 secreto contributors
# SPDX-License-Identifier: EUPL-1.2

"""Decryption (spec/format.md, *Decryption order of checks*)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

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
