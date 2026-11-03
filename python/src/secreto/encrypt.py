# SPDX-FileCopyrightText: 2026 secreto contributors
# SPDX-License-Identifier: EUPL-1.2

"""Encryption (spec/format.md)."""

from __future__ import annotations

import os
from collections.abc import Sequence

from . import argon, armor, header, hpke, inner, stream
from .error import InvalidKeyError
from .header import Stanza
from .keys import Recipient
from .sign import SigningKey

STANZA_MLKEM = "mlkem1024p384"


def _mlkem_stanza(recipient: Recipient, file_key: bytes) -> Stanza:
    enc, ct = hpke.seal_base(recipient.ek, file_key)
    return Stanza([STANZA_MLKEM, header.b64_encode(enc)], ct)


def encrypt(
    content: bytes,
    recipients: Sequence[Recipient] | None = None,
    passphrase: bytes | None = None,
    pad: bool = False,
    signer: SigningKey | None = None,
) -> bytes:
    """Encrypt ``content`` to recipients XOR a passphrase; returns binary ciphertext."""
    if (passphrase is None) == (not recipients):
        raise InvalidKeyError("provide either recipients or a passphrase")
    if recipients and len(recipients) > header.MAX_STANZAS:
        raise InvalidKeyError("too many recipients")
    file_key = os.urandom(32)
    if passphrase is not None:
        stanzas = [argon.wrap(passphrase, file_key)]
    else:
        stanzas = [_mlkem_stanza(r, file_key) for r in recipients or ()]
    hdr, mac = header.serialize(stanzas, file_key)
    sigblock = signer.sign(mac, content) if signer is not None else None
    plain = inner.build(content, sigblock, pad)
    nonce = os.urandom(stream.NONCE_LEN)
    key = stream.payload_key(file_key, nonce)
    return hdr + nonce + stream.encrypt(key, plain)


def encrypt_armored(content: bytes, **kwargs) -> bytes:
    return armor.encode(encrypt(content, **kwargs))
