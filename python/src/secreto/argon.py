"""Argon2id passphrase recipient (spec/format.md, *Recipient type: argon2id*)."""

from __future__ import annotations

import os
import re

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from .error import FormatError, NoMatchError
from .header import Stanza, b64_decode, b64_encode

TYPE = "argon2id"
SALT_LABEL = b"secreto/v1/argon2id"
SALT_LEN = 16
BODY_LEN = 48
DEFAULT_M, DEFAULT_T, DEFAULT_P = 1048576, 3, 4
M_RANGE = (65536, 4194304)
T_RANGE = (3, 16)
P_RANGE = (1, 16)
_CANON = re.compile(r"[1-9][0-9]*")


def argon2id_raw(
    password: bytes,
    salt: bytes,
    m_kib: int,
    t: int,
    p: int,
    length: int = 32,
    secret: bytes | None = None,
    ad: bytes | None = None,
) -> bytes:
    return Argon2id(
        salt=salt,
        length=length,
        iterations=t,
        lanes=p,
        memory_cost=m_kib,
        ad=ad or None,
        secret=secret or None,
    ).derive(password)


def wrap_key(passphrase: bytes, salt: bytes, m_kib: int, t: int, p: int) -> bytes:
    return argon2id_raw(passphrase, SALT_LABEL + salt, m_kib, t, p, 32)


def wrap(passphrase: bytes, file_key: bytes) -> Stanza:
    salt = os.urandom(SALT_LEN)
    key = wrap_key(passphrase, salt, DEFAULT_M, DEFAULT_T, DEFAULT_P)
    body = ChaCha20Poly1305(key).encrypt(b"\x00" * 12, file_key, None)
    return Stanza(
        [TYPE, b64_encode(salt), str(DEFAULT_M), str(DEFAULT_T), str(DEFAULT_P)], body
    )


def _param(text: str, lo: int, hi: int) -> int:
    if not _CANON.fullmatch(text):
        raise FormatError("non-canonical argon2id parameter")
    v = int(text)
    if not lo <= v <= hi:
        raise FormatError("argon2id parameter out of range")
    return v


def parse_params(stanza: Stanza) -> tuple[bytes, int, int, int]:
    """Validate an argon2id stanza; returns ``(salt, m, t, p)``."""
    if len(stanza.args) != 5:
        raise FormatError("argon2id stanza needs 4 arguments")
    salt = b64_decode(stanza.args[1])
    if len(salt) != SALT_LEN:
        raise FormatError("invalid argon2id salt length")
    m = _param(stanza.args[2], *M_RANGE)
    t = _param(stanza.args[3], *T_RANGE)
    p = _param(stanza.args[4], *P_RANGE)
    if len(stanza.body) != BODY_LEN:
        raise FormatError("invalid argon2id body length")
    return salt, m, t, p


def unwrap(stanza: Stanza, passphrase: bytes) -> bytes:
    salt, m, t, p = parse_params(stanza)
    key = wrap_key(passphrase, salt, m, t, p)
    try:
        return ChaCha20Poly1305(key).decrypt(b"\x00" * 12, stanza.body, None)
    except InvalidTag:
        raise NoMatchError() from None
