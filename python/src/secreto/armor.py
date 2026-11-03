"""Strict PEM armor (RFC 7468 §3), label ``SECRETO ENCRYPTED FILE``."""

from __future__ import annotations

import base64
import binascii

from .error import FormatError

LABEL = "SECRETO ENCRYPTED FILE"
BEGIN = f"-----BEGIN {LABEL}-----"
END = f"-----END {LABEL}-----"
_WS = b" \t\r\n"
_B64 = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")


def is_armored(data: bytes) -> bool:
    return data.lstrip(_WS).startswith(b"-----BEGIN")


def encode(data: bytes) -> bytes:
    b = base64.b64encode(data).decode("ascii")
    lines = [BEGIN] + [b[i : i + 64] for i in range(0, len(b), 64)] + [END]
    return ("\n".join(lines) + "\n").encode("ascii")


def decode(data: bytes) -> bytes:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise FormatError("armor is not ASCII") from None
    text = text.strip(" \t\r\n")
    lines = text.split("\n")
    lines = [ln[:-1] if ln.endswith("\r") else ln for ln in lines]
    if len(lines) < 3 or lines[0] != BEGIN or lines[-1] != END:
        raise FormatError("invalid armor delimiters")
    body = lines[1:-1]
    for i, ln in enumerate(body):
        if not ln or len(ln) > 64:
            raise FormatError("invalid armor line length")
        if i != len(body) - 1 and len(ln) != 64:
            raise FormatError("invalid armor line width")
        if any(c not in _B64 for c in ln):
            raise FormatError("invalid armor character")
    joined = "".join(body)
    if len(joined) % 4:
        raise FormatError("invalid armor padding")
    try:
        raw = base64.b64decode(joined, validate=True)
    except (binascii.Error, ValueError):
        raise FormatError("invalid armor base64") from None
    if base64.b64encode(raw).decode("ascii") != joined:
        raise FormatError("non-canonical armor base64")
    return raw
