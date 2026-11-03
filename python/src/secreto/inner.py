"""Inner plaintext: ``flags || content || 0x80 || 0x00*k || [sigblock]``."""

from __future__ import annotations

from .error import FormatError
from .padme import padme
from .sign import SIGBLOCK_LEN

FLAG_UNSIGNED = 0x00
FLAG_SIGNED = 0x01


def build(content: bytes, sigblock: bytes | None = None, pad: bool = False) -> bytes:
    flags = FLAG_SIGNED if sigblock is not None else FLAG_UNSIGNED
    body = bytes([flags]) + content + b"\x80"
    total = len(body) + (len(sigblock) if sigblock is not None else 0)
    k = padme(total) - total if pad else 0
    return body + b"\x00" * k + (sigblock or b"")


def parse(plain: bytes) -> tuple[bytes, bytes | None]:
    """Return ``(content, sigblock or None)``; raise :class:`FormatError`."""
    if not plain:
        raise FormatError("empty inner plaintext")
    flags = plain[0]
    if flags == FLAG_UNSIGNED:
        region, sig = plain[1:], None
    elif flags == FLAG_SIGNED:
        if len(plain) < 1 + 1 + SIGBLOCK_LEN:
            raise FormatError("truncated signature block")
        region, sig = plain[1:-SIGBLOCK_LEN], plain[-SIGBLOCK_LEN:]
    else:
        raise FormatError("unknown inner flags")
    stripped = region.rstrip(b"\x00")
    if not stripped or stripped[-1] != 0x80:
        raise FormatError("invalid inner padding")
    return stripped[:-1], sig
