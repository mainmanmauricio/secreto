"""Bech32 (BIP173 charset and polymod) without the 90-character limit.

Secret HRPs are stored upper-case; the checksum is computed over the
lower-case HRP.  Mixed case is rejected.
"""

from __future__ import annotations

from .error import InvalidKeyError

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_REV = {c: i for i, c in enumerate(CHARSET)}
MAX_LEN = 8192
_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


class Bech32Error(InvalidKeyError):
    """Invalid Bech32 string."""


def _polymod(values: list[int]) -> int:
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= _GEN[i]
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _checksum(hrp: str, data5: list[int]) -> list[int]:
    pm = _polymod(_hrp_expand(hrp) + data5 + [0] * 6) ^ 1
    return [(pm >> 5 * (5 - i)) & 31 for i in range(6)]


def convertbits(data: bytes | list[int], frombits: int, tobits: int, pad: bool) -> list[int]:
    acc = 0
    bits = 0
    out: list[int] = []
    maxv = (1 << tobits) - 1
    for v in data:
        if v < 0 or (v >> frombits):
            raise Bech32Error("invalid data value")
        acc = (acc << frombits) | v
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
        acc &= (1 << bits) - 1
    if pad:
        if bits:
            out.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or acc:
        raise Bech32Error("invalid padding")
    return out


def encode(hrp: str, data: bytes) -> str:
    """Encode ``data``; an upper-case ``hrp`` yields an upper-case string."""
    if not hrp or any(not 33 <= ord(c) <= 126 for c in hrp):
        raise Bech32Error("invalid HRP")
    if hrp != hrp.lower() and hrp != hrp.upper():
        raise Bech32Error("mixed-case HRP")
    upper = hrp != hrp.lower()
    lower_hrp = hrp.lower()
    d5 = convertbits(data, 8, 5, True)
    s = lower_hrp + "1" + "".join(CHARSET[x] for x in d5 + _checksum(lower_hrp, d5))
    if len(s) > MAX_LEN:
        raise Bech32Error("Bech32 string too long")
    return s.upper() if upper else s


def decode(s: str) -> tuple[str, bytes]:
    """Decode; returns ``(hrp, data)`` with the HRP in the case as written."""
    if not isinstance(s, str):
        raise Bech32Error("not a string")
    if len(s) > MAX_LEN:
        raise Bech32Error("Bech32 string too long")
    if any(not 33 <= ord(c) <= 126 for c in s):
        raise Bech32Error("invalid character")
    if s != s.lower() and s != s.upper():
        raise Bech32Error("mixed case")
    low = s.lower()
    pos = low.rfind("1")
    if pos < 1 or pos + 7 > len(low):
        raise Bech32Error("invalid separator position")
    hrp_low = low[:pos]
    try:
        d5 = [_REV[c] for c in low[pos + 1 :]]
    except KeyError:
        raise Bech32Error("invalid data character") from None
    if _polymod(_hrp_expand(hrp_low) + d5) != 1:
        raise Bech32Error("bad checksum")
    data = bytes(convertbits(d5[:-6], 5, 8, False))
    return s[:pos], data


def decode_exact(s: str, hrp: str, length: int) -> bytes:
    """Decode requiring the exact HRP (case-sensitive) and data length."""
    got_hrp, data = decode(s)
    if got_hrp != hrp:
        raise Bech32Error("wrong key type")
    if len(data) != length:
        raise Bech32Error("wrong key length")
    return data
