"""Header parsing and serialisation (spec/format.md, *Header*)."""

from __future__ import annotations

import base64
import binascii
import hmac as _hmac
import hashlib
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .error import FormatError

VERSION = b"secreto/v1"
MAX_HEADER = 1 << 20
MAX_STANZAS = 256
MAX_LINE = 4096
MAC_LEN = 64
_B64_CHARS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")


def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=")


def b64_decode(text: str | bytes) -> bytes:
    """Decode canonical unpadded standard base64; reject anything else."""
    raw = text.encode("ascii", "strict") if isinstance(text, str) else bytes(text)
    if any(c not in _B64_CHARS for c in raw):
        raise FormatError("invalid base64")
    if len(raw) % 4 == 1:
        raise FormatError("invalid base64 length")
    padded = raw + b"=" * (-len(raw) % 4)
    try:
        out = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        raise FormatError("invalid base64") from None
    if base64.b64encode(out).rstrip(b"=") != raw:
        raise FormatError("non-canonical base64")
    return out


@dataclass
class Stanza:
    args: list[str]
    body: bytes = b""

    @property
    def type(self) -> str:
        return self.args[0]


@dataclass
class Header:
    stanzas: list[Stanza] = field(default_factory=list)
    mac: bytes = b""
    mac_input: bytes = b""  # header bytes up to and including "---"
    length: int = 0  # total header length including the final LF


def mac_key(file_key: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA512(), length=64, salt=None, info=b"secreto/v1/header"
    ).derive(file_key)


def compute_mac(file_key: bytes, mac_input: bytes) -> bytes:
    return _hmac.new(mac_key(file_key), mac_input, hashlib.sha512).digest()


def verify_mac(file_key: bytes, header: Header) -> bool:
    return _hmac.compare_digest(compute_mac(file_key, header.mac_input), header.mac)


def format_stanza(stanza: Stanza) -> bytes:
    out = ("-> " + " ".join(stanza.args) + "\n").encode("ascii")
    b = b64_encode(stanza.body)
    lines = [b[i : i + 64] for i in range(0, len(b), 64)]
    if not lines or len(lines[-1]) == 64:
        lines.append("")
    return out + "".join(ln + "\n" for ln in lines).encode("ascii")


def serialize_unmacced(stanzas: list[Stanza]) -> bytes:
    """Header bytes up to and including ``---`` (the MAC input)."""
    return VERSION + b"\n" + b"".join(format_stanza(s) for s in stanzas) + b"---"


def serialize(stanzas: list[Stanza], file_key: bytes) -> tuple[bytes, bytes]:
    """Return ``(header_bytes, mac)``."""
    mac_input = serialize_unmacced(stanzas)
    mac = compute_mac(file_key, mac_input)
    return mac_input + b" " + b64_encode(mac).encode("ascii") + b"\n", mac


def parse(data: bytes) -> Header:
    """Parse the header at the start of ``data``; payload begins at ``.length``."""
    pos = 0
    n = len(data)

    def read_line() -> bytes:
        nonlocal pos
        end = data.find(b"\n", pos, min(n, pos + MAX_LINE + 1))
        if end < 0:
            raise FormatError("truncated header or line too long")
        line = data[pos:end]
        pos = end + 1
        if pos > MAX_HEADER:
            raise FormatError("header too large")
        return line

    if read_line() != VERSION:
        raise FormatError("unsupported version")

    stanzas: list[Stanza] = []
    while True:
        line_start = pos
        line = read_line()
        if line.startswith(b"--- "):
            if not stanzas:
                raise FormatError("no recipient stanzas")
            mac_text = line[4:]
            if len(mac_text) != 86:
                raise FormatError("invalid MAC line")
            mac = b64_decode(mac_text)
            if len(mac) != MAC_LEN:
                raise FormatError("invalid MAC length")
            return Header(stanzas, mac, data[: line_start + 3], pos)
        if not line.startswith(b"-> "):
            raise FormatError("invalid header line")
        if len(stanzas) >= MAX_STANZAS:
            raise FormatError("too many stanzas")
        raw_args = line[3:].split(b" ")
        for a in raw_args:
            if not a or any(not 0x21 <= c <= 0x7E for c in a):
                raise FormatError("invalid stanza argument")
        args = [a.decode("ascii") for a in raw_args]
        chunks: list[bytes] = []
        while True:
            bl = read_line()
            if len(bl) > 64 or any(c not in _B64_CHARS for c in bl):
                raise FormatError("invalid stanza body line")
            chunks.append(bl)
            if len(bl) < 64:
                break
        stanzas.append(Stanza(args, b64_decode(b"".join(chunks))))
