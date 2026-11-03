"""STREAM payload encryption (age variant, 64 KiB chunks)."""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .error import FormatError

CHUNK = 65536
TAG = 16
NONCE_LEN = 16


def payload_key(file_key: bytes, nonce: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA512(), length=32, salt=nonce, info=b"secreto/v1/payload"
    ).derive(file_key)


def chunk_nonce(counter: int, final: bool) -> bytes:
    return counter.to_bytes(11, "big") + (b"\x01" if final else b"\x00")


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    aead = ChaCha20Poly1305(key)
    out = []
    n = len(plaintext)
    count = max(1, -(-n // CHUNK))
    for i in range(count):
        chunk = plaintext[i * CHUNK : (i + 1) * CHUNK]
        out.append(aead.encrypt(chunk_nonce(i, i == count - 1), chunk, None))
    return b"".join(out)


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt a STREAM; every failure is a :class:`FormatError`."""
    aead = ChaCha20Poly1305(key)
    ct_chunk = CHUNK + TAG
    pos = 0
    counter = 0
    out = []
    while True:
        chunk = ciphertext[pos : pos + ct_chunk]
        final = len(chunk) < ct_chunk or pos + ct_chunk == len(ciphertext)
        if len(chunk) < TAG:
            raise FormatError("truncated payload")
        try:
            pt = aead.decrypt(chunk_nonce(counter, final), chunk, None)
        except InvalidTag:
            raise FormatError("payload authentication failed") from None
        if final:
            if not pt:
                raise FormatError("empty final chunk")
            out.append(pt)
            return b"".join(out)
        out.append(pt)
        pos += ct_chunk
        counter += 1
