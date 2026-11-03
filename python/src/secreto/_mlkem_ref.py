"""Minimal pure-Python ML-KEM-1024 *deterministic encapsulation* (FIPS 203).

``cryptography`` only exposes randomised encapsulation, but the component test
vectors (and any known-answer test) need ``Encaps_internal(ek, m)``.  This
module implements exactly that (K-PKE.Encrypt + the FO transform) for
ML-KEM-1024 and is used for test vectors only; production encapsulation uses
``cryptography``.
"""

from __future__ import annotations

import hashlib

Q = 3329
K = 4
ETA1 = 2
ETA2 = 2
DU = 11
DV = 5
EK_LEN = 384 * K + 32  # 1568
CT_LEN = 32 * (DU * K + DV)  # 1568


def _bitrev7(i: int) -> int:
    return int(f"{i:07b}"[::-1], 2)


_ZETAS = [pow(17, _bitrev7(i), Q) for i in range(128)]


def _ntt(f: list[int]) -> list[int]:
    f = f[:]
    i = 1
    ln = 128
    while ln >= 2:
        for start in range(0, 256, 2 * ln):
            zeta = _ZETAS[i]
            i += 1
            for j in range(start, start + ln):
                t = zeta * f[j + ln] % Q
                f[j + ln] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        ln //= 2
    return f


def _ntt_inv(f: list[int]) -> list[int]:
    f = f[:]
    i = 127
    ln = 2
    while ln <= 128:
        for start in range(0, 256, 2 * ln):
            zeta = _ZETAS[i]
            i -= 1
            for j in range(start, start + ln):
                t = f[j]
                f[j] = (t + f[j + ln]) % Q
                f[j + ln] = zeta * (f[j + ln] - t) % Q
        ln *= 2
    inv128 = pow(128, -1, Q)
    return [x * inv128 % Q for x in f]


_GAMMAS = [pow(17, 2 * _bitrev7(i) + 1, Q) for i in range(128)]


def _basemul(a: list[int], b: list[int]) -> list[int]:
    out = [0] * 256
    for i in range(128):
        g = _GAMMAS[i]
        a0, a1 = a[2 * i], a[2 * i + 1]
        b0, b1 = b[2 * i], b[2 * i + 1]
        out[2 * i] = (a0 * b0 + a1 * b1 % Q * g) % Q
        out[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return out


def _add(a: list[int], b: list[int]) -> list[int]:
    return [(x + y) % Q for x, y in zip(a, b)]


def _sample_ntt(seed: bytes) -> list[int]:
    n = 840
    while True:
        stream = hashlib.shake_128(seed).digest(n)
        out: list[int] = []
        for i in range(0, len(stream) - 2, 3):
            d1 = stream[i] + 256 * (stream[i + 1] & 0x0F)
            d2 = (stream[i + 1] >> 4) + 16 * stream[i + 2]
            if d1 < Q:
                out.append(d1)
            if d2 < Q and len(out) < 256:
                out.append(d2)
            if len(out) >= 256:
                return out[:256]
        n *= 2


def _cbd(data: bytes, eta: int) -> list[int]:
    bits = int.from_bytes(data, "little")
    out = []
    mask = (1 << eta) - 1
    for i in range(256):
        x = (bits >> (2 * i * eta)) & mask
        y = (bits >> ((2 * i + 1) * eta)) & mask
        out.append((x.bit_count() - y.bit_count()) % Q)
    return out


def _prf(eta: int, s: bytes, n: int) -> bytes:
    return hashlib.shake_256(s + bytes([n])).digest(64 * eta)


def _byte_decode(data: bytes, d: int) -> list[int]:
    v = int.from_bytes(data, "little")
    mask = (1 << d) - 1
    m = Q if d == 12 else (1 << d)
    return [((v >> (d * i)) & mask) % m for i in range(256)]


def _byte_encode(f: list[int], d: int) -> bytes:
    v = 0
    for i, x in enumerate(f):
        v |= x << (d * i)
    return v.to_bytes(32 * d, "little")


def _compress(x: int, d: int) -> int:
    return ((x << d) + Q // 2) // Q % (1 << d)


def _decompress(y: int, d: int) -> int:
    return (y * Q + (1 << (d - 1))) >> d


def _kpke_encrypt(ek: bytes, m: bytes, r: bytes) -> bytes:
    t_hat = [_byte_decode(ek[384 * i : 384 * (i + 1)], 12) for i in range(K)]
    rho = ek[384 * K :]
    a_hat = [[_sample_ntt(rho + bytes([j, i])) for j in range(K)] for i in range(K)]
    n = 0
    y = []
    for _ in range(K):
        y.append(_cbd(_prf(ETA1, r, n), ETA1))
        n += 1
    e1 = []
    for _ in range(K):
        e1.append(_cbd(_prf(ETA2, r, n), ETA2))
        n += 1
    e2 = _cbd(_prf(ETA2, r, n), ETA2)
    y_hat = [_ntt(p) for p in y]
    u = []
    for i in range(K):
        acc = [0] * 256
        for j in range(K):
            acc = _add(acc, _basemul(a_hat[j][i], y_hat[j]))
        u.append(_add(_ntt_inv(acc), e1[i]))
    mu = [_decompress(b, 1) for b in _byte_decode(m, 1)]
    acc = [0] * 256
    for j in range(K):
        acc = _add(acc, _basemul(t_hat[j], y_hat[j]))
    v = _add(_add(_ntt_inv(acc), e2), mu)
    c1 = b"".join(_byte_encode([_compress(x, DU) for x in p], DU) for p in u)
    c2 = _byte_encode([_compress(x, DV) for x in v], DV)
    return c1 + c2


def encaps_derand(ek: bytes, m: bytes) -> tuple[bytes, bytes]:
    """Return ``(shared_secret, ciphertext)`` for 32-byte message ``m``."""
    if len(ek) != EK_LEN or len(m) != 32:
        raise ValueError("bad ML-KEM-1024 input length")
    g = hashlib.sha3_512(m + hashlib.sha3_256(ek).digest()).digest()
    shared, r = g[:32], g[32:]
    return shared, _kpke_encrypt(ek, m, r)
