import json

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from conftest import VECTORS
from secreto import argon, bech32, hpke, kem, padme, stream
from secreto.error import FormatError, InvalidKeyError


def load(name):
    return json.loads((VECTORS / "components" / name).read_text())


# ---- MLKEM1024-P384 ------------------------------------------------------
@pytest.mark.parametrize("i", range(3))
def test_mlkem1024p384(i):
    v = load("mlkem1024p384.json")["vectors"][i]
    seed = bytes.fromhex(v["seed"])
    dk, ek = kem.derive_key_pair(seed)
    assert ek.hex() == v["encapsulation_key"]
    assert v["decapsulation_key"] == v["seed"]
    # component keys
    full = kem._shake256(seed, 112)
    assert full[:64].hex() == v["decapsulation_key_pq"]
    assert full[64:].hex() == v["decapsulation_key_t"]
    ss, ct = kem.encaps_derand(ek, bytes.fromhex(v["randomness"]))
    assert ct.hex() == v["ciphertext"]
    assert ss.hex() == v["shared_secret"]
    assert kem.decaps(dk, ct).hex() == v["shared_secret"]
    assert kem.decaps(seed, ct) == ss
    # random encaps round trip
    ss2, ct2 = kem.encaps(ek)
    assert kem.decaps(dk, ct2) == ss2


def test_kem_rejects_bad_points():
    dk, ek = kem.derive_key_pair(b"\x07" * 32)
    ss, ct = kem.encaps(ek)
    bad = ct[:-1] + bytes([ct[-1] ^ 1])  # off-curve
    with pytest.raises(FormatError):
        kem.decaps(dk, bad)
    with pytest.raises(FormatError):
        kem.decaps(dk, ct[:-1])
    with pytest.raises(InvalidKeyError):
        kem.validate_ek(ek[:-1])
    with pytest.raises(InvalidKeyError):
        kem.validate_ek(ek[:1568] + b"\x04" + b"\x00" * 96)


def test_random_scalar_rejection_extension():
    seed = b"\xff" * 48  # >= group order -> rejected, extended via SHAKE256
    s = kem.random_scalar(seed)
    assert 0 < s < kem.P384_ORDER
    assert s == int.from_bytes(kem._shake256(seed + b"\x01", 48), "big")
    assert kem.random_scalar(b"\x00" * 48) == int.from_bytes(
        kem._shake256(b"\x00" * 48 + b"\x01", 48), "big"
    )


# ---- HPKE ------------------------------------------------------------------
def test_hpke_key_schedule_sha512():
    v = load("hpke_key_schedule_sha512.json")
    s = v["suite"]
    sid = hpke.suite_id(s["kem_id"], s["kdf_id"], s["aead_id"])
    key, nonce, exporter, secret, ctx = hpke.key_schedule(
        bytes.fromhex(v["shared_secret"]), bytes.fromhex(v["info"]), sid, s["mode"]
    )
    assert ctx.hex() == v["key_schedule_context"]
    assert secret.hex() == v["secret"]
    assert key.hex() == v["key"]
    assert nonce.hex() == v["base_nonce"]
    assert exporter.hex() == v["exporter_secret"]
    for enc in v["encryptions"]:
        assert enc["sequence_number"] != 0 or nonce.hex() == enc["nonce"]
        ct = AESGCM(key).encrypt(
            bytes.fromhex(enc["nonce"]), bytes.fromhex(enc["pt"]), bytes.fromhex(enc["aad"])
        )
        assert ct.hex() == enc["ct"]


def test_hpke_seal_open():
    dk, ek = kem.derive_key_pair(b"\x09" * 32)
    enc, ct = hpke.seal_base(ek, b"k" * 32)
    assert len(enc) == 1665 and len(ct) == 48
    assert hpke.open_base(dk, enc, ct) == b"k" * 32
    with pytest.raises(FormatError):
        hpke.open_base(dk, enc, ct[:-1] + bytes([ct[-1] ^ 1]))


# ---- Argon2id --------------------------------------------------------------
@pytest.mark.parametrize("i", range(2))
def test_argon2id(i):
    v = load("argon2id.json")["vectors"][i]
    tag = argon.argon2id_raw(
        bytes.fromhex(v["password"]),
        bytes.fromhex(v["salt"]),
        v["m_kib"],
        v["t"],
        v["p"],
        v["tag_length"],
        secret=bytes.fromhex(v["secret"]),
        ad=bytes.fromhex(v["ad"]),
    )
    assert tag.hex() == v["tag"]


# ---- Bech32 ----------------------------------------------------------------
def test_bech32_vectors():
    d = load("bech32.json")
    for v in d["vectors"]:
        data = bytes.fromhex(v["data_hex"])
        assert bech32.encode(v["hrp"], data) == v["encoded"]
        assert bech32.decode(v["encoded"]) == (v["hrp"], data)
    for v in d["invalid"]:
        with pytest.raises(bech32.Bech32Error):
            bech32.decode(v["encoded"])


def test_bech32_long():
    data = bytes(range(256)) * 15
    s = bech32.encode("secreto", data)
    assert len(s) > 90
    assert bech32.decode(s) == ("secreto", data)


# ---- Padmé / STREAM ----------------------------------------------------------
def test_padme_vectors():
    for v in load("padme.json")["vectors"]:
        assert padme.padme(v["L"]) == v["padded"]


def test_stream_nonces():
    for v in load("stream.json")["nonce_examples"]:
        assert stream.chunk_nonce(v["counter"], v["final"]).hex() == v["nonce_hex"]


@pytest.mark.parametrize("n", [1, 2, 65535, 65536, 65537, 131072, 131073])
def test_stream_roundtrip(n):
    key = b"\x01" * 32
    pt = bytes(i % 251 for i in range(n))
    ct = stream.encrypt(key, pt)
    assert stream.decrypt(key, ct) == pt
    with pytest.raises(FormatError):
        stream.decrypt(key, ct[:-1])
    with pytest.raises(FormatError):
        stream.decrypt(key, ct + b"\x00")
