"""Whole-file test kit (vectors/testkit/*.vec)."""

import pytest

from conftest import VECTORS
from secreto import keys
from secreto.decrypt import decrypt
from secreto.error import SecretoError

EXIT = {
    "success": 0,
    "no-match": 3,
    "header-failure": 4,
    "payload-failure": 4,
    "signature-failure": 5,
}
FILES = sorted((VECTORS / "testkit").glob("*.vec"))


def parse_vec(raw: bytes):
    sep = raw.index(b"\n\n")
    meta = raw[:sep].decode("utf-8")
    body = raw[sep + 2 :]
    m = {"identity": []}
    for line in meta.split("\n"):
        k, _, v = line.partition(": ")
        if k == "identity":
            m["identity"].append(v)
        else:
            m[k] = v
    return m, body


def test_have_all_vectors():
    assert len(FILES) == 203


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.stem)
def test_vector(path):
    meta, body = parse_vec(path.read_bytes())
    expect = meta["expect"]
    idents = [keys.Identity.from_bech32(i) for i in meta["identity"]]
    pw = meta["passphrase"].encode() if "passphrase" in meta else None
    verify = keys.signer_public_from_bech32(meta["verify"]) if "verify" in meta else None
    try:
        res = decrypt(body, identities=idents, passphrase=pw, verify=verify)
        code = 0
    except SecretoError as e:
        code = e.exit_code
        res = None
    assert code == EXIT[expect], (path.name, expect, code)
    if code == 0:
        assert res.content.hex() == meta["payload"]
        if verify is not None:
            assert res.verified
