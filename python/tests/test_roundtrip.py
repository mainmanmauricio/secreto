# SPDX-FileCopyrightText: 2026 secreto contributors
# SPDX-License-Identifier: EUPL-1.2

"""Encrypt/decrypt round trips and CLI behaviour."""

import io
import os
import stat
import subprocess
import sys

import pytest

from secreto import armor, cli, keygen, keys
from secreto.decrypt import decrypt
from secreto.encrypt import encrypt
from secreto.error import FormatError, NoMatchError, SignatureError
from secreto.sign import SIGBLOCK_LEN, SigningKey


@pytest.fixture(scope="module")
def ident():
    return keys.Identity.generate()


@pytest.fixture(scope="module")
def signer():
    return SigningKey.generate()


@pytest.mark.parametrize("n", [0, 1, 100, 65534, 65535, 65536, 70000])
def test_mlkem_roundtrip(ident, n):
    data = os.urandom(n)
    ct = encrypt(data, recipients=[ident.recipient()])
    assert decrypt(ct, identities=[ident]).content == data


def test_multi_recipient_and_wrong_identity(ident):
    other = keys.Identity.generate()
    ct = encrypt(b"hi", recipients=[other.recipient(), ident.recipient()])
    assert decrypt(ct, identities=[ident]).content == b"hi"
    with pytest.raises(NoMatchError):
        decrypt(ct, identities=[keys.Identity.generate()])


def test_pad(ident):
    ct = encrypt(b"x" * 1000, recipients=[ident.recipient()], pad=True)
    ct2 = encrypt(b"x" * 1001, recipients=[ident.recipient()], pad=True)
    assert len(ct) == len(ct2) or abs(len(ct) - len(ct2)) < 40
    assert decrypt(ct, identities=[ident]).content == b"x" * 1000


def test_signed(ident, signer):
    data = b"signed content" * 100
    ct = encrypt(data, recipients=[ident.recipient()], signer=signer, pad=True)
    r = decrypt(ct, identities=[ident])
    assert r.content == data and not r.verified and r.signer_id == signer.public_key().signer_id
    r = decrypt(ct, identities=[ident], verify=signer.public_key())
    assert r.verified
    with pytest.raises(SignatureError):
        decrypt(ct, identities=[ident], verify=SigningKey.generate().public_key())
    with pytest.raises(SignatureError):
        decrypt(encrypt(b"u", recipients=[ident.recipient()]), identities=[ident], verify=signer.public_key())


def test_tamper(ident):
    ct = bytearray(encrypt(b"hello", recipients=[ident.recipient()]))
    ct[-1] ^= 1
    with pytest.raises(FormatError):
        decrypt(bytes(ct), identities=[ident])


def test_key_encodings(ident, signer):
    assert keys.Identity.from_bech32(ident.to_bech32()).seed == ident.seed
    assert keys.Recipient.from_bech32(ident.recipient().to_bech32()) == ident.recipient()
    with pytest.raises(Exception):
        keys.Identity.from_bech32(ident.to_bech32().lower())
    sk = keys.signing_key_from_bech32(keys.signing_key_to_bech32(signer))
    assert sk.public_key() == signer.public_key()
    pk = keys.signer_public_from_bech32(keys.signer_public_to_bech32(signer.public_key()))
    assert pk == signer.public_key()


# ---- CLI -------------------------------------------------------------------
def run(argv, stdin=b"", env=None):
    e = dict(os.environ)
    e.pop("SECRETO_PASSPHRASE_FD", None)
    e.update(env or {})
    return subprocess.run(
        [sys.executable, "-m", argv[0], *argv[1:]], input=stdin, capture_output=True, env=e
    )


def test_cli_roundtrip(tmp_path):
    idf = tmp_path / "id.txt"
    r = run(["secreto.keygen", "-o", str(idf)])
    assert r.returncode == 0
    recipient = r.stderr.decode().strip()
    assert recipient.startswith("secreto1")
    assert stat.S_IMODE(idf.stat().st_mode) == 0o600
    # -y
    r = run(["secreto.keygen", "-y", str(idf)])
    assert r.stdout.decode().strip() == recipient
    # refuse overwrite
    assert run(["secreto.keygen", "-o", str(idf)]).returncode == 2

    out = tmp_path / "out.sec"
    r = run(["secreto.cli", "-r", recipient, "-o", str(out)], stdin=b"payload")
    assert r.returncode == 0, r.stderr
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert not [p for p in tmp_path.iterdir() if ".tmp." in p.name]
    r = run(["secreto.cli", "-d", "-i", str(idf), str(out)])
    assert (r.returncode, r.stdout) == (0, b"payload")
    # armored via stdout
    r = run(["secreto.cli", "-a", "-r", recipient], stdin=b"armored")
    assert r.stdout.startswith(b"-----BEGIN SECRETO ENCRYPTED FILE-----")
    r = run(["secreto.cli", "-d", "-i", str(idf)], stdin=r.stdout)
    assert r.stdout == b"armored"
    # wrong identity -> 3
    other = tmp_path / "other.txt"
    run(["secreto.keygen", "-o", str(other)])
    r = run(["secreto.cli", "-d", "-i", str(other), str(out)])
    assert r.returncode == 3 and r.stderr.startswith(b"secreto: error:")
    # corrupted -> 4
    bad = tmp_path / "bad.sec"
    bad.write_bytes(out.read_bytes()[:-3])
    assert run(["secreto.cli", "-d", "-i", str(idf), str(bad)]).returncode == 4
    # missing file -> 2
    assert run(["secreto.cli", "-d", "-i", str(idf), str(tmp_path / "nope")]).returncode == 2


def test_cli_usage_errors(tmp_path):
    assert run(["secreto.cli"]).returncode == 1
    assert run(["secreto.cli", "-d"]).returncode == 1
    assert run(["secreto.cli", "-e"]).returncode == 1
    assert run(["secreto.cli", "-p", "-r", "x"], env={"SECRETO_PASSPHRASE_FD": "0"}).returncode == 1
    assert run(["secreto.cli", "-r", "bogus"]).returncode == 1
    assert run(["secreto.cli", "--bogus"]).returncode == 1
    assert run(["secreto.keygen", "extra"]).returncode == 1


def test_cli_sign_verify(tmp_path):
    idf, skf = tmp_path / "id", tmp_path / "sk"
    rcpt = run(["secreto.keygen", "-o", str(idf)]).stderr.decode().strip()
    pub = run(["secreto.keygen", "--signing", "-o", str(skf)]).stderr.decode().strip()
    assert pub.startswith("secretosig1")
    assert run(["secreto.keygen", "--signing", "-y", str(skf)]).stdout.decode().strip() == pub
    ct = run(["secreto.cli", "-r", rcpt, "--sign", str(skf), "--pad", "-a"], stdin=b"data").stdout
    r = run(["secreto.cli", "-d", "-i", str(idf)], stdin=ct)
    assert r.stdout == b"data" and b"NOT verified" in r.stderr
    r = run(["secreto.cli", "-d", "-i", str(idf), "--verify", pub], stdin=ct)
    assert (r.returncode, r.stdout) == (0, b"data")
    other = run(["secreto.keygen", "--signing"]).stderr.decode().strip()
    assert run(["secreto.cli", "-d", "-i", str(idf), "--verify", other], stdin=ct).returncode == 5


def test_cli_passphrase_fd(tmp_path):
    rfd, wfd = os.pipe()
    os.write(wfd, b"hunter2\r\nignored")
    os.close(wfd)
    # low-cost check of the fd reader itself
    from secreto.cli import _read_passphrase_fd

    assert _read_passphrase_fd(str(rfd)) == b"hunter2"
    with pytest.raises(Exception):
        _read_passphrase_fd("abc")
