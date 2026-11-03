"""Hypothesis property tests for the bech32, header and armor parsers."""

import string

from hypothesis import given, settings, strategies as st

from secreto import armor, bech32, header, padme
from secreto.error import FormatError, InvalidKeyError

HRPS = st.sampled_from(["secreto", "SECRETO-SECRET-KEY-", "secretosig", "SECRETO-SIGNING-KEY-", "abc"])


@given(HRPS, st.binary(max_size=600))
def test_bech32_roundtrip(hrp, data):
    s = bech32.encode(hrp, data)
    assert bech32.decode(s) == (hrp, data)
    # case flip of a whole string is still valid for the lower-cased form
    if hrp == hrp.lower():
        assert bech32.decode(s.upper())[1] == data


@given(HRPS, st.binary(min_size=1, max_size=100), st.data())
def test_bech32_detects_corruption(hrp, data, d):
    s = bech32.encode(hrp, data)
    i = d.draw(st.integers(len(hrp) + 1, len(s) - 1))
    alphabet = [c for c in bech32.CHARSET if c != s[i].lower()]
    c = d.draw(st.sampled_from(alphabet))
    c = c.upper() if s[i].isupper() else c
    t = s[:i] + c + s[i + 1 :]
    try:
        bech32.decode(t)
    except InvalidKeyError:
        return
    raise AssertionError("single-character corruption not detected")


@given(st.text(max_size=200))
def test_bech32_decode_never_crashes(s):
    try:
        bech32.decode(s)
    except InvalidKeyError:
        pass


@given(st.binary(max_size=300))
def test_header_parse_never_crashes(data):
    try:
        header.parse(data)
    except FormatError:
        pass


@given(st.binary(max_size=300))
def test_header_parse_random_after_version(tail):
    try:
        header.parse(b"secreto/v1\n-> x\n" + tail)
    except FormatError:
        pass


stanza_args = st.lists(
    st.text(alphabet=string.ascii_letters + string.digits + "+/-_.", min_size=1, max_size=20),
    min_size=1,
    max_size=5,
)


@settings(max_examples=60)
@given(st.lists(st.tuples(stanza_args, st.binary(max_size=300)), min_size=1, max_size=5), st.binary(min_size=32, max_size=32), st.binary(max_size=40))
def test_header_roundtrip(stanzas, key, payload):
    sts = [header.Stanza(a, b) for a, b in stanzas]
    raw, mac = header.serialize(sts, key)
    h = header.parse(raw + payload)
    assert [(s.args, s.body) for s in h.stanzas] == [(s.args, s.body) for s in sts]
    assert h.mac == mac and h.length == len(raw)
    assert header.verify_mac(key, h)
    assert not header.verify_mac(bytes(b ^ 1 for b in key), h)


@given(st.binary(max_size=100))
def test_b64_canonical_roundtrip(data):
    assert header.b64_decode(header.b64_encode(data)) == data


@given(st.text(alphabet=string.ascii_letters + string.digits + "+/=", max_size=60))
def test_b64_decode_is_canonical(text):
    try:
        out = header.b64_decode(text)
    except FormatError:
        return
    assert header.b64_encode(out) == text


@given(st.binary(min_size=1, max_size=500))
def test_armor_roundtrip(data):
    assert armor.decode(armor.encode(data)) == data
    assert armor.decode(b"\n  " + armor.encode(data) + b"\n\n") == data
    assert armor.decode(armor.encode(data).replace(b"\n", b"\r\n")) == data


@given(st.binary(max_size=300))
def test_armor_decode_never_crashes(data):
    try:
        armor.decode(data)
    except FormatError:
        pass


@given(st.integers(1, 1 << 40))
def test_padme_properties(n):
    p = padme.padme(n)
    assert p >= n
    assert p == padme.padme(p)
    assert p <= 2 * n
